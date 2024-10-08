#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>

// 32MiB (just needs to be enough to exceed cache)
#define MAP_SIZE 0x2000000
#define MAP_ADDR 0xdead0000000

int main()
{
	uint64_t rng;
	uint64_t *mapping = mmap((void*)MAP_ADDR, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE, -1, 0);
	if ((intptr_t)mapping == -1) {
		perror("mmap");
		return -1;
	}
	for (;;) {
		printf(".");
		fflush(stdout);

		// write loop
		rng = 0xbeef;
		for (size_t i=0; i < MAP_SIZE / 8; i++) {
			rng = rng * 6364136223846793005L + 1; // LCG
			mapping[i] = rng;
		}

		// read loop
		rng = 0xbeef;
		for (size_t i=0; i < MAP_SIZE / 8; i++) {
			rng = rng * 6364136223846793005L + 1; // LCG
			uint64_t actual = mapping[i];
			if (rng != actual) {
				printf("\nERROR: addr=0x%016lx expected=0x%016lx actual=0x%016lx diff=0x%016lx\n", (uintptr_t)&mapping[i], rng, actual, rng ^ actual);
			}
		}
	}
}
