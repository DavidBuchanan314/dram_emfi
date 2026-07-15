#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/random.h>

// like datect_dropped_writes.py but in C

#define FILLER_SIZE 0x10000  // smaller than LLC
#define BUF_SIZE (256 * 0x100000)  // should exceed LLC
#define CL_SIZE 64

int main()
{
    char *a = aligned_alloc(CL_SIZE, FILLER_SIZE);
    assert(a != NULL);
    assert(getrandom(a, FILLER_SIZE, GRND_NONBLOCK) == FILLER_SIZE);

    char *b = aligned_alloc(CL_SIZE, FILLER_SIZE);
    assert(b != NULL);
    assert(getrandom(b, FILLER_SIZE, GRND_NONBLOCK) == FILLER_SIZE);

    char *buf = aligned_alloc(CL_SIZE, BUF_SIZE);
    assert(buf != NULL);

    for (;;) {
        char *tmp = a;
        a = b;
        b = tmp;

        // TODO: consider deliberately slowing the write phase, so that most of wall-time is spend writing?
        // Write into buffer exceeding LLC
        for (off_t i = 0; i < BUF_SIZE; i += FILLER_SIZE) {
            memcpy(buf+i, a, FILLER_SIZE);
        }

	printf(".");
	fflush(stdout);

        // Read back from the buffer, check it's what we expected
        for (off_t i = 0; i < BUF_SIZE; i += FILLER_SIZE) {
            if (memcmp(buf+i, a, FILLER_SIZE) != 0) {
                printf("\n[*] GLITCH!\n");
                for (off_t j = 0; j < FILLER_SIZE; j += CL_SIZE) {
                    if (memcmp(buf+i+j, b+j, CL_SIZE) == 0) {
                        printf("[+] DROPPED WRITE CONFIRMED at address %p\n", buf+i+j);
                    } else if (memcmp(buf+i+j, a+j, CL_SIZE) != 0) {
                        printf("[*] some other kind of glitch at address %p\n", buf+i+j);
                        printf("actual:   ");
                        for (off_t k = 0; k < CL_SIZE; k++) {
                            printf("%02x", *(unsigned char*)(buf+i+j+k));
                        }
                        printf("\n");
                        printf("expected: ");
                        for (off_t k = 0; k < CL_SIZE; k++) {
                            printf("%02x", *(unsigned char*)(a+j+k));
                        }
                        printf("\n");
                        printf("stale:    ");
                        for (off_t k = 0; k < CL_SIZE; k++) {
                            printf("%02x", *(unsigned char*)(b+j+k));
                        }
                        printf("\n");
                    }
                }
            }
        }
    }

    return 0;
}
