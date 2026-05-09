AARCH64_CC ?= aarch64-linux-gnu-gcc

all: linux_x86_64_lpe memtester android_aarch64_lpe

payload/payload_elf.h: payload/*.c
	make -C payload/

linux_x86_64_lpe: linux_x86_64_lpe.c payload/payload_elf.h
	gcc linux_x86_64_lpe.c -o linux_x86_64_lpe -Wall -Wextra -Wpedantic

memtester: memtester.c
	gcc memtester.c -o memtester -Wall -Wextra -Wpedantic

# Freestanding (no libc), uses ../linux_syscall_support.h.
# -Wl,-z,max-page-size=0x1000 is required: the default 64K alignment puts the
# BSS LOAD segment at a file offset past EOF, which Android's in-kernel ELF
# loader rejects with SIGSEGV during exec.
android_aarch64_lpe: android_aarch64_lpe.c ../linux_syscall_support.h
	$(AARCH64_CC) android_aarch64_lpe.c -o android_aarch64_lpe \
		-static -nostdlib -ffreestanding \
		-fno-stack-protector -fno-asynchronous-unwind-tables \
		-O2 -Wall -Wextra \
		-Wl,-z,max-page-size=0x1000
