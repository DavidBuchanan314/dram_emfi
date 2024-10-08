all: linux_x86_64_lpe memtester

payload/payload_elf.h: payload/*.c
	make -C payload/

linux_x86_64_lpe: linux_x86_64_lpe.c payload/payload_elf.h
	gcc linux_x86_64_lpe.c -o linux_x86_64_lpe -Wall -Wextra -Wpedantic

memtester: memtester.c
	gcc memtester.c -o memtester -Wall -Wextra -Wpedantic
