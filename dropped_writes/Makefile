all: linux_x86_64_lpe memtest_writedrops

linux_x86_64_lpe: linux_x86_64_lpe.c
	gcc linux_x86_64_lpe.c -o linux_x86_64_lpe -static -Wall -Wextra -Wpedantic

memtest_writedrops: memtest_writedrops.c
	gcc memtest_writedrops.c -o memtest_writedrops -static -Wall -Wextra -Wpedantic

.PHONY: run
run: linux_x86_64_lpe
	scp -P5555 linux_x86_64_lpe localhost:/tmp/
	ssh -t -p 5555 localhost /tmp/linux_x86_64_lpe