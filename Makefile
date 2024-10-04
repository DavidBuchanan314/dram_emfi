all: linux_x86_64_lpe

linux_x86_64_lpe: linux_x86_64_lpe.c
	gcc linux_x86_64_lpe.c -o linux_x86_64_lpe -Wall -Wextra -Wpedantic
