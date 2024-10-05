all: payload_elf.h

payload_elf.h: gimme_shell.elf
	xxd -n payload_elf -i $< $@

gimme_shell.elf: gimme_shell.c
	gcc $< -o $@ -Os -s -ffreestanding -nostdlib -N -static
