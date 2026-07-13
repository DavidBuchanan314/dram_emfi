import os
import mmap

BUF_SIZE = 128 * 0x100000  # should ideally exceed LLC
CL_SIZE = 64

a = os.urandom(BUF_SIZE)
b = os.urandom(BUF_SIZE)
buf = mmap.mmap(-1, len(a)) # mmap means we're page aligned (which means we're cache-line-aligned)

print(f"waiting for dropped writes at pid {os.getpid()}")

while True:
	a, b = b, a
	buf[:] = a
	if buf[:] != a:
		print("inconsistency detected!")
		for i in range(0, len(buf), CL_SIZE):
			if buf[i:i+CL_SIZE] == b[i:i+CL_SIZE]:  # look for old value, specifically
				print(f"dropped write detected at offset", hex(i))
			elif buf[i:i+CL_SIZE] != a[i:i+CL_SIZE]:  # some other type of fault
				print(buf[i:i+CL_SIZE].hex(), "!=", a[i:i+CL_SIZE].hex(), "at offset", hex(i))
