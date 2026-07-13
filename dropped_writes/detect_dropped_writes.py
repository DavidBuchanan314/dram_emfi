import os
import mmap

FILLER_SIZE = 0x10000  # smaller than LLC
BUF_SIZE = 128 * 0x100000  # should exceed LLC
CL_SIZE = 64

def mmap_count(haystack: mmap.mmap, needle: bytes):
	# for some reason mmap doesn't have .find
	i = 0
	count = 0
	while i < len(haystack):
		i = haystack.find(needle, i)
		if i == -1:
			break
		i += len(needle)
		count += 1
	return count

a = os.urandom(FILLER_SIZE)
b = os.urandom(FILLER_SIZE)
buf = mmap.mmap(-1, BUF_SIZE) # mmap means we're page aligned (which means we're cache-line-aligned)

print(f"waiting for dropped writes at pid {os.getpid()}")

while True:
	a, b = b, a
	for i in range(0, BUF_SIZE, FILLER_SIZE):
		buf[i:i+FILLER_SIZE] = a
	if mmap_count(buf, a) != BUF_SIZE // FILLER_SIZE:
		print("inconsistency detected!")
		for i in range(0, BUF_SIZE, CL_SIZE):
			fi = i % FILLER_SIZE
			if buf[i:i+CL_SIZE] == b[fi:fi+CL_SIZE]:  # look for old value, specifically
				print(f"dropped write detected at offset", hex(i))
			elif buf[i:i+CL_SIZE] != a[fi:fi+CL_SIZE]:  # some other type of fault
				print(buf[i:i+CL_SIZE].hex(), "!=", a[fi:fi+CL_SIZE].hex(), "at offset", hex(i))
