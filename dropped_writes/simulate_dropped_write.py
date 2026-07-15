"""
Note: this does not accurately simulate caching effects
"""

import re
import random
import logging
import time
from typing import List, BinaryIO

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

PAGE_SIZE = 0x1000
CACHE_LINE_SIZE = 64

ONLY_GLITCH_PTES = False

def enumerate_rw_pages(pid: int) -> List[int]:
	pages = []
	with open(f"/proc/{pid}/maps") as maps_file:
		for line in maps_file.readlines():
			match = re.match(
				r"^([0-9a-f]+)\-([0-9a-f]+) (.{4}) ",
				line
			)
			assert match is not None
			start_hex, end_hex, perms = match.groups()
			if not perms.startswith("r"):
				continue
			start, end = int(start_hex, 16), int(end_hex, 16)
			for i in range(start, end, PAGE_SIZE):
				pages.append(i)
	return pages

def block_a_write(mem: BinaryIO, pages: List[int]) -> bool:
	MAX_RETRIES = 100
	for _ in range(MAX_RETRIES):
		for page in pages:
			#print(hex(page))
			try:
				mem.seek(page)
				a = mem.read(PAGE_SIZE)
				time.sleep(0.001)  # for linux LPE, give time for kernel to repoint the PTEs
				mem.seek(page)
				b = mem.read(PAGE_SIZE)
			except OSError:
				continue
			if a == b:
				continue

			# a write happened in between each read - enumerate modified cache lines
			dirty_cls = []
			for i in range(0, PAGE_SIZE, CACHE_LINE_SIZE):
				if a[i:i+CACHE_LINE_SIZE] != b[i:i+CACHE_LINE_SIZE]:
					dirty_cls.append(i)
			
			# revert a random cl
			i = random.choice(dirty_cls)

			print("before: ", a[i:i+CACHE_LINE_SIZE].hex())
			print("after:  ", b[i:i+CACHE_LINE_SIZE].hex())

			if ONLY_GLITCH_PTES and (a[i] != 0x27 or b[i] != 0x27):  # very very naive looks-like-PTE heuristic
				continue

			print("reverting to 'before'")
			mem.seek(page + i)
			mem.write(a[i:i+CACHE_LINE_SIZE])
			return True
			#logger.info(f"Blocked a write at {hex(page+i)}")
			
			#time.sleep(0.01)
			#mem.seek(page)
			#c = mem.read(PAGE_SIZE)
			#print("new:      ", c[i:i+CACHE_LINE_SIZE].hex())
			#return True

	logger.error("Failed to block a write, giving up.")
	return False

if __name__ == "__main__":
	import sys
	pid = int(sys.argv[1])
	pages = enumerate_rw_pages(pid)
	random.shuffle(pages) # don't bias towards low addresses
	with open(f"/proc/{pid}/mem", "wb+", buffering=0) as mem:
		block_a_write(mem, pages)
