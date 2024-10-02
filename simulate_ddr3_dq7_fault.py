"""
yoinked from https://github.com/DavidBuchanan314/irradiate.py/blob/main/irradiate.py
"""

import re
import random
import logging
from typing import List, BinaryIO
from dataclasses import dataclass

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@dataclass
class MemRange:
	start: int
	length: int

def enumerate_readable_ranges() -> List[MemRange]:
	ranges = []
	with open(f"/proc/self/maps") as maps_file:
		for line in maps_file.readlines():
			start_hex, end_hex, perms = re.match(
				r"^([0-9a-f]+)\-([0-9a-f]+) (.{4}) ",
				line
			).groups()
			if not perms.startswith("r"):
				continue
			start, end = int(start_hex, 16), int(end_hex, 16)
			ranges.append(MemRange(
				start=start,
				length=end - start
			))
	return ranges

def do_a_flip(mem: BinaryIO, ranges: List[MemRange]) -> None:
	range_total = sum(r.length for r in ranges)
	MAX_FLIP_RETRIES = 100
	for _ in range(MAX_FLIP_RETRIES):
		try:
			offset = random.randrange(range_total) & ~7 # 64-bit word align
			bit_idx = 7 # DQ7
			for range_ in ranges:
				if offset < range_.length:
					target_addr = range_.start + offset
					break
				offset -= range_.length
			logger.debug(f"going to flip addr {hex(target_addr)}, bit {bit_idx}")
			mem.seek(target_addr)
			initial_val = mem.read(1)[0]
			flipped_val = initial_val ^ (1 << bit_idx)
			mem.seek(target_addr)
			mem.write(bytes([flipped_val]))
			logger.debug(f"0x{initial_val:02x} -> 0x{flipped_val:02x}")
			return True
		except:
			logger.info("flip failed, trying again at a different address...")

	logger.error("Failed to flip, giving up.")
	return False

def simulate_emfi():
	ranges = enumerate_readable_ranges()
	with open(f"/proc/self/mem", "wb+") as mem:
		do_a_flip(mem, ranges)
