#!/usr/bin/env python3

import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("in_elf")
parser.add_argument("out_elf")
args = parser.parse_args()

elf = bytearray(open(args.in_elf, "rb").read())

e_machine = elf[0x12:0x14]
if e_machine == b"\xba\xab":
	print("switching ELF from old microblaze ID to new")
	e_machine = b"\x00\xbd"
elif e_machine == b"\x00\xbd":
	print("switching ELF from new microblaze ID to old")
	e_machine = b"\xba\xab"
else:
	raise ValueError("not a microblaze elf")

elf[0x12:0x14] = e_machine

open(args.out_elf, "wb").write(elf)
os.chmod(args.out_elf, 0o755)
