#!/usr/bin/env python3

import sys

from lief import ELF
from ublaze.bflt import *


bflt = BFLT.parse_stream(open(sys.argv[1], "rb"))

elf = ELF.Binary("bflt2elf", ELF.ELF_CLASS.CLASS32)
elf.header.file_type = ELF.E_TYPE.EXECUTABLE

load_seg = ELF.Segment()
load_seg.type = ELF.SEGMENT_TYPES.LOAD
load_seg.flags = ELF.SEGMENT_FLAGS(7)
# load_seg.flags |= ELF.SEGMENT_FLAGS.R
# load_seg.flags |= ELF.SEGMENT_FLAGS.W
# load_seg.flags |= ELF.SEGMENT_FLAGS.X
print(load_seg.flags)
r = elf.add(load_seg, base=0)
print(r)

print(elf.segments)

sect_text = ELF.Section(".text")
sect_text.content = list(BFLTHeader.build(bflt.header) + bflt.code)
sect_text.virtual_address = 0x0

sect_data = ELF.Section(".data")
sect_data.content = list(bflt.data)
sect_data.virtual_address = bflt.header.data_start

sect_bss = ELF.Section(".bss")
sect_bss.content = [0] * (bflt.header.bss_end - bflt.header.data_end)
sect_bss.virtual_address = bflt.header.data_end

a = elf.add(sect_text, True)
b = elf.add(sect_data, True)
c = elf.add(sect_bss, True)
print(f"b: {b}")
print(f"c: {c}")

elf.entrypoint = bflt.entry

builder = ELF.Builder(elf)
builder.build()
builder.write(sys.argv[2])
