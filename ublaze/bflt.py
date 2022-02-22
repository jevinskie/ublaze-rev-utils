import datetime
import enum
import math

from construct import *

u8 = Int8ub
u16 = Int16ub
u32 = Int32ub

class BFLTFlagsEnum(enum.IntFlag):
    RAM    = 0x0001
    GOTPIC = 0x0002
    GZIP   = 0x0004
    GZDATA = 0x0008
    KTRACE = 0x0010
    LISTK  = 0x0020

BFLTFlags = Enum(u32, BFLTFlagsEnum)


class BFLTBuildDateAdapter(Adapter):
    UnixEpoch = datetime.datetime(1970, 1, 1, 0, 0, 0)

    def _decode(self, obj, context, path) -> datetime.datetime:
        return self.UnixEpoch + datetime.timedelta(seconds=obj)

    def _encode(self, obj: datetime.datetime, context, path):
        td = obj - self.UnixEpoch
        return int(math.ceil(td.total_seconds()))


BFLTBuildDate = BFLTBuildDateAdapter(u32)

BFLTHeader = Struct(
    'magic' / Const(b"bFLT"),
    'rev' / u32,
    'entry' / Hex(u32),
    'data_start' / Hex(u32),
    'data_end' / Hex(u32),
    'bss_end' / Hex(u32),
    'stack_size' / Hex(u32),
    'reloc_start' / Hex(u32),
    'reloc_count' / u32,
    'flags' / BFLTFlags,
    'build_date' / BFLTBuildDate,
    'filler' / Padding(4 * 5),
)

BFLT = Struct(
    'header' / BFLTHeader,
    'code' / Bytes(lambda this: this.header.data_start - this._subcons.header.sizeof()),
    'data' / Bytes(this.header.data_end - this.header.data_start),
    'relocs' / u32[this.header.reloc_count],
)

__all__ = ('BFLTFlagsEnum', 'BFLTFlags', 'BFLTBuildDate', 'BFLTHeader', 'BFLT')
