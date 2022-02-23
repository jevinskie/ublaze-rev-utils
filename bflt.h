#pragma once

#include <cstdint>

struct bflt_header_t {
    char magic[4];
    uint32_t rev;
    uint32_t entry;
    uint32_t data_start;
    uint32_t data_end;
    uint32_t bss_end;
    uint32_t stack_size;
    uint32_t reloc_start;
    uint32_t reloc_count;
    uint32_t flags;
    uint32_t build_date;
    uint32_t filler[5];
};
