#include <cassert>
#include <cstdio>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bit>
#include <string>

#include <elfio/elfio.hpp>
using namespace ELFIO;
#include <ixm/byteswap.hpp>

#include "bflt.h"

#define R_MICROBLAZE_32 1
#define R_MICROBLAZE_64 5

template <typename T> T bswap(T v) {
    if constexpr (std::endian::native == std::endian::little)
        return ixm::byteswap(v);
    return v;
}

template <typename T> T bswap(T *v) {
    if constexpr (std::endian::native == std::endian::little)
        *v = ixm::byteswap(*v);
    return *v;
}

uint8_t *readfile(const char *filename, std::size_t *len = nullptr, bool rw = true,
                  const void *preferred_addr = (const void *)0x400000000ull) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        assert(!"couldnt open");
    }

    struct stat st {};
    if (fstat(fd, &st) != 0) {
        assert(!"couldnt stat");
    }

    auto *buf =
        (uint8_t *)mmap((void *)preferred_addr, st.st_size, rw ? PROT_READ | PROT_WRITE : PROT_READ,
                        MAP_PRIVATE | (preferred_addr ? MAP_FIXED : 0), fd, 0);
    if (buf == NULL) {
        assert(!"couldnt mmap");
    }
    close(fd);

    if (len) {
        *len = st.st_size;
    }

    return buf;
}

void writefile(const char *filename, uint8_t *buf, std::size_t len) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    assert(fd >= 0);
    auto wrote_len = write(fd, buf, len);
    assert(wrote_len == (ssize_t)len);
    close(fd);
}

int main(int argc, const char **argv) {
    assert(argc == 3);

    uint32_t load_addr = 0x1000'0000;
    // uint32_t load_addr = 0x0;

    size_t in_sz = 0;
    auto in_buf  = readfile(argv[1], &in_sz, true);

    auto bflt_hdr = *(bflt_header_t *)in_buf;
    assert(!memcmp(bflt_hdr.magic, "bFLT", 4));
    assert(bswap(bflt_hdr.rev) == 4);
    bswap(&bflt_hdr.entry);
    bswap(&bflt_hdr.data_start);
    bswap(&bflt_hdr.data_end);
    bswap(&bflt_hdr.bss_end);
    bswap(&bflt_hdr.stack_size);
    bswap(&bflt_hdr.reloc_start);
    bswap(&bflt_hdr.reloc_count);

    auto code_buf  = (const char *)in_buf;
    size_t code_sz = bflt_hdr.data_start;

    auto data_buf  = (const char *)in_buf + bflt_hdr.data_start;
    size_t data_sz = bflt_hdr.data_end - bflt_hdr.data_start;

    auto bss_sz = bflt_hdr.bss_end - bflt_hdr.data_end;

    auto reloc_buf = (uint32_t *)(in_buf + bflt_hdr.reloc_start);

    for (uint32_t i = 0; i < bflt_hdr.reloc_count; ++i) {
        uint32_t addr = reloc_buf[i];
        bswap(&addr);
        uint32_t addr_val, inst_hi, inst_lo;
        uint32_t *addr_p;
        bool is64 = false;
        if (addr & 0x8000'0000) {
            addr &= ~0x8000'0000;
            is64 = true;
        }
        if (addr < code_sz) {
            addr_p = (uint32_t *)(in_buf + addr + sizeof(bflt_hdr));
        } else {
            printf("data reloc!\n");
            addr_p = (uint32_t *)(in_buf + addr + sizeof(bflt_hdr));
        }
        printf("reloc[%04u]: 0x%08x %s addr_p: %p\n", i, addr, is64 ? "*" : "", addr_p);
        if (!is64) {
            addr_val = addr_p[0];
            bswap(&addr_val);
        } else {
            inst_hi = addr_p[0];
            bswap(&inst_hi);
            inst_lo = addr_p[1];
            bswap(&inst_lo);
            addr_val = ((inst_hi & 0xFFFF) << 16) | (inst_lo & 0xFFFF);
        }
        uint32_t new_addr_val = addr_val + load_addr;
        printf("addr_p: %p addr_val: 0x%08x new_addr_val: 0x%08x\n", addr_p, addr_val,
               new_addr_val);
        // printf("new_addr_val: %p\n", new_addr_val);
        // *addr_p = bswap(new_addr_val);
    }

    elfio writer;
    writer.create(ELFCLASS32, ELFDATA2MSB);

    writer.set_os_abi(ELFOSABI_LINUX);
    writer.set_type(ET_EXEC);
    writer.set_machine(EM_MICROBLAZE);
    uint32_t elf_entry = bflt_hdr.entry + load_addr;
    printf("elf_entry: 0x%08x\n", elf_entry);
    writer.set_entry(elf_entry);
    auto load_seg = writer.segments.add();
    load_seg->set_type(PT_LOAD);
    load_seg->set_virtual_address(load_addr);
    load_seg->set_physical_address(load_addr);
    load_seg->set_flags(PF_X | PF_R | PF_W);
    load_seg->set_align(0x1000);

    auto text_sec = writer.sections.add(".text");
    text_sec->set_type(SHT_PROGBITS);
    text_sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    text_sec->set_data(code_buf, code_sz);
    text_sec->set_addr_align(0x4);
    load_seg->add_section_index(text_sec->get_index(), text_sec->get_addr_align());

    auto data_sec = writer.sections.add(".data");
    data_sec->set_type(SHT_PROGBITS);
    data_sec->set_flags(SHF_ALLOC | SHF_WRITE);
    data_sec->set_data(data_buf, data_sz);
    data_sec->set_addr_align(0x4);
    load_seg->add_section_index(data_sec->get_index(), data_sec->get_addr_align());

    auto bss_sec = writer.sections.add(".bss");
    bss_sec->set_type(SHT_NOBITS);
    bss_sec->set_flags(SHF_ALLOC | SHF_WRITE);
    bss_sec->set_size(bss_sz);
    bss_sec->set_addr_align(0x4);
    load_seg->add_section_index(bss_sec->get_index(), bss_sec->get_addr_align());

    // auto text_rel = writer.sections.add(".rel.text");
    // text_rel->set_type(SHT_REL);
    // text_rel->set_info(text_sec->get_index());
    // // text_rel->set_link( sym_sec->get_index() );
    // text_rel->set_addr_align(4);
    // text_rel->set_entry_size(writer.get_default_entry_size(SHT_REL));

    writer.save(argv[2]);
    assert(!chmod(argv[2], 0755));

    return 0;
}
