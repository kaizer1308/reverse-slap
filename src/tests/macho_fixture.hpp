#pragma once

// src/tests/macho_fixture.hpp
// deterministic in-memory builders for the .ipa tests: a small but complete
// arm64 MH_EXECUTE, FAT wrappers, a ZIP writer and binary/XML plists. no
// external tools, every expected address lives in exe_layout

#include <zlib.h>

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace slop_test::macho {

// ---------------------------------------------------------------- byte io

namespace detail {

inline void put_le(std::vector<uint8_t>& b, size_t off, uint64_t v, size_t n) {
    if (b.size() < off + n) b.resize(off + n, 0);
    for (size_t i = 0; i < n; ++i) b[off + i] = uint8_t(v >> (8 * i));
}

inline void put_be(std::vector<uint8_t>& b, size_t off, uint64_t v, size_t n) {
    if (b.size() < off + n) b.resize(off + n, 0);
    for (size_t i = 0; i < n; ++i) b[off + i] = uint8_t(v >> (8 * (n - 1 - i)));
}

inline void put_bytes(std::vector<uint8_t>& b, size_t off, const void* p, size_t n) {
    if (b.size() < off + n) b.resize(off + n, 0);
    if (n) std::memcpy(b.data() + off, p, n);
}

// appending little-endian writer
struct le_writer_t {
    std::vector<uint8_t>& b;

    void u8(uint8_t v)   { b.push_back(v); }
    void u16(uint16_t v) { put_le(b, b.size(), v, 2); }
    void u32(uint32_t v) { put_le(b, b.size(), v, 4); }
    void u64(uint64_t v) { put_le(b, b.size(), v, 8); }
    void bytes(const void* p, size_t n) { put_bytes(b, b.size(), p, n); }
    void str(std::string_view s) { bytes(s.data(), s.size()); }
    // fixed 16 byte NUL padded Mach-O name
    void name16(std::string_view s) {
        char buf[16] = {};
        std::memcpy(buf, s.data(), s.size() < 16 ? s.size() : 16);
        bytes(buf, 16);
    }
    void pad_to(size_t align) { while (b.size() % align) b.push_back(0); }
};

inline void uleb(std::vector<uint8_t>& b, uint64_t v) {
    do {
        uint8_t byte = uint8_t(v & 0x7F);
        v >>= 7;
        if (v) byte |= 0x80;
        b.push_back(byte);
    } while (v);
}

} // namespace detail

inline std::vector<uint8_t> bytes_of(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ---------------------------------------------------------------- A64 encoders

namespace a64 {

// condition codes for b.cond
constexpr unsigned kCondEq = 0x0;
constexpr unsigned kCondNe = 0x1;

// stp x29, x30, [sp, #-16]!   (STP 64-bit pre-index, imm7 = -2, Rt2=30 Rn=31 Rt=29)
constexpr uint32_t kStpFpLrPre  = 0xA9BF7BFD;
// mov x29, sp                 (ADD x29, sp, #0)
constexpr uint32_t kMovFpSp     = 0x910003FD;
// ldp x29, x30, [sp], #16     (LDP 64-bit post-index, imm7 = 2)
constexpr uint32_t kLdpFpLrPost = 0xA8C17BFD;
// ret                         (RET x30)
constexpr uint32_t kRet         = 0xD65F03C0;
// br x16
constexpr uint32_t kBrX16       = 0xD61F0200;

inline int64_t delta(uint64_t pc, uint64_t target) {
    return int64_t(target) - int64_t(pc);
}

// adrp xd, target  (op=1, immlo = pages[1:0] at 29, immhi = pages[20:2] at 5)
inline uint32_t adrp(unsigned rd, uint64_t pc, uint64_t target) {
    const int64_t  pages = int64_t(target >> 12) - int64_t(pc >> 12);
    const uint32_t imm   = uint32_t(pages) & 0x1FFFFF;
    return 0x90000000u | ((imm & 3u) << 29) | ((imm >> 2) << 5) | rd;
}
// add xd, xn, #imm12   (ADD immediate, 64-bit, no shift)
inline uint32_t add_imm_x(unsigned rd, unsigned rn, uint32_t imm12) {
    return 0x91000000u | ((imm12 & 0xFFFu) << 10) | (rn << 5) | rd;
}
// ldr xt, [xn, #byte_off]   (LDR immediate, unsigned offset, scaled by 8)
inline uint32_t ldr_x_uimm(unsigned rt, unsigned rn, uint32_t byte_off) {
    return 0xF9400000u | (((byte_off / 8) & 0xFFFu) << 10) | (rn << 5) | rt;
}
// movz wd, #imm16   (mov wd, #imm)
inline uint32_t movz_w(unsigned rd, uint32_t imm16) {
    return 0x52800000u | ((imm16 & 0xFFFFu) << 5) | rd;
}
// bl target   (imm26 words)
inline uint32_t bl(uint64_t pc, uint64_t target) {
    return 0x94000000u | (uint32_t(delta(pc, target) >> 2) & 0x03FFFFFFu);
}
// b target   (imm26 words)
inline uint32_t b(uint64_t pc, uint64_t target) {
    return 0x14000000u | (uint32_t(delta(pc, target) >> 2) & 0x03FFFFFFu);
}
// b.<cond> target   (imm19 words at 5, cond at 0)
inline uint32_t b_cond(unsigned cond, uint64_t pc, uint64_t target) {
    return 0x54000000u | ((uint32_t(delta(pc, target) >> 2) & 0x7FFFFu) << 5) | cond;
}
// cbz xt, target   (sf=1, imm19 words at 5)
inline uint32_t cbz_x(unsigned rt, uint64_t pc, uint64_t target) {
    return 0xB4000000u | ((uint32_t(delta(pc, target) >> 2) & 0x7FFFFu) << 5) | rt;
}
// tbz <r>t, #bit, target   (b5 at 31, b40 at 19, imm14 words at 5)
inline uint32_t tbz(unsigned rt, unsigned bit, uint64_t pc, uint64_t target) {
    return 0x36000000u | ((bit >> 5) << 31) | ((bit & 31u) << 19) |
           ((uint32_t(delta(pc, target) >> 2) & 0x3FFFu) << 5) | rt;
}

inline void emit(std::vector<uint8_t>& b, size_t off, uint32_t word) {
    detail::put_le(b, off, word, 4);
}

} // namespace a64

// ---------------------------------------------------------------- Mach-O

constexpr uint32_t kMhMagic64    = 0xFEEDFACF;
constexpr uint32_t kFatMagic     = 0xCAFEBABE;
constexpr uint32_t kCpuArm64     = 0x0100000C;
constexpr uint32_t kCpuX86_64    = 0x01000007;
constexpr uint32_t kSubArm64All  = 0;
constexpr uint32_t kSubX86_64All = 3;

// Fixed layout of the arm64 executable build_arm64_exe() emits. Tests assert
// against these, never against literals
//
//   file 0x0000  mach header + load commands         __TEXT (r-x) 0x0000..0x4000
//   file 0x1000  __TEXT.__text     main, helper
//   file 0x1040  __TEXT.__stubs    stub0 -> _puts via got[1]
//   file 0x1060  __TEXT.__cstring  "hello from ipa"
//   file 0x4000  __DATA_CONST.__got  got[0] _objc_msgSend, got[1] _puts (rw-)
//   file 0x8000  __LINKEDIT        function starts, symtab, indirect syms, strtab
struct exe_layout_t {
    uint64_t base          = 0x100000000;          // __TEXT vmaddr, fileoff 0
    uint64_t page          = 0x4000;

    uint64_t text_off      = 0x1000;
    uint64_t text_va       = base + text_off;
    uint64_t main_va       = text_va;
    uint64_t main_size     = 9 * 4;
    uint64_t bl_stub_va    = main_va + 0x10;       // bl stub0
    uint64_t bl_helper_va  = main_va + 0x14;       // bl helper
    uint64_t helper_va     = main_va + main_size;
    uint64_t helper_size   = 2 * 4;
    uint64_t text_size     = main_size + helper_size;
    uint64_t text_end      = text_va + text_size;

    uint64_t stubs_off     = 0x1040;
    uint64_t stub0_va      = base + stubs_off;     // binds _puts
    uint64_t stub_size     = 12;

    uint64_t cstring_off   = 0x1060;
    uint64_t cstring_va    = base + cstring_off;
    const char* cstring    = "hello from ipa";
    uint64_t cstring_size  = 15;                   // includes the NUL

    uint64_t data_const_off = 0x4000;
    uint64_t data_const_va  = base + data_const_off;
    uint64_t got0_va       = data_const_va;        // _objc_msgSend, libobjc
    uint64_t got1_va       = data_const_va + 8;    // _puts, libSystem
    uint64_t got_size      = 16;

    uint64_t linkedit_off  = 0x8000;
    uint64_t linkedit_va   = base + linkedit_off;

    uint64_t entry_off     = text_off;             // LC_MAIN entryoff
    uint64_t entry_va      = main_va;
};
inline constexpr exe_layout_t exe_layout{};

struct exe_opts_t {
    // emit LC_ENCRYPTION_INFO_64 with this cryptid (bytes stay plaintext)
    std::optional<uint32_t> cryptid;
};

inline std::vector<uint8_t> build_arm64_exe(const exe_opts_t& opts = {}) {
    using detail::le_writer_t;
    const exe_layout_t& L = exe_layout;

    // section numbers (1-based, load-command order) for n_sect
    constexpr uint8_t kSectText = 1;

    // ---- __LINKEDIT payload, built first so the load commands know sizes
    std::vector<uint8_t> le;
    le_writer_t lw{le};

    // function starts: ULEB deltas from __TEXT vmaddr, 0 terminated
    const size_t fstarts_rel = le.size();
    detail::uleb(le, L.main_va - L.base);
    detail::uleb(le, L.helper_va - L.main_va);
    le.push_back(0);
    lw.pad_to(8);
    const size_t fstarts_size = le.size() - fstarts_rel;

    // strtab: index 0 is the empty name
    std::string strtab(1, '\0');
    auto add_str = [&](const char* s) {
        const uint32_t at = uint32_t(strtab.size());
        strtab += s;
        strtab.push_back('\0');
        return at;
    };
    const uint32_t s_helper = add_str("_helper");
    const uint32_t s_main   = add_str("_main");
    const uint32_t s_objc   = add_str("_objc_msgSend");
    const uint32_t s_puts   = add_str("_puts");
    while (strtab.size() % 8) strtab.push_back('\0');

    // symtab (nlist_64): locals, external defs, undefs, as LC_DYSYMTAB expects
    //   0 _helper        N_SECT            (local)
    //   1 _main          N_SECT | N_EXT    (external def)
    //   2 _objc_msgSend  N_UNDF | N_EXT    ordinal 2 (libobjc)
    //   3 _puts          N_UNDF | N_EXT    ordinal 1 (libSystem)
    constexpr uint8_t kNSect = 0x0E, kNExt = 0x01, kNUndf = 0x00;
    const size_t symoff_rel = le.size();
    auto nlist = [&](uint32_t strx, uint8_t type, uint8_t sect, uint16_t desc, uint64_t value) {
        lw.u32(strx); lw.u8(type); lw.u8(sect); lw.u16(desc); lw.u64(value);
    };
    nlist(s_helper, kNSect,         kSectText, 0,               L.helper_va);
    nlist(s_main,   kNSect | kNExt, kSectText, 0,               L.main_va);
    nlist(s_objc,   kNUndf | kNExt, 0,         uint16_t(2 << 8), 0);
    nlist(s_puts,   kNUndf | kNExt, 0,         uint16_t(1 << 8), 0);
    constexpr uint32_t kNSyms = 4;
    constexpr uint32_t kSymObjc = 2, kSymPuts = 3;

    // indirect symbol table:
    //   [0] _puts          __stubs[0]   (reserved1 = 0)
    //   [1] _objc_msgSend  __got[0]     (reserved1 = 1)
    //   [2] _puts          __got[1]
    const size_t indirect_rel = le.size();
    lw.u32(kSymPuts);
    lw.u32(kSymObjc);
    lw.u32(kSymPuts);
    constexpr uint32_t kNIndirect = 3;
    lw.pad_to(8);

    const size_t stroff_rel = le.size();
    lw.str(strtab);
    const size_t linkedit_size = le.size();

    // ---- load commands
    std::vector<uint8_t> cmds;
    le_writer_t cw{cmds};
    uint32_t ncmds = 0;

    struct sect_t {
        const char* sect; const char* seg;
        uint64_t addr, size; uint32_t off, align, flags, reserved1, reserved2;
    };
    auto segment = [&](const char* name, uint64_t vmaddr, uint64_t vmsize,
                       uint64_t fileoff, uint64_t filesize, uint32_t prot,
                       uint32_t seg_flags, std::initializer_list<sect_t> sects) {
        cw.u32(0x19);                                       // LC_SEGMENT_64
        cw.u32(uint32_t(72 + 80 * sects.size()));
        cw.name16(name);
        cw.u64(vmaddr); cw.u64(vmsize); cw.u64(fileoff); cw.u64(filesize);
        cw.u32(prot); cw.u32(prot);                         // maxprot, initprot
        cw.u32(uint32_t(sects.size())); cw.u32(seg_flags);
        for (const auto& s : sects) {
            cw.name16(s.sect); cw.name16(s.seg);
            cw.u64(s.addr); cw.u64(s.size);
            cw.u32(s.off); cw.u32(s.align);
            cw.u32(0); cw.u32(0);                           // reloff, nreloc
            cw.u32(s.flags); cw.u32(s.reserved1); cw.u32(s.reserved2); cw.u32(0);
        }
        ++ncmds;
    };

    constexpr uint32_t kProtR = 1, kProtW = 2, kProtX = 4;
    const uint64_t linkedit_vmsize = (linkedit_size + L.page - 1) / L.page * L.page;

    segment("__PAGEZERO", 0, L.base, 0, 0, 0, 0, {});
    segment("__TEXT", L.base, L.page, 0, L.page, kProtR | kProtX, 0, {
        // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        {"__text", "__TEXT", L.text_va, L.text_size, uint32_t(L.text_off), 2,
         0x80000400u, 0, 0},
        // S_SYMBOL_STUBS | instruction attrs, reserved1 = first indirect
        // index, reserved2 = stub size
        {"__stubs", "__TEXT", L.stub0_va, L.stub_size, uint32_t(L.stubs_off), 2,
         0x80000408u, 0, uint32_t(L.stub_size)},
        // S_CSTRING_LITERALS
        {"__cstring", "__TEXT", L.cstring_va, L.cstring_size, uint32_t(L.cstring_off), 0,
         0x2u, 0, 0},
    });
    segment("__DATA_CONST", L.data_const_va, L.page, L.data_const_off, L.page,
            kProtR | kProtW, 0x10 /* SG_READ_ONLY */, {
        // S_NON_LAZY_SYMBOL_POINTERS, reserved1 = first indirect index
        {"__got", "__DATA_CONST", L.got0_va, L.got_size, uint32_t(L.data_const_off), 3,
         0x6u, 1, 0},
    });
    segment("__LINKEDIT", L.linkedit_va, linkedit_vmsize, L.linkedit_off,
            linkedit_size, kProtR, 0, {});

    if (opts.cryptid) {
        cw.u32(0x2C);                                       // LC_ENCRYPTION_INFO_64
        cw.u32(24);
        cw.u32(uint32_t(L.text_off));                       // cryptoff
        cw.u32(uint32_t(L.page - L.text_off));              // cryptsize
        cw.u32(*opts.cryptid);
        cw.u32(0);                                          // pad
        ++ncmds;
    }

    cw.u32(0x2);                                            // LC_SYMTAB
    cw.u32(24);
    cw.u32(uint32_t(L.linkedit_off + symoff_rel));
    cw.u32(kNSyms);
    cw.u32(uint32_t(L.linkedit_off + stroff_rel));
    cw.u32(uint32_t(strtab.size()));
    ++ncmds;

    cw.u32(0xB);                                            // LC_DYSYMTAB
    cw.u32(80);
    cw.u32(0); cw.u32(1);                                   // ilocalsym, nlocalsym
    cw.u32(1); cw.u32(1);                                   // iextdefsym, nextdefsym
    cw.u32(2); cw.u32(2);                                   // iundefsym, nundefsym
    cw.u32(0); cw.u32(0);                                   // tocoff, ntoc
    cw.u32(0); cw.u32(0);                                   // modtaboff, nmodtab
    cw.u32(0); cw.u32(0);                                   // extrefsymoff, nextrefsyms
    cw.u32(uint32_t(L.linkedit_off + indirect_rel));        // indirectsymoff
    cw.u32(kNIndirect);                                     // nindirectsyms
    cw.u32(0); cw.u32(0);                                   // extreloff, nextrel
    cw.u32(0); cw.u32(0);                                   // locreloff, nlocrel
    ++ncmds;

    // LC_LOAD_DYLIB, ordinals follow command order
    auto dylib = [&](std::string_view path) {
        const size_t size = (24 + path.size() + 1 + 7) / 8 * 8;
        cw.u32(0xC);
        cw.u32(uint32_t(size));
        cw.u32(24);                                         // name offset
        cw.u32(2);                                          // timestamp
        cw.u32(0x10000); cw.u32(0x10000);                   // current, compat
        cw.str(path);
        for (size_t i = 24 + path.size(); i < size; ++i) cw.u8(0);
        ++ncmds;
    };
    dylib("/usr/lib/libSystem.B.dylib");                    // ordinal 1
    dylib("/usr/lib/libobjc.A.dylib");                      // ordinal 2

    cw.u32(0x80000028);                                     // LC_MAIN
    cw.u32(24);
    cw.u64(L.entry_off);
    cw.u64(0);                                              // stacksize
    ++ncmds;

    cw.u32(0x26);                                           // LC_FUNCTION_STARTS
    cw.u32(16);
    cw.u32(uint32_t(L.linkedit_off + fstarts_rel));
    cw.u32(uint32_t(fstarts_size));
    ++ncmds;

    if (32 + cmds.size() > L.text_off)
        throw std::logic_error("macho fixture: load commands overflow __text");

    // ---- the file
    std::vector<uint8_t> f(L.linkedit_off + linkedit_size, 0);
    detail::put_le(f, 0x00, kMhMagic64, 4);
    detail::put_le(f, 0x04, kCpuArm64, 4);
    detail::put_le(f, 0x08, kSubArm64All, 4);
    detail::put_le(f, 0x0C, 2, 4);                          // MH_EXECUTE
    detail::put_le(f, 0x10, ncmds, 4);
    detail::put_le(f, 0x14, cmds.size(), 4);
    detail::put_le(f, 0x18, 0x200084, 4);                   // MH_PIE | MH_TWOLEVEL | MH_DYLDLINK
    detail::put_le(f, 0x1C, 0, 4);
    detail::put_bytes(f, 32, cmds.data(), cmds.size());

    // main
    const uint64_t m = L.main_va;
    auto at = [&](uint64_t va) { return size_t(va - L.base); };
    a64::emit(f, at(m + 0x00), a64::kStpFpLrPre);                        // stp x29, x30, [sp, #-16]!
    a64::emit(f, at(m + 0x04), a64::kMovFpSp);                           // mov x29, sp
    a64::emit(f, at(m + 0x08), a64::adrp(0, m + 0x08, L.cstring_va));    // adrp x0, cstring@PAGE
    a64::emit(f, at(m + 0x0C), a64::add_imm_x(0, 0,                      // add x0, x0, cstring@PAGEOFF
                                             uint32_t(L.cstring_va & 0xFFF)));
    a64::emit(f, at(L.bl_stub_va),   a64::bl(L.bl_stub_va, L.stub0_va));  // bl stub0 (_puts)
    a64::emit(f, at(L.bl_helper_va), a64::bl(L.bl_helper_va, L.helper_va)); // bl helper
    a64::emit(f, at(m + 0x18), a64::movz_w(0, 0));                       // mov w0, #0
    a64::emit(f, at(m + 0x1C), a64::kLdpFpLrPost);                       // ldp x29, x30, [sp], #16
    a64::emit(f, at(m + 0x20), a64::kRet);                               // ret

    // helper
    a64::emit(f, at(L.helper_va + 0), a64::movz_w(0, 42));               // mov w0, #42
    a64::emit(f, at(L.helper_va + 4), a64::kRet);                        // ret

    // stub0 -> got[1] (_puts)
    const uint64_t s = L.stub0_va;
    a64::emit(f, at(s + 0), a64::adrp(16, s, L.got1_va));                // adrp x16, got1@PAGE
    a64::emit(f, at(s + 4), a64::ldr_x_uimm(16, 16,                      // ldr x16, [x16, got1@PAGEOFF]
                                            uint32_t(L.got1_va & 0xFFF)));
    a64::emit(f, at(s + 8), a64::kBrX16);                                // br x16

    detail::put_bytes(f, L.cstring_off, L.cstring, L.cstring_size);

    // got slots stay zero: dyld binds them
    detail::put_bytes(f, L.linkedit_off, le.data(), le.size());
    return f;
}

// minimal thin x86_64 MH_EXECUTE header with no load commands: a FAT
// sibling that must never be picked over arm64
inline std::vector<uint8_t> build_x86_64_stub() {
    std::vector<uint8_t> f(32, 0);
    detail::put_le(f, 0x00, kMhMagic64, 4);
    detail::put_le(f, 0x04, kCpuX86_64, 4);
    detail::put_le(f, 0x08, kSubX86_64All, 4);
    detail::put_le(f, 0x0C, 2, 4);
    return f;
}

struct fat_slice_t {
    uint32_t             cputype    = 0;
    uint32_t             cpusubtype = 0;
    std::vector<uint8_t> bytes;
    uint32_t             align_log2 = 14;   // 16 KiB pages
};

// big-endian fat_header + fat_arch[], slices at their alignment. `offsets`
// receives each slice's file offset in input order
inline std::vector<uint8_t> build_fat(const std::vector<fat_slice_t>& slices,
                                      std::vector<size_t>* offsets = nullptr) {
    std::vector<uint8_t> f;
    detail::put_be(f, 0, kFatMagic, 4);
    detail::put_be(f, 4, slices.size(), 4);
    size_t cursor = 8 + 20 * slices.size();
    if (offsets) offsets->clear();
    for (size_t i = 0; i < slices.size(); ++i) {
        const auto&  s     = slices[i];
        const size_t align = size_t(1) << s.align_log2;
        cursor = (cursor + align - 1) / align * align;
        const size_t hdr = 8 + 20 * i;
        detail::put_be(f, hdr + 0,  s.cputype, 4);
        detail::put_be(f, hdr + 4,  s.cpusubtype, 4);
        detail::put_be(f, hdr + 8,  cursor, 4);
        detail::put_be(f, hdr + 12, s.bytes.size(), 4);
        detail::put_be(f, hdr + 16, s.align_log2, 4);
        detail::put_bytes(f, cursor, s.bytes.data(), s.bytes.size());
        if (offsets) offsets->push_back(cursor);
        cursor += s.bytes.size();
    }
    return f;
}

// ---------------------------------------------------------------- ZIP

struct zip_entry_t {
    std::string          name;      // '/' suffix = directory (always stored, empty)
    std::vector<uint8_t> data;
    std::optional<bool>  deflate;   // per-entry override of the archive default
};

// where each entry's payload landed, in input order
struct zip_layout_t {
    std::vector<size_t>   data_off;
    std::vector<size_t>   data_size;   // compressed size
    std::vector<uint16_t> method;
};

inline std::vector<uint8_t> raw_deflate(const std::vector<uint8_t>& in) {
    z_stream zs{};
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        throw std::runtime_error("deflateInit2 failed");
    std::vector<uint8_t> out(deflateBound(&zs, uLong(in.size())) + 16);
    zs.next_in   = const_cast<Bytef*>(in.data());
    zs.avail_in  = uInt(in.size());
    zs.next_out  = out.data();
    zs.avail_out = uInt(out.size());
    const int rc = deflate(&zs, Z_FINISH);
    const uLong produced = zs.total_out;
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) throw std::runtime_error("deflate failed");
    out.resize(produced);
    return out;
}

inline uint32_t crc_of(const std::vector<uint8_t>& d) {
    uLong c = crc32(0L, Z_NULL, 0);
    if (!d.empty()) c = crc32(c, d.data(), uInt(d.size()));
    return uint32_t(c);
}

// local headers + central directory + EOCD, no data descriptors, no ZIP64
inline std::vector<uint8_t> build_zip(const std::vector<zip_entry_t>& entries,
                                      bool deflate,
                                      zip_layout_t* layout = nullptr) {
    using detail::le_writer_t;
    constexpr uint16_t kDosTime = 0;        // 00:00:00
    constexpr uint16_t kDosDate = 0x21;     // 1980-01-01

    std::vector<uint8_t> z;
    le_writer_t w{z};
    struct cd_rec_t { uint16_t method; uint32_t crc; size_t csize, usize, lho; };
    std::vector<cd_rec_t> cd;
    if (layout) *layout = {};

    for (const auto& e : entries) {
        const bool dir  = !e.name.empty() && e.name.back() == '/';
        const bool defl = !dir && e.deflate.value_or(deflate);
        const std::vector<uint8_t> payload = defl ? raw_deflate(e.data) : e.data;
        const uint16_t method = defl ? 8 : 0;
        const uint32_t crc    = crc_of(e.data);
        const size_t   lho    = z.size();

        w.u32(0x04034B50);
        w.u16(20);                          // version needed
        w.u16(0);                           // flags
        w.u16(method);
        w.u16(kDosTime); w.u16(kDosDate);
        w.u32(crc);
        w.u32(uint32_t(payload.size()));
        w.u32(uint32_t(e.data.size()));
        w.u16(uint16_t(e.name.size()));
        w.u16(0);                           // extra
        w.str(e.name);
        if (layout) {
            layout->data_off.push_back(z.size());
            layout->data_size.push_back(payload.size());
            layout->method.push_back(method);
        }
        w.bytes(payload.data(), payload.size());
        cd.push_back({method, crc, payload.size(), e.data.size(), lho});
    }

    const size_t cd_off = z.size();
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        const auto& r = cd[i];
        const bool dir = !e.name.empty() && e.name.back() == '/';
        w.u32(0x02014B50);
        w.u16(0x031E);                      // made by: unix, 3.0
        w.u16(20);
        w.u16(0);
        w.u16(r.method);
        w.u16(kDosTime); w.u16(kDosDate);
        w.u32(r.crc);
        w.u32(uint32_t(r.csize));
        w.u32(uint32_t(r.usize));
        w.u16(uint16_t(e.name.size()));
        w.u16(0); w.u16(0);                 // extra, comment
        w.u16(0); w.u16(0);                 // disk start, internal attrs
        w.u32(dir ? 0x41ED0010u : 0x81A40000u);   // unix mode in the high half
        w.u32(uint32_t(r.lho));
        w.str(e.name);
    }
    const size_t cd_size = z.size() - cd_off;

    w.u32(0x06054B50);
    w.u16(0); w.u16(0);                     // disk numbers
    w.u16(uint16_t(entries.size()));
    w.u16(uint16_t(entries.size()));
    w.u32(uint32_t(cd_size));
    w.u32(uint32_t(cd_off));
    w.u16(0);                               // comment length
    return z;
}

inline void corrupt_byte(std::vector<uint8_t>& buf, size_t off) {
    buf.at(off) ^= 0xFF;
}

// flip the middle byte of entry `index`'s stored/compressed payload
inline void corrupt_entry_payload(std::vector<uint8_t>& zip, const zip_layout_t& l,
                                  size_t index) {
    if (index >= l.data_off.size() || l.data_size[index] == 0)
        throw std::logic_error("corrupt_entry_payload: entry has no payload");
    corrupt_byte(zip, l.data_off[index] + l.data_size[index] / 2);
}

// ---------------------------------------------------------------- plists

// bplist00 holding one top-level dict of ASCII string -> ASCII string.
// objects: 0 = dict, 1..n keys, n+1..2n values; 1-byte object refs
inline std::vector<uint8_t> build_bplist(const std::map<std::string, std::string>& kv) {
    const size_t n    = kv.size();
    const size_t nobj = 1 + 2 * n;
    if (nobj > 255) throw std::logic_error("build_bplist: too many entries");

    std::vector<uint8_t> b = bytes_of("bplist00");
    std::vector<uint64_t> offsets;

    // marker nibble count, or 0xF + an int object for counts >= 15
    auto put_marker = [&](uint8_t marker, size_t count) {
        if (count < 15) { b.push_back(uint8_t(marker | count)); return; }
        b.push_back(uint8_t(marker | 0x0F));
        if (count < 0x100) { b.push_back(0x10); b.push_back(uint8_t(count)); }
        else { b.push_back(0x11); b.push_back(uint8_t(count >> 8)); b.push_back(uint8_t(count)); }
    };

    offsets.push_back(b.size());
    put_marker(0xD0, n);
    for (size_t i = 0; i < n; ++i) b.push_back(uint8_t(1 + i));
    for (size_t i = 0; i < n; ++i) b.push_back(uint8_t(1 + n + i));

    auto put_ascii = [&](const std::string& s) {
        offsets.push_back(b.size());
        put_marker(0x50, s.size());
        b.insert(b.end(), s.begin(), s.end());
    };
    for (const auto& [k, v] : kv) { (void)v; put_ascii(k); }
    for (const auto& [k, v] : kv) { (void)k; put_ascii(v); }

    const uint64_t table_off = b.size();
    const uint8_t  off_size  = table_off < 0x100 ? 1 : table_off < 0x10000 ? 2 : 4;
    for (uint64_t o : offsets) detail::put_be(b, b.size(), o, off_size);

    // trailer: 5 unused + sort version, offset int size, ref size,
    // object count, top object, offset table offset
    for (int i = 0; i < 6; ++i) b.push_back(0);
    b.push_back(off_size);
    b.push_back(1);
    detail::put_be(b, b.size(), nobj, 8);
    detail::put_be(b, b.size(), 0, 8);
    detail::put_be(b, b.size(), table_off, 8);
    return b;
}

// XML plist with one top-level dict of strings. `raw_prefix` is spliced
// verbatim at the top of the dict (non-string values: arrays, booleans)
inline std::vector<uint8_t> build_xml_plist(const std::map<std::string, std::string>& kv,
                                            const std::string& raw_prefix = {}) {
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '&') o += "&amp;";
            else if (c == '<') o += "&lt;";
            else if (c == '>') o += "&gt;";
            else o.push_back(c);
        }
        return o;
    };
    std::string x =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n";
    x += raw_prefix;
    for (const auto& [k, v] : kv)
        x += "\t<key>" + esc(k) + "</key>\n\t<string>" + esc(v) + "</string>\n";
    x += "</dict>\n</plist>\n";
    return bytes_of(x);
}

} // namespace slop_test::macho
