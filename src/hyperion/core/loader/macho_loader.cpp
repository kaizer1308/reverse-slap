#include "macho_loader.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cstring>
#include <fstream>

namespace hype {

namespace {

constexpr size_t kMaxFileSize = 2ULL * 1024 * 1024 * 1024;
// zero-fill sections and segment tails beyond this get no backing buffer: a
// malformed size would otherwise turn into a multi-gigabyte allocation
constexpr u64    kMaxZeroFill = 256ULL * 1024 * 1024;

constexpr u32 MH_MAGIC_32  = 0xFEEDFACE;
constexpr u32 MH_MAGIC_64  = 0xFEEDFACF;
constexpr u32 MH_CIGAM_32  = 0xCEFAEDFE;
constexpr u32 MH_CIGAM_64  = 0xCFFAEDFE;
// FAT headers are big-endian on disk; compared against be32() reads
constexpr u32 FAT_MAGIC    = 0xCAFEBABE;
constexpr u32 FAT_MAGIC_64 = 0xCAFEBABF;

constexpr u32 MH_TWOLEVEL = 0x80;

constexpr u32 CPU_TYPE_X86    = 0x00000007;
constexpr u32 CPU_TYPE_X86_64 = 0x01000007;
constexpr u32 CPU_TYPE_ARM    = 0x0000000C;
constexpr u32 CPU_TYPE_ARM64  = 0x0100000C;

constexpr u32 LC_SEGMENT            = 0x01;
constexpr u32 LC_SYMTAB             = 0x02;
constexpr u32 LC_UNIXTHREAD         = 0x05;
constexpr u32 LC_DYSYMTAB           = 0x0B;
constexpr u32 LC_LOAD_DYLIB         = 0x0C;
constexpr u32 LC_SEGMENT_64         = 0x19;
constexpr u32 LC_LAZY_LOAD_DYLIB    = 0x20;
constexpr u32 LC_ENCRYPTION_INFO    = 0x21;
constexpr u32 LC_FUNCTION_STARTS    = 0x26;
constexpr u32 LC_ENCRYPTION_INFO_64 = 0x2C;
constexpr u32 LC_LOAD_WEAK_DYLIB    = 0x80000018;
constexpr u32 LC_REEXPORT_DYLIB     = 0x8000001F;
constexpr u32 LC_LOAD_UPWARD_DYLIB  = 0x80000023;
constexpr u32 LC_MAIN               = 0x80000028;

constexpr u32 VM_PROT_READ    = 1;
constexpr u32 VM_PROT_WRITE   = 2;
constexpr u32 VM_PROT_EXECUTE = 4;

constexpr u32 SECTION_TYPE                 = 0xFF;
constexpr u32 S_ZEROFILL                   = 0x01;
constexpr u32 S_NON_LAZY_SYMBOL_POINTERS   = 0x06;
constexpr u32 S_LAZY_SYMBOL_POINTERS       = 0x07;
constexpr u32 S_SYMBOL_STUBS               = 0x08;
constexpr u32 S_GB_ZEROFILL                = 0x0C;
constexpr u32 S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10;
constexpr u32 S_THREAD_LOCAL_ZEROFILL      = 0x12;
constexpr u32 S_ATTR_PURE_INSTRUCTIONS     = 0x80000000;
constexpr u32 S_ATTR_SOME_INSTRUCTIONS     = 0x00000400;

constexpr u32 INDIRECT_SYMBOL_LOCAL = 0x80000000;
constexpr u32 INDIRECT_SYMBOL_ABS   = 0x40000000;

constexpr u8 N_STAB = 0xE0;
constexpr u8 N_TYPE = 0x0E;
constexpr u8 N_EXT  = 0x01;
constexpr u8 N_SECT = 0x0E;

constexpr u8 DYNAMIC_LOOKUP_ORDINAL = 0xFE;
constexpr u8 EXECUTABLE_ORDINAL     = 0xFF;

#pragma pack(push, 1)
struct MachHeader32 {
    u32 magic;
    u32 cputype;
    u32 cpusubtype;
    u32 filetype;
    u32 ncmds;
    u32 sizeofcmds;
    u32 flags;
};

struct MachHeader64 {
    u32 magic;
    u32 cputype;
    u32 cpusubtype;
    u32 filetype;
    u32 ncmds;
    u32 sizeofcmds;
    u32 flags;
    u32 reserved;
};

struct LoadCmd {
    u32 cmd;
    u32 cmdsize;
};

struct SegmentCmd32 {
    u32  cmd;
    u32  cmdsize;
    char segname[16];
    u32  vmaddr;
    u32  vmsize;
    u32  fileoff;
    u32  filesize;
    u32  maxprot;
    u32  initprot;
    u32  nsects;
    u32  flags;
};

struct SegmentCmd64 {
    u32  cmd;
    u32  cmdsize;
    char segname[16];
    u64  vmaddr;
    u64  vmsize;
    u64  fileoff;
    u64  filesize;
    u32  maxprot;
    u32  initprot;
    u32  nsects;
    u32  flags;
};

struct Section32 {
    char sectname[16];
    char segname[16];
    u32  addr;
    u32  size;
    u32  offset;
    u32  align;
    u32  reloff;
    u32  nreloc;
    u32  flags;
    u32  reserved1;
    u32  reserved2;
};

struct Section64 {
    char sectname[16];
    char segname[16];
    u64  addr;
    u64  size;
    u32  offset;
    u32  align;
    u32  reloff;
    u32  nreloc;
    u32  flags;
    u32  reserved1;
    u32  reserved2;
    u32  reserved3;
};

struct SymtabCmd {
    u32 cmd;
    u32 cmdsize;
    u32 symoff;
    u32 nsyms;
    u32 stroff;
    u32 strsize;
};

// dysymtab_command up to the indirect symbol table fields
struct DysymtabCmd {
    u32 cmd;
    u32 cmdsize;
    u32 ilocalsym;
    u32 nlocalsym;
    u32 iextdefsym;
    u32 nextdefsym;
    u32 iundefsym;
    u32 nundefsym;
    u32 tocoff;
    u32 ntoc;
    u32 modtaboff;
    u32 nmodtab;
    u32 extrefsymoff;
    u32 nextrefsyms;
    u32 indirectsymoff;
    u32 nindirectsyms;
};

struct LinkeditDataCmd {
    u32 cmd;
    u32 cmdsize;
    u32 dataoff;
    u32 datasize;
};

struct EncryptionInfoCmd {
    u32 cmd;
    u32 cmdsize;
    u32 cryptoff;
    u32 cryptsize;
    u32 cryptid;
};

struct Nlist32 {
    u32 n_strx;
    u8  n_type;
    u8  n_sect;
    u16 n_desc;
    u32 n_value;
};

struct Nlist64 {
    u32 n_strx;
    u8  n_type;
    u8  n_sect;
    u16 n_desc;
    u64 n_value;
};

struct EntryPointCmd {
    u32 cmd;
    u32 cmdsize;
    u64 entryoff;
    u64 stacksize;
};
#pragma pack(pop)

constexpr size_t kFatHeaderSize = 8;
constexpr size_t kFatArchSize   = 20;   // cputype, cpusubtype, offset, size, align
constexpr size_t kFatArch64Size = 32;   // cputype, cpusubtype, u64 offset, u64 size, align, reserved

bool range_ok(size_t size, u64 off, u64 len) {
    return off <= size && len <= size - off;
}

template <class T>
bool read_at(const u8* base, size_t size, u64 off, T& out) {
    if (!range_ok(size, off, sizeof(T))) return false;
    std::memcpy(&out, base + off, sizeof(T));
    return true;
}

u32 le32(const u8* p) {
    u32 v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

u32 be32(const u8* p) {
    return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}

u64 be64(const u8* p) {
    return (u64(be32(p)) << 32) | be32(p + 4);
}

// FAT slice preference, lower is better; -1 for architectures we cannot analyze
int cpu_rank(u32 cputype) {
    switch (cputype) {
    case CPU_TYPE_ARM64:  return 0;
    case CPU_TYPE_X86_64: return 1;
    case CPU_TYPE_ARM:    return 2;
    case CPU_TYPE_X86:    return 3;
    default:              return -1;
    }
}

u32 prot_to_flags(u32 prot) {
    u32 f = 0;
    if (prot & VM_PROT_READ)    f |= 0x40000000;
    if (prot & VM_PROT_WRITE)   f |= 0x80000000;
    if (prot & VM_PROT_EXECUTE) f |= 0x20000000;
    return f;
}

bool is_zerofill(u32 sect_flags) {
    u32 type = sect_flags & SECTION_TYPE;
    return type == S_ZEROFILL || type == S_GB_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL;
}

std::string fixed_name(const char* s) {
    return std::string(s, strnlen(s, 16));
}

std::string_view strip_underscore(std::string_view name) {
    if (!name.empty() && name[0] == '_') name.remove_prefix(1);
    return name;
}

} // anon

bool MachOLoader::is_macho(const u8* data, size_t len) {
    if (!data || len < 4) return false;
    u32 le = le32(data);
    if (le == MH_MAGIC_32 || le == MH_MAGIC_64 || le == MH_CIGAM_32 || le == MH_CIGAM_64)
        return true;
    u32 be = be32(data);
    return be == FAT_MAGIC || be == FAT_MAGIC_64;
}

std::optional<MachOLoader::Slice> MachOLoader::select_slice(const u8* data, size_t len) {
    if (!data || len < 4) return std::nullopt;

    u32 le = le32(data);
    if (le == MH_MAGIC_64) {
        if (len < sizeof(MachHeader64)) return std::nullopt;
        return Slice{0, len};
    }
    if (le == MH_MAGIC_32) {
        if (len < sizeof(MachHeader32)) return std::nullopt;
        return Slice{0, len};
    }

    u32 magic = be32(data);
    if (magic != FAT_MAGIC && magic != FAT_MAGIC_64) return std::nullopt;
    if (len < kFatHeaderSize) return std::nullopt;

    bool   fat64    = magic == FAT_MAGIC_64;
    size_t entry_sz = fat64 ? kFatArch64Size : kFatArchSize;
    u64    narch    = (std::min<u64>)(be32(data + 4), (len - kFatHeaderSize) / entry_sz);

    int   best_rank = -1;
    Slice best;
    for (u64 i = 0; i < narch; ++i) {
        const u8* p = data + kFatHeaderSize + i * entry_sz;
        int rank = cpu_rank(be32(p));
        if (rank < 0) continue;

        u64 off = fat64 ? be64(p + 8)  : be32(p + 8);
        u64 sz  = fat64 ? be64(p + 16) : be32(p + 12);
        if (!range_ok(len, off, sz) || sz < sizeof(MachHeader32)) continue;

        // the slice itself must be a thin little-endian Mach-O
        u32 inner = le32(data + off);
        if (inner != MH_MAGIC_32 && inner != MH_MAGIC_64) continue;
        if (inner == MH_MAGIC_64 && sz < sizeof(MachHeader64)) continue;

        if (best_rank < 0 || rank < best_rank) {
            best_rank = rank;
            best = {static_cast<size_t>(off), static_cast<size_t>(sz)};
        }
    }
    if (best_rank < 0) return std::nullopt;
    return best;
}

std::optional<PEImage> MachOLoader::load(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        spdlog::error("macho: cannot open: {}", path.string());
        return std::nullopt;
    }

    auto file_sz = static_cast<size_t>(f.tellg());
    if (file_sz > kMaxFileSize) {
        spdlog::error("macho: file too large: {} bytes (max {})", file_sz, kMaxFileSize);
        return std::nullopt;
    }

    auto raw = std::make_shared<std::vector<u8>>(file_sz);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(raw->data()), static_cast<std::streamsize>(file_sz));
    if (!f) {
        spdlog::error("macho: short read: {}", path.string());
        return std::nullopt;
    }

    // load_buffer only borrows, so the image keeps the bytes it was parsed from
    auto img = load_buffer(raw->data(), raw->size());
    if (img) img->storage.push_back(std::move(raw));
    return img;
}

std::optional<PEImage> MachOLoader::load_buffer(const u8* data, size_t len) {
    *this = MachOLoader{};

    auto slice = select_slice(data, len);
    if (!slice) {
        u32 le = (data && len >= 4) ? le32(data) : 0;
        if (le == MH_CIGAM_32 || le == MH_CIGAM_64)
            spdlog::error("macho: big-endian Mach-O is not supported");
        else
            spdlog::error("macho: not a Mach-O, or no usable slice ({} bytes)", len);
        return std::nullopt;
    }

    PEImage img;
    img.arch  = Arch::X64;
    img.base  = 0;
    img.entry = 0;
    img.raw   = {data, len};

    base_ = data + slice->offset;
    size_ = slice->size;

    if (!parse_header(img)) return std::nullopt;

    // two passes: symtab, dysymtab, dylibs and __TEXT may come in any order
    collect_load_commands(img);
    if (img.segments.empty()) {
        spdlog::error("macho: no mapped segments");
        return std::nullopt;
    }

    resolve_base_entry(img);
    validate_symtab();
    parse_symtab(img);
    parse_dysymtab(img);
    parse_function_starts(img);

    if (img.encrypted)
        spdlog::warn("macho: code is encrypted (cryptid != 0), disassembly will be noise");

    spdlog::info("macho: base=0x{:X} entry=0x{:X} segs={} imports={} exports={} symbols={} funcs={}",
                 img.base, img.entry, img.segments.size(), img.imports.size(),
                 img.exports.size(), img.symbols.size(), img.runtime_funcs.size());
    return img;
}

bool MachOLoader::parse_header(PEImage& img) {
    MachHeader32 hdr{};
    if (!read_at(base_, size_, 0, hdr)) return false;

    if (hdr.magic == MH_MAGIC_64) {
        is64_ = true;
        header_size_ = sizeof(MachHeader64);
    } else if (hdr.magic == MH_MAGIC_32) {
        is64_ = false;
        header_size_ = sizeof(MachHeader32);
    } else {
        spdlog::error("macho: bad magic 0x{:08X}", hdr.magic);
        return false;
    }
    if (size_ < header_size_) return false;

    switch (hdr.cputype) {
    case CPU_TYPE_X86_64: img.arch = Arch::X64;   break;
    case CPU_TYPE_X86:    img.arch = Arch::X86;   break;
    case CPU_TYPE_ARM64:  img.arch = Arch::ARM64; break;
    case CPU_TYPE_ARM:    img.arch = Arch::ARM;   break;
    default:
        spdlog::error("macho: unsupported cputype 0x{:08X}", hdr.cputype);
        return false;
    }

    ncmds_      = hdr.ncmds;
    sizeofcmds_ = hdr.sizeofcmds;
    flags_      = hdr.flags;
    return true;
}

void MachOLoader::collect_load_commands(PEImage& img) {
    size_t end = header_size_ + static_cast<size_t>((std::min<u64>)(sizeofcmds_, size_ - header_size_));
    size_t off = header_size_;

    for (u32 i = 0; i < ncmds_; ++i) {
        LoadCmd lc{};
        if (end - off < sizeof(LoadCmd)) break;
        std::memcpy(&lc, base_ + off, sizeof(lc));
        if (lc.cmdsize < sizeof(LoadCmd) || lc.cmdsize > end - off) {
            spdlog::warn("macho: load command {} has bad size {}", i, lc.cmdsize);
            break;
        }

        switch (lc.cmd) {
        case LC_SEGMENT:
        case LC_SEGMENT_64:
            parse_segment(img, off, lc.cmdsize, lc.cmd == LC_SEGMENT_64);
            break;
        case LC_SYMTAB: {
            SymtabCmd sc{};
            if (lc.cmdsize >= sizeof(sc) && read_at(base_, size_, off, sc)) {
                symoff_  = sc.symoff;
                nsyms_   = sc.nsyms;
                stroff_  = sc.stroff;
                strsize_ = sc.strsize;
            }
            break;
        }
        case LC_DYSYMTAB: {
            DysymtabCmd dc{};
            if (lc.cmdsize >= sizeof(dc) && read_at(base_, size_, off, dc)) {
                indirectsymoff_ = dc.indirectsymoff;
                nindirectsyms_  = dc.nindirectsyms;
            }
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB:
        case LC_LOAD_UPWARD_DYLIB:
            parse_dylib(off, lc.cmdsize);
            break;
        case LC_MAIN: {
            EntryPointCmd ep{};
            if (lc.cmdsize >= sizeof(ep) && read_at(base_, size_, off, ep)) {
                have_main_ = true;
                entryoff_  = ep.entryoff;
            }
            break;
        }
        case LC_UNIXTHREAD:
            parse_thread(img, off, lc.cmdsize);
            break;
        case LC_FUNCTION_STARTS: {
            LinkeditDataCmd ld{};
            if (lc.cmdsize >= sizeof(ld) && read_at(base_, size_, off, ld)) {
                fstarts_off_  = ld.dataoff;
                fstarts_size_ = ld.datasize;
            }
            break;
        }
        case LC_ENCRYPTION_INFO:
        case LC_ENCRYPTION_INFO_64: {
            EncryptionInfoCmd ec{};
            if (lc.cmdsize >= sizeof(ec) && read_at(base_, size_, off, ec) && ec.cryptid != 0)
                img.encrypted = true;
            break;
        }
        default:
            break;
        }
        off += lc.cmdsize;
    }
}

std::span<const u8> MachOLoader::file_view(PEImage& img, u64 off, u64 file_sz, u64 mem_sz,
                                           u64& backed) const {
    // a truncated slice backs only what it has
    size_t avail = off < size_ ? static_cast<size_t>((std::min<u64>)(file_sz, size_ - off)) : 0;
    const u8* p = avail ? base_ + off : base_;
    backed = avail;
    if (mem_sz > avail && mem_sz <= kMaxZeroFill)
        return segment_bytes(img, p, avail, static_cast<size_t>(mem_sz));
    return {p, avail};
}

void MachOLoader::parse_segment(PEImage& img, size_t off, u32 cmdsize, bool seg64) {
    std::string segname;
    u64 vmaddr = 0, vmsize = 0, fileoff = 0, filesize = 0;
    u32 initprot = 0, nsects = 0;
    size_t hdr_sz = 0;

    if (seg64) {
        SegmentCmd64 sc{};
        if (cmdsize < sizeof(sc) || !read_at(base_, size_, off, sc)) return;
        segname  = fixed_name(sc.segname);
        vmaddr   = sc.vmaddr;
        vmsize   = sc.vmsize;
        fileoff  = sc.fileoff;
        filesize = sc.filesize;
        initprot = sc.initprot;
        nsects   = sc.nsects;
        hdr_sz   = sizeof(sc);
    } else {
        SegmentCmd32 sc{};
        if (cmdsize < sizeof(sc) || !read_at(base_, size_, off, sc)) return;
        segname  = fixed_name(sc.segname);
        vmaddr   = sc.vmaddr;
        vmsize   = sc.vmsize;
        fileoff  = sc.fileoff;
        filesize = sc.filesize;
        initprot = sc.initprot;
        nsects   = sc.nsects;
        hdr_sz   = sizeof(sc);
    }

    if (segname == "__TEXT" && !have_text_) {
        have_text_    = true;
        text_vmaddr_  = vmaddr;
        text_fileoff_ = fileoff;
    }
    if (filesize > 0 && vmaddr < low_vmaddr_) low_vmaddr_ = vmaddr;

    // __PAGEZERO maps 4 GiB of nothing at 0; __LINKEDIT is loader metadata
    if (segname == "__PAGEZERO" || segname == "__LINKEDIT") return;
    if (vmsize == 0 && filesize == 0) return;

    u32 prot_flags = prot_to_flags(initprot);

    if (nsects == 0) {
        Segment seg;
        seg.name     = segname;
        seg.va       = vmaddr;
        seg.size     = vmsize;
        seg.file_off = fileoff;
        seg.flags    = prot_flags;
        seg.data     = file_view(img, fileoff, filesize, vmsize, seg.file_sz);
        img.segments.push_back(std::move(seg));
        return;
    }

    size_t sect_sz = seg64 ? sizeof(Section64) : sizeof(Section32);
    size_t room    = (cmdsize - hdr_sz) / sect_sz;
    if (nsects > room) {
        spdlog::warn("macho: segment {} claims {} sections, command holds {}", segname, nsects, room);
        nsects = static_cast<u32>(room);
    }

    for (u32 s = 0; s < nsects; ++s) {
        size_t sect_off = off + hdr_sz + s * sect_sz;
        SectInfo info;
        std::string name;
        u32 offset = 0;

        if (seg64) {
            Section64 sec{};
            if (!read_at(base_, size_, sect_off, sec)) break;
            name = fixed_name(sec.segname) + "." + fixed_name(sec.sectname);
            info = {sec.addr, sec.size, sec.flags, sec.reserved1, sec.reserved2};
            offset = sec.offset;
        } else {
            Section32 sec{};
            if (!read_at(base_, size_, sect_off, sec)) break;
            name = fixed_name(sec.segname) + "." + fixed_name(sec.sectname);
            info = {sec.addr, sec.size, sec.flags, sec.reserved1, sec.reserved2};
            offset = sec.offset;
        }

        Segment seg;
        seg.name  = std::move(name);
        seg.va    = info.addr;
        seg.size  = info.size;
        seg.flags = prot_flags & ~0x20000000u;
        // __TEXT also holds __cstring / __const: only instruction sections execute
        if ((initprot & VM_PROT_EXECUTE) &&
            (info.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)))
            seg.flags |= 0x20000000;

        if (is_zerofill(info.flags)) {
            seg.file_off = 0;
            seg.file_sz  = 0;
            if (info.size <= kMaxZeroFill)
                seg.data = segment_bytes(img, base_, 0, static_cast<size_t>(info.size));
        } else {
            seg.file_off = offset;
            seg.data     = file_view(img, offset, info.size, 0, seg.file_sz);
        }

        sects_.push_back(info);
        img.segments.push_back(std::move(seg));
    }
}

void MachOLoader::parse_dylib(size_t off, u32 cmdsize) {
    // every dylib command takes an ordinal slot, even an unreadable one
    std::string name;
    u32 name_off = 0;
    if (cmdsize >= 12 && read_at(base_, size_, off + 8, name_off) &&
        name_off >= 8 && name_off < cmdsize) {
        const char* p = reinterpret_cast<const char*>(base_ + off + name_off);
        std::string_view install(p, strnlen(p, cmdsize - name_off));
        auto slash = install.rfind('/');
        if (slash != std::string_view::npos) install.remove_prefix(slash + 1);
        name = install;
    }
    dylibs_.push_back(std::move(name));
}

void MachOLoader::parse_thread(PEImage& img, size_t off, u32 cmdsize) {
    // thread_command: cmd, cmdsize, flavor, count, then the register state
    size_t index = 0, width = 0;
    switch (img.arch) {
    case Arch::X64:   index = 16; width = 8; break;   // rip
    case Arch::ARM64: index = 32; width = 8; break;   // pc
    case Arch::X86:   index = 10; width = 4; break;   // eip
    case Arch::ARM:   index = 15; width = 4; break;   // r15
    default: return;
    }
    size_t at = 16 + index * width;
    if (cmdsize < at + width) return;

    if (width == 8) {
        u64 pc = 0;
        if (!read_at(base_, size_, off + at, pc)) return;
        thread_pc_ = pc;
    } else {
        u32 pc = 0;
        if (!read_at(base_, size_, off + at, pc)) return;
        thread_pc_ = pc;
    }
    have_thread_ = true;
}

void MachOLoader::resolve_base_entry(PEImage& img) {
    if (have_text_)
        img.base = text_vmaddr_;
    else
        img.base = low_vmaddr_ != INVALID_VA ? low_vmaddr_ : 0;

    // LC_MAIN's entryoff is a file offset into __TEXT
    if (have_main_)
        img.entry = have_text_ ? text_vmaddr_ + entryoff_ - text_fileoff_ : img.base + entryoff_;
    else if (have_thread_)
        img.entry = thread_pc_;

    // thumb entry points carry the mode in bit 0
    if (img.arch == Arch::ARM) img.entry &= ~va_t(1);

    if (img.entry == 0) {
        auto exec = std::find_if(img.segments.begin(), img.segments.end(),
                                 [](const Segment& s) { return s.executable(); });
        img.entry = exec != img.segments.end() ? exec->va : img.segments.front().va;
        return;
    }

    bool mapped = std::any_of(img.segments.begin(), img.segments.end(),
                              [&](const Segment& s) { return s.contains(img.entry); });
    if (!mapped) spdlog::warn("macho: entry point 0x{:X} not within any section", img.entry);
}

void MachOLoader::validate_symtab() {
    size_t nl_sz = is64_ ? sizeof(Nlist64) : sizeof(Nlist32);
    if (!range_ok(size_, symoff_, u64(nsyms_) * nl_sz)) {
        if (nsyms_) spdlog::warn("macho: symbol table out of bounds");
        nsyms_ = 0;
    }
    if (!range_ok(size_, stroff_, strsize_)) {
        if (strsize_) spdlog::warn("macho: string table out of bounds");
        strsize_ = 0;
    }
    if (!range_ok(size_, indirectsymoff_, u64(nindirectsyms_) * 4)) {
        if (nindirectsyms_) spdlog::warn("macho: indirect symbol table out of bounds");
        nindirectsyms_ = 0;
    }
}

bool MachOLoader::read_nlist(u32 index, Nlist& out) const {
    if (index >= nsyms_) return false;
    if (is64_) {
        Nlist64 nl{};
        if (!read_at(base_, size_, u64(symoff_) + u64(index) * sizeof(Nlist64), nl)) return false;
        out = {nl.n_strx, nl.n_type, nl.n_sect, nl.n_desc, nl.n_value};
    } else {
        Nlist32 nl{};
        if (!read_at(base_, size_, u64(symoff_) + u64(index) * sizeof(Nlist32), nl)) return false;
        out = {nl.n_strx, nl.n_type, nl.n_sect, nl.n_desc, nl.n_value};
    }
    return true;
}

std::string_view MachOLoader::sym_name(const Nlist& nl) const {
    if (nl.strx >= strsize_) return {};
    const char* p = reinterpret_cast<const char*>(base_ + stroff_ + nl.strx);
    return {p, strnlen(p, strsize_ - nl.strx)};
}

std::string MachOLoader::dylib_for(u16 desc) const {
    // flat namespace images carry no library ordinals
    if (!(flags_ & MH_TWOLEVEL)) return {};
    u32 ordinal = (desc >> 8) & 0xFF;   // GET_LIBRARY_ORDINAL
    if (ordinal == 0 || ordinal == DYNAMIC_LOOKUP_ORDINAL || ordinal == EXECUTABLE_ORDINAL)
        return {};
    if (ordinal > dylibs_.size()) return {};
    return dylibs_[ordinal - 1];
}

void MachOLoader::parse_symtab(PEImage& img) {
    for (u32 i = 0; i < nsyms_; ++i) {
        Nlist nl;
        if (!read_nlist(i, nl)) break;
        if (nl.type & N_STAB) continue;
        if ((nl.type & N_TYPE) != N_SECT) continue;
        if (nl.value == 0) continue;

        auto name = strip_underscore(sym_name(nl));
        if (name.empty()) continue;

        if (nl.type & N_EXT) {
            Export exp;
            exp.name = std::string(name);
            exp.addr = nl.value;
            img.exports.push_back(std::move(exp));
        } else {
            img.symbols.push_back({std::string(name), nl.value});
        }
    }
}

void MachOLoader::parse_dysymtab(PEImage& img) {
    if (!nindirectsyms_) return;
    const u64 ptr_sz = is64_ ? 8 : 4;

    for (const auto& s : sects_) {
        u32  type  = s.flags & SECTION_TYPE;
        bool ptrs  = type == S_NON_LAZY_SYMBOL_POINTERS || type == S_LAZY_SYMBOL_POINTERS ||
                     type == S_LAZY_DYLIB_SYMBOL_POINTERS;
        bool stubs = type == S_SYMBOL_STUBS;
        if (!ptrs && !stubs) continue;

        u64 stride = ptrs ? ptr_sz : s.reserved2;
        if (stride == 0) continue;

        u64 count = s.size / stride;
        for (u64 j = 0; j < count; ++j) {
            u64 idx = u64(s.reserved1) + j;
            if (idx >= nindirectsyms_) break;

            u32 isym = le32(base_ + indirectsymoff_ + idx * 4);
            if (isym & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;

            Nlist nl;
            if (!read_nlist(isym, nl)) continue;
            auto name = strip_underscore(sym_name(nl));
            if (name.empty()) continue;

            va_t at = s.addr + j * stride;
            if (ptrs) {
                Import imp;
                imp.dll      = dylib_for(nl.desc);
                imp.name     = std::string(name);
                imp.ordinal  = 0;
                imp.iat_addr = at;
                img.imports.push_back(std::move(imp));
            } else {
                img.symbols.push_back({std::string(name), at});
            }
        }
    }
}

void MachOLoader::parse_function_starts(PEImage& img) {
    if (!fstarts_size_) return;
    if (!range_ok(size_, fstarts_off_, fstarts_size_)) {
        spdlog::warn("macho: function starts out of bounds");
        return;
    }

    // ULEB128 deltas, the first from the __TEXT start, terminated by 0
    const u8* p = base_ + fstarts_off_;
    const u8* e = p + fstarts_size_;
    va_t addr = have_text_ ? text_vmaddr_ : img.base;
    std::vector<va_t> starts;
    while (p < e) {
        u64 delta = 0;
        unsigned shift = 0;
        bool done = false;
        while (p < e) {
            u8 b = *p++;
            if (shift < 64) delta |= u64(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) { done = true; break; }
        }
        if (!done || delta == 0) break;
        addr += delta;
        starts.push_back(img.arch == Arch::ARM ? addr & ~va_t(1) : addr);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

    std::vector<const Segment*> exec;
    for (const auto& seg : img.segments)
        if (seg.executable() && seg.size) exec.push_back(&seg);

    for (size_t i = 0; i < starts.size(); ++i) {
        va_t start = starts[i];
        auto it = std::find_if(exec.begin(), exec.end(),
                               [&](const Segment* s) { return s->contains(start); });
        if (it == exec.end()) continue;
        va_t end = (*it)->va + (*it)->size;
        if (i + 1 < starts.size()) end = (std::min)(end, starts[i + 1]);
        img.runtime_funcs.push_back({start, end});
    }
}

}
