#pragma once
#include "core/types.h"
#include "pe_loader.h"
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hype {

// Little-endian Mach-O (thin, or the preferred slice of a FAT / FAT64 file)
// into the PE-shaped image the analyzer consumes. One segment per section,
// named "<seg>.<sect>"; file offsets are relative to the analyzed slice
class MachOLoader {
public:
    std::optional<PEImage> load(const std::filesystem::path& path);
    // In-memory variant: borrows `data` (must outlive the image) exactly like
    // PELoader::load_buffer. FAT input analyzes the slice select_slice() picks
    std::optional<PEImage> load_buffer(const u8* data, size_t len);

    struct Slice { size_t offset = 0; size_t size = 0; };
    // Thin little-endian Mach-O -> whole buffer. FAT / FAT64 -> preferred
    // slice: arm64, then x86_64, then arm, then x86. nullopt when not a
    // Mach-O or no usable slice
    static std::optional<Slice> select_slice(const u8* data, size_t len);
    // Thin (either endianness) or FAT/FAT64 magic in the first 4 bytes
    static bool is_macho(const u8* data, size_t len);

private:
    struct SectInfo {
        va_t addr      = 0;
        u64  size      = 0;
        u32  flags     = 0;
        u32  reserved1 = 0;
        u32  reserved2 = 0;
    };
    struct Nlist {
        u32 strx  = 0;
        u8  type  = 0;
        u8  sect  = 0;
        u16 desc  = 0;
        u64 value = 0;
    };

    bool parse_header(PEImage& img);
    // pass 1: emit segments, record every other command's fields
    void collect_load_commands(PEImage& img);
    void parse_segment(PEImage& img, size_t off, u32 cmdsize, bool seg64);
    void parse_dylib(size_t off, u32 cmdsize);
    void parse_thread(PEImage& img, size_t off, u32 cmdsize);
    // pass 2: everything that depends on more than one command
    void resolve_base_entry(PEImage& img);
    void validate_symtab();
    void parse_symtab(PEImage& img);
    void parse_dysymtab(PEImage& img);
    void parse_function_starts(PEImage& img);

    std::span<const u8> file_view(PEImage& img, u64 off, u64 file_sz, u64 mem_sz,
                                  u64& backed) const;
    bool read_nlist(u32 index, Nlist& out) const;
    std::string_view sym_name(const Nlist& nl) const;
    std::string dylib_for(u16 desc) const;

    const u8* base_ = nullptr;   // analyzed slice
    size_t    size_ = 0;
    bool      is64_ = true;
    size_t    header_size_ = 0;
    u32       ncmds_ = 0;
    u32       sizeofcmds_ = 0;
    u32       flags_ = 0;

    bool      have_text_ = false;
    va_t      text_vmaddr_ = 0;
    u64       text_fileoff_ = 0;
    va_t      low_vmaddr_ = INVALID_VA;   // lowest file-backed segment

    bool      have_main_ = false;
    u64       entryoff_ = 0;
    bool      have_thread_ = false;
    va_t      thread_pc_ = 0;

    u32       symoff_ = 0;
    u32       nsyms_ = 0;
    u32       stroff_ = 0;
    u32       strsize_ = 0;
    u32       indirectsymoff_ = 0;
    u32       nindirectsyms_ = 0;
    u32       fstarts_off_ = 0;
    u32       fstarts_size_ = 0;

    std::vector<std::string> dylibs_;   // load order = two-level library ordinal - 1
    std::vector<SectInfo>    sects_;
};

}
