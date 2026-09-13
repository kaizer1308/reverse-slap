#pragma once
#include "core/types.h"
#include <filesystem>
#include <memory>
#include <optional>

namespace hype {

struct RuntimeFunc {
    va_t start;
    va_t end;
};

struct PEImage {
    Arch                       arch;
    va_t                       base;
    va_t                       entry;
    std::vector<Segment>       segments;
    std::vector<Import>        imports;
    std::vector<Export>        exports;
    std::vector<RuntimeFunc>   runtime_funcs;
    // Whole file bytes. load_buffer() borrows the caller's buffer, which must
    // outlive the image; load() and the ELF/Mach-O loaders keep what they read,
    // plus any zero-extended segment tails, alive in `storage`
    std::span<const u8>                           raw;
    std::vector<std::shared_ptr<std::vector<u8>>> storage;
};

// `file_sz` bytes at `p` as segment data, zero-extended to `mem_sz` when the
// segment maps more than the file backs. Only that extended case copies
inline std::span<const u8> segment_bytes(PEImage& img, const u8* p, size_t file_sz,
                                         size_t mem_sz = 0) {
    if (mem_sz <= file_sz) return {p, file_sz};
    auto tail = std::make_shared<std::vector<u8>>(p, p + file_sz);
    tail->resize(mem_sz, 0);
    img.storage.push_back(tail);
    return *tail;
}

class PELoader {
public:
    std::optional<PEImage> load(const std::filesystem::path& path);
    // In-memory variant (reverse-slop port): parse from a byte buffer —
    // e.g. the session's patched `file` image — instead of re-reading disk.
    std::optional<PEImage> load_buffer(const u8* data, size_t len);

private:
    bool parse_headers(PEImage& img);
    bool parse_sections(PEImage& img);
    bool parse_imports(PEImage& img);
    bool parse_exports(PEImage& img);
    void parse_exceptions(PEImage& img);

    const u8* base_ = nullptr;
    size_t    size_ = 0;
};

}
