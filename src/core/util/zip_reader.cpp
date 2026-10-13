// src/core/util/zip_reader.cpp

#include "core/util/zip_reader.hpp"

#include <algorithm>
#include <climits>
#include <cstring>
#include <limits>

#include <zlib.h>

namespace slop::core::util::zip {

namespace {

constexpr uint32_t kLocalSig     = 0x04034b50;
constexpr uint32_t kCentralSig   = 0x02014b50;
constexpr uint32_t kEocdSig      = 0x06054b50;
constexpr uint32_t kEocd64LocSig = 0x07064b50;
constexpr uint32_t kEocd64Sig    = 0x06064b50;

constexpr size_t kEocdSize       = 22;
constexpr size_t kEocd64LocSize  = 20;
constexpr size_t kEocd64Size     = 56;
constexpr size_t kCentralSize    = 46;
constexpr size_t kLocalSize      = 30;
constexpr size_t kMaxComment     = 0xFFFF;

uint16_t rd16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
uint32_t rd32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t rd64(const uint8_t* p) noexcept {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

// [off, off+size) inside a buffer of `len` bytes, overflow-safe
bool in_range(uint64_t off, uint64_t size, size_t len) noexcept {
    return off <= len && size <= static_cast<uint64_t>(len) - off;
}

bool fail(std::string* error, std::string msg) {
    if (error) *error = std::move(msg);
    return false;
}

} // namespace

bool has_zip_magic(const uint8_t* data, size_t len) noexcept {
    if (!data || len < 4) return false;
    const uint32_t sig = rd32(data);
    return sig == kLocalSig || sig == kEocdSig;
}

bool archive_t::open(const uint8_t* data, size_t len, std::string* error) {
    data_ = nullptr;
    len_  = 0;
    entries_.clear();
    index_.clear();

    if (!data || len < kEocdSize) return fail(error, "zip: file too small");

    // end of central directory: scan backwards through the comment window
    size_t eocd = SIZE_MAX;
    const size_t last  = len - kEocdSize;
    const size_t first = last > kMaxComment ? last - kMaxComment : 0;
    for (size_t pos = last + 1; pos-- > first;) {
        if (rd32(data + pos) != kEocdSig) continue;
        const size_t comment = rd16(data + pos + 20);
        if (comment <= len - pos - kEocdSize) { eocd = pos; break; }
    }
    if (eocd == SIZE_MAX) return fail(error, "zip: end of central directory not found");

    const uint8_t* e = data + eocd;
    uint64_t total   = rd16(e + 10);
    uint64_t cd_size = rd32(e + 12);
    uint64_t cd_off  = rd32(e + 16);

    // zip64: locator sits immediately before the classic record
    if (eocd >= kEocd64LocSize && rd32(data + eocd - kEocd64LocSize) == kEocd64LocSig) {
        const uint64_t rec = rd64(data + eocd - kEocd64LocSize + 8);
        if (!in_range(rec, kEocd64Size, len) || rd32(data + rec) != kEocd64Sig)
            return fail(error, "zip: bad zip64 end of central directory");
        const uint8_t* r = data + rec;
        total   = rd64(r + 32);
        cd_size = rd64(r + 40);
        cd_off  = rd64(r + 48);
    } else if (total == 0xFFFF || cd_size == 0xFFFFFFFFu || cd_off == 0xFFFFFFFFu) {
        return fail(error, "zip: zip64 locator missing");
    }

    if (!in_range(cd_off, cd_size, len))
        return fail(error, "zip: central directory outside the file");
    if (total > cd_size / kCentralSize)
        return fail(error, "zip: entry count exceeds central directory size");

    entries_.reserve(static_cast<size_t>(total));
    const uint8_t* cd  = data + cd_off;
    const size_t   end = static_cast<size_t>(cd_size);
    size_t         pos = 0;
    for (uint64_t i = 0; i < total; ++i) {
        if (end - pos < kCentralSize || rd32(cd + pos) != kCentralSig)
            return fail(error, "zip: corrupt central directory entry " + std::to_string(i));
        const uint8_t* h = cd + pos;
        const size_t name_len    = rd16(h + 28);
        const size_t extra_len   = rd16(h + 30);
        const size_t comment_len = rd16(h + 32);
        const size_t var_len     = name_len + extra_len + comment_len;
        if (end - pos - kCentralSize < var_len)
            return fail(error, "zip: truncated central directory entry " + std::to_string(i));

        entry_t ent;
        ent.flags               = rd16(h + 8);
        ent.method              = rd16(h + 10);
        ent.crc32               = rd32(h + 16);
        ent.compressed_size     = rd32(h + 20);
        ent.uncompressed_size   = rd32(h + 24);
        ent.local_header_offset = rd32(h + 42);
        ent.name.assign(reinterpret_cast<const char*>(h + kCentralSize), name_len);

        // zip64 extended information: only the saturated fields, in order
        const bool need_u = ent.uncompressed_size   == 0xFFFFFFFFu;
        const bool need_c = ent.compressed_size     == 0xFFFFFFFFu;
        const bool need_o = ent.local_header_offset == 0xFFFFFFFFu;
        if (need_u || need_c || need_o) {
            const uint8_t* x    = h + kCentralSize + name_len;
            size_t         xpos = 0;
            bool           found = false;
            while (extra_len - xpos >= 4) {
                const uint16_t id = rd16(x + xpos);
                const size_t   sz = rd16(x + xpos + 2);
                if (extra_len - xpos - 4 < sz) break;
                if (id == 0x0001) {
                    const uint8_t* f    = x + xpos + 4;
                    size_t         fpos = 0;
                    auto take = [&](uint64_t& v) {
                        if (sz - fpos < 8) return false;
                        v = rd64(f + fpos);
                        fpos += 8;
                        return true;
                    };
                    if ((need_u && !take(ent.uncompressed_size)) ||
                        (need_c && !take(ent.compressed_size)) ||
                        (need_o && !take(ent.local_header_offset)))
                        return fail(error, "zip: short zip64 extra field in '" + ent.name + "'");
                    found = true;
                    break;
                }
                xpos += 4 + sz;
            }
            if (!found)
                return fail(error, "zip: missing zip64 extra field in '" + ent.name + "'");
        }

        index_.emplace(ent.name, entries_.size());
        entries_.push_back(std::move(ent));
        pos += kCentralSize + var_len;
    }

    data_ = data;
    len_  = len;
    return true;
}

const std::vector<entry_t>& archive_t::entries() const noexcept {
    return entries_;
}

const entry_t* archive_t::find(std::string_view name) const {
    const auto it = index_.find(std::string(name));
    return it == index_.end() ? nullptr : &entries_[it->second];
}

bool archive_t::extract(const entry_t& e, std::vector<uint8_t>& out,
                        std::string* error, uint64_t max_size) const {
    out.clear();
    if (!data_) return fail(error, "zip: archive not open");
    const std::string& n = e.name;
    if (e.is_encrypted()) return fail(error, "zip: '" + n + "' is encrypted");
    if (e.method != 0 && e.method != 8)
        return fail(error, "zip: '" + n + "' uses unsupported compression method " +
                               std::to_string(e.method));
    if (e.uncompressed_size > max_size)
        return fail(error, "zip: '" + n + "' is too large (" +
                               std::to_string(e.uncompressed_size) + " bytes)");
    if (e.uncompressed_size > std::numeric_limits<size_t>::max())
        return fail(error, "zip: '" + n + "' does not fit in memory");

    // the local header's own name/extra lengths may differ from the central copy
    if (!in_range(e.local_header_offset, kLocalSize, len_) ||
        rd32(data_ + e.local_header_offset) != kLocalSig)
        return fail(error, "zip: bad local header for '" + n + "'");
    const uint8_t* lh       = data_ + e.local_header_offset;
    const uint64_t data_off = e.local_header_offset + kLocalSize + rd16(lh + 26) + rd16(lh + 28);
    if (!in_range(data_off, e.compressed_size, len_))
        return fail(error, "zip: data for '" + n + "' is truncated");

    const uint8_t* src   = data_ + data_off;
    const size_t   csize = static_cast<size_t>(e.compressed_size);
    const size_t   usize = static_cast<size_t>(e.uncompressed_size);

    if (e.method == 0) {
        if (csize != usize)
            return fail(error, "zip: stored entry '" + n + "' has mismatched sizes");
        out.assign(src, src + csize);
    } else {
        out.resize(usize);
        z_stream zs{};
        if (inflateInit2(&zs, -MAX_WBITS) != Z_OK)
            return fail(error, "zip: inflateInit failed");

        uint8_t  dummy    = 0;
        uint8_t* out_base = usize ? out.data() : &dummy;
        size_t   in_left  = csize;
        size_t   out_left = usize;
        zs.next_in  = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(src));
        zs.next_out = out_base;
        std::string err;
        for (;;) {
            if (zs.avail_in == 0 && in_left) {
                const size_t chunk = std::min<size_t>(in_left, UINT_MAX);
                zs.avail_in = static_cast<uInt>(chunk);
                in_left -= chunk;
            }
            if (zs.avail_out == 0 && out_left) {
                const size_t chunk = std::min<size_t>(out_left, UINT_MAX);
                zs.avail_out = static_cast<uInt>(chunk);
                out_left -= chunk;
            }
            const int rc = inflate(&zs, Z_NO_FLUSH);
            if (rc == Z_STREAM_END) break;
            if (rc == Z_OK) continue;
            if (rc == Z_BUF_ERROR) {
                if (zs.avail_out == 0 && out_left == 0)
                    err = "zip: '" + n + "' inflates past its declared size";
                else
                    err = "zip: deflate stream of '" + n + "' is truncated";
            } else {
                err = "zip: corrupt deflate stream in '" + n + "'" +
                      (zs.msg ? std::string(" (") + zs.msg + ")" : std::string());
            }
            break;
        }
        const size_t produced = static_cast<size_t>(zs.next_out - out_base);
        inflateEnd(&zs);
        if (!err.empty()) {
            out.clear();
            return fail(error, std::move(err));
        }
        if (produced != usize) {
            out.clear();
            return fail(error, "zip: '" + n + "' inflated to " + std::to_string(produced) +
                                   " bytes, expected " + std::to_string(usize));
        }
    }

    uLong        crc  = ::crc32(0L, Z_NULL, 0);
    const Bytef* p    = out.data();
    size_t       left = out.size();
    while (left) {
        const size_t chunk = std::min<size_t>(left, UINT_MAX);
        crc = ::crc32(crc, p, static_cast<uInt>(chunk));
        p += chunk;
        left -= chunk;
    }
    if (static_cast<uint32_t>(crc) != e.crc32) {
        out.clear();
        return fail(error, "zip: crc-32 mismatch in '" + n + "'");
    }
    return true;
}

} // namespace slop::core::util::zip
