#pragma once

// src/core/disasm/ipa.hpp
// iOS app archive (.ipa): locate Payload/<Name>.app/, read Info.plist
// (xml or binary) and pull out the main executable

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::disasm::ipa {

struct bundle_t {
    std::string app_dir;          // "Payload/Foo.app/"
    std::string executable;       // CFBundleExecutable, or the .app stem fallback
    std::string executable_path;  // archive path of the main binary
    std::string bundle_id;        // CFBundleIdentifier (may be empty)
    std::string version;          // CFBundleShortVersionString
    std::string build;            // CFBundleVersion
    std::string min_os;           // MinimumOSVersion
};

struct extract_result_t {
    bool                 ok = false;
    std::string          error;
    bundle_t             bundle;
    std::vector<uint8_t> binary;   // main executable bytes as stored (thin or FAT)
};

// ZIP with a top-level "Payload/<name>.app/" bundle
bool looks_like_ipa(const uint8_t* data, size_t len);
extract_result_t extract_main_binary(const uint8_t* data, size_t len);

} // namespace slop::core::disasm::ipa
