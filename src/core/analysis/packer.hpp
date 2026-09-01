#pragma once

// packer heuristics over a parsed pe, section names, entry stubs, entropy,
// import anomalies, wx sections, tls callbacks and overlay

#include <cstdint>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"

namespace slop::core::analysis {

struct packer_section_report_t {
    std::string name;
    uint32_t    rva          = 0;
    uint32_t    raw_size     = 0;
    uint32_t    virtual_size = 0;
    uint32_t    characteristics = 0;   // raw IMAGE_SCN_* flags
    double      entropy      = 0.0;    // over raw bytes (sampled)
    bool        writable_exec = false;
};

struct packer_detection_t {
    std::string type;        // section_name | byte_signature | string_reference |
                             // high_entropy | imports | layout | wx_section | tls | overlay
    std::string protector;   // family when identified, otherwise ""
    std::string detail;
    uint64_t    location = 0; // file offset / VA where applicable
};

struct packer_verdict_t {
    bool        packed     = false;
    std::string family;                 // strongest identified family, "" = unknown/generic
    double      confidence = 0.0;       // 0..1
    double      file_entropy  = 0.0;
    std::vector<packer_detection_t>     detections;
    std::vector<packer_section_report_t> sections;
};

// Shannon entropy over raw bytes (0.0 .. 8.0)
double shannon_entropy(const uint8_t* data, size_t len);

packer_verdict_t packer_analyze(const disasm::pe_image_t& pe,
                                const std::vector<uint8_t>& file);

} // namespace slop::core::analysis
