// src/core/runtime/investigation.hpp
// Investigation framework: evidence system, findings tracker, open questions,
// security audit, binary recon, and investigation workflow guides.
// Ported from REA's evidence model and Recurse's recon page.
#pragma once

#include "core/runtime/backend.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::runtime::investigation {

// ── evidence system (REA-style) ──────────────────────────────────────────
// every conclusion has a chain of evidence with confidence and limitations

enum class confidence_t : uint8_t {
    certain,     // verified by multiple sources
    high,        // single reliable source
    medium,      // heuristic-based
    low,         // speculation, pattern match
    unknown
};

struct evidence_t {
    std::string source;        // "memory scan", "packet capture", "disasm", etc.
    std::string description;
    std::uint64_t address = 0; // related VA (0 = not address-specific)
    std::string raw_data;      // hex or text evidence
    int64_t timestamp_ms = 0;
};

struct finding_t {
    std::string id;            // unique finding ID (auto-generated)
    std::string title;
    std::string category;      // "vulnerability", "behavior", "structure", "unknown"
    confidence_t confidence = confidence_t::unknown;
    std::string description;
    std::vector<evidence_t> evidence;
    std::string limitations;   // what this finding doesn't prove
    std::string status;        // "open", "confirmed", "resolved", "disputed"
    int64_t created_ms = 0;
    int64_t updated_ms = 0;
};

struct open_question_t {
    std::string id;
    std::string question;
    std::string context;       // what led to this question
    std::string status;        // "open", "investigating", "answered"
    std::string answer;        // filled when resolved
    int64_t created_ms = 0;
};

// findings database (in-memory, exportable to JSON)
class findings_db_t {
public:
    std::string add_finding(finding_t f);
    void update_finding(const std::string& id, const finding_t& f);
    void remove_finding(const std::string& id);
    const finding_t* get(const std::string& id) const;
    const std::vector<finding_t>& all() const { return findings_; }

    std::string add_question(open_question_t q);
    void answer_question(const std::string& id, const std::string& answer);
    const std::vector<open_question_t>& questions() const { return questions_; }

    // export/import as JSON bundles with provenance
    bool export_json(const std::string& path) const;
    bool import_json(const std::string& path);
    void clear();

private:
    std::vector<finding_t> findings_;
    std::vector<open_question_t> questions_;
    uint32_t next_finding_id_ = 1;
    uint32_t next_question_id_ = 1;
};

// ── security audit / hardening report (Recurse-style) ────────────────────

struct security_feature_t {
    std::string name;          // "ASLR", "DEP/NX", "CFG", "CET", "SEH", etc.
    bool        enabled = false;
    std::string detail;        // additional info
};

struct security_audit_t {
    std::string module_name;
    std::uint64_t base = 0;
    std::uint32_t size = 0;

    // PE security features
    std::vector<security_feature_t> features;

    // hashes
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string crc32;

    // entropy
    float overall_entropy = 0.0f;
    bool  likely_packed = false;

    // imports analysis
    size_t import_count = 0;
    size_t suspicious_imports = 0;  // dangerous APIs
    std::vector<std::string> dangerous_apis;

    // sections
    size_t section_count = 0;
    bool   has_writable_exec = false;  // W+X sections
    bool   has_no_relocs = false;
};

// run a security audit on a loaded module
security_audit_t audit_module(backend_t& be, const target_handle_t& h,
                               std::uint64_t base, std::uint32_t size,
                               const std::string& name);

// audit from file bytes
security_audit_t audit_file(const std::vector<uint8_t>& file,
                             const std::string& name);

// ── investigation workflow guides ────────────────────────────────────────

struct workflow_step_t {
    std::string action;        // MCP tool + action to run
    std::string description;
    std::string expected;      // what to look for in the result
};

struct investigation_workflow_t {
    std::string name;
    std::string description;
    std::vector<workflow_step_t> steps;
};

// get predefined investigation workflows
std::vector<investigation_workflow_t> get_workflows();

} // namespace slop::core::runtime::investigation
