// src/core/runtime/engine_dumper.hpp
// Game engine SDK dumpers: UE4/UE5 GObjects/GNames walker (Dumper-7 style)
// and Unity Il2Cpp metadata reader (Il2CppDumper style).
// All reads through kernel phys path — invisible to AC.
#pragma once

#include "core/runtime/game_tools.hpp"
#include "core/network/traffic_store.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace slop::core::runtime::engine_dump {

using game_tools::reader_t;

// ═══ UE4/UE5 SDK DUMPER (Dumper-7 approach) ══════════════════════════════
// Walk GObjects array, resolve FNames, dump class hierarchy with offsets

struct ue_property_t {
    std::string name;
    std::string type;       // "int32", "float", "FVector", "UObject*", etc.
    uint32_t    offset = 0;
    uint32_t    size = 0;
};

struct ue_function_t {
    std::string name;
    uint64_t    func_ptr = 0;    // native function pointer
    uint32_t    flags = 0;
};

struct ue_class_t {
    std::string name;
    std::string package;
    std::string super_class;
    uint64_t    address = 0;     // UObject* in memory
    uint32_t    size = 0;        // class instance size
    std::vector<ue_property_t> properties;
    std::vector<ue_function_t> functions;
};

struct ue_enum_t {
    std::string name;
    std::vector<std::pair<std::string, int64_t>> values;
};

struct ue_sdk_dump_t {
    std::vector<ue_class_t> classes;
    std::vector<ue_enum_t>  enums;
    uint64_t gobjects_addr = 0;
    uint64_t gnames_addr = 0;
    size_t   object_count = 0;
    std::string engine_version;  // "4.27", "5.3", etc.
    std::vector<std::string> warnings;
};

// find GObjects and GNames in the game module
uint64_t find_gobjects(const reader_t& r, uint64_t module_base, uint32_t module_size);
uint64_t find_gnames(const reader_t& r, uint64_t module_base, uint32_t module_size);

// dump the full UE SDK from live memory
ue_sdk_dump_t dump_ue_sdk(const reader_t& r, uint64_t module_base,
                           uint32_t module_size, size_t max_objects = 100000);

// export SDK as C++ headers to a directory
bool export_ue_sdk(const ue_sdk_dump_t& sdk, const std::string& output_dir);

// ═══ UNITY IL2CPP DUMPER (Il2CppDumper approach) ═════════════════════════
// Parse global-metadata.dat and GameAssembly.dll from memory

struct il2cpp_field_t {
    std::string name;
    std::string type;
    uint32_t    offset = 0;
    uint32_t    token = 0;
};

struct il2cpp_method_t {
    std::string name;
    std::string return_type;
    std::vector<std::pair<std::string, std::string>> params; // name, type
    uint64_t    method_ptr = 0;    // native method pointer
    uint32_t    token = 0;
    bool        is_virtual = false;
    bool        is_static = false;
};

struct il2cpp_class_t {
    std::string namespace_name;
    std::string name;
    std::string full_name;         // namespace.name
    std::string parent;
    uint64_t    address = 0;       // Il2CppClass* in memory
    uint32_t    instance_size = 0;
    uint32_t    token = 0;
    std::vector<il2cpp_field_t> fields;
    std::vector<il2cpp_method_t> methods;
    std::vector<std::string> interfaces;
};

struct il2cpp_string_literal_t {
    uint32_t index;
    std::string value;
};

struct il2cpp_dump_t {
    std::vector<il2cpp_class_t> classes;
    std::vector<il2cpp_string_literal_t> string_literals;
    uint64_t metadata_addr = 0;
    uint64_t codegenmodules_addr = 0;
    size_t   class_count = 0;
    size_t   method_count = 0;
    std::string unity_version;
    std::vector<std::string> warnings;
};

// find il2cpp metadata registration in GameAssembly.dll
uint64_t find_il2cpp_metadata(const reader_t& r, uint64_t ga_base, uint32_t ga_size);

// dump Il2Cpp class info from live memory
il2cpp_dump_t dump_il2cpp(const reader_t& r, uint64_t ga_base,
                           uint32_t ga_size, size_t max_classes = 50000);

// export as C# dummy DLL stub info (dump.cs format)
bool export_il2cpp_cs(const il2cpp_dump_t& dump, const std::string& output_path);

// export as C++ header with offsets
bool export_il2cpp_header(const il2cpp_dump_t& dump, const std::string& output_path);

// ═══ TELESCOPE (pwndbg-style recursive pointer deref) ════════════════════

struct telescope_entry_t {
    uint64_t    address;
    uint64_t    value;
    std::string annotation;    // "→ code", "→ string", "→ heap", "→ stack", etc.
    bool        is_pointer;    // true if value looks like a valid pointer
    int         depth;
};

std::vector<telescope_entry_t> telescope(
    const reader_t& r, uint64_t start_addr,
    const std::vector<runtime::module_info_t>& modules,
    const std::vector<runtime::region_info_t>& regions,
    int max_depth = 8);

// ═══ API SCHEMA INFERENCE (mitmproxy2swagger approach) ════════════════════

struct api_endpoint_t {
    std::string method;        // GET, POST, PUT, etc.
    std::string path;          // /api/v1/users
    std::string host;
    uint16_t    port;
    size_t      request_count;
    std::vector<std::string> content_types;
    std::vector<std::string> sample_bodies;  // first few request bodies
};

struct api_schema_t {
    std::vector<api_endpoint_t> endpoints;
    std::string base_url;
    size_t total_requests;
};

// infer API endpoints from captured packets
api_schema_t infer_api_schema(
    const network::traffic_store_t& store,
    uint32_t filter_pid = 0);

// export as OpenAPI/Swagger YAML
bool export_openapi(const api_schema_t& schema,
                     const std::string& output_path);

} // namespace slop::core::runtime::engine_dump
