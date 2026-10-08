// src/core/runtime/engine_dumper.cpp
// UE SDK dumper, Il2Cpp metadata reader, telescope, API schema inference.
#include "core/runtime/engine_dumper.hpp"
#include "core/runtime/world_projection.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace slop::core::runtime::engine_dump {
using namespace slop::core::runtime;

// ═══ UE SDK DUMPER ═══════════════════════════════════════════════════════

// GObjects pattern: look for the FUObjectArray signature
// The array is typically at a fixed offset from the module base,
// found by scanning for characteristic byte patterns
uint64_t find_gobjects(const reader_t& r, uint64_t base, uint32_t size) {
    // scan for the FChunkedFixedUObjectArray pattern:
    // a pointer followed by MaxElements, NumElements, MaxChunks, NumChunks
    // heuristic: find a region where [ptr, int32>0, int32>0, int32>0, int32>0]
    // and ptr points to a valid array of pointers
    const size_t scan_sz = std::min<size_t>(size, 8 * 1024 * 1024);
    std::vector<uint8_t> buf(scan_sz);
    if (!r.read(base, buf.data(), scan_sz)) return 0;

    for (size_t i = 0; i + 32 <= scan_sz; i += 8) {
        uint64_t ptr = 0;
        std::memcpy(&ptr, buf.data() + i, 8);
        if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

        int32_t max_elem = 0, num_elem = 0, max_chunks = 0, num_chunks = 0;
        std::memcpy(&max_elem, buf.data() + i + 0x10, 4);
        std::memcpy(&num_elem, buf.data() + i + 0x14, 4);
        std::memcpy(&max_chunks, buf.data() + i + 0x18, 4);
        std::memcpy(&num_chunks, buf.data() + i + 0x1C, 4);

        if (num_elem > 1000 && num_elem < 10000000 &&
            max_elem >= num_elem && max_elem < 20000000 &&
            num_chunks > 0 && num_chunks < 1000 &&
            max_chunks >= num_chunks && max_chunks < 2000) {
            // verify: read the first chunk pointer
            uint64_t chunk0 = 0;
            if (r.read(ptr, &chunk0, 8) && chunk0 > 0x10000 && chunk0 < 0x7FFFFFFFFFFF) {
                return base + i;
            }
        }
    }
    return 0;
}

uint64_t find_gnames(const reader_t& r, uint64_t base, uint32_t size) {
    // GNames: FNamePool or TNameEntryArray
    // scan for a chunked array with plausible counts
    const size_t scan_sz = std::min<size_t>(size, 8 * 1024 * 1024);
    std::vector<uint8_t> buf(scan_sz);
    if (!r.read(base, buf.data(), scan_sz)) return 0;

    for (size_t i = 0; i + 24 <= scan_sz; i += 8) {
        uint64_t ptr = 0;
        std::memcpy(&ptr, buf.data() + i, 8);
        if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

        // try reading as a chunked name array
        uint64_t chunk0 = 0;
        if (!r.read(ptr, &chunk0, 8)) continue;
        if (chunk0 < 0x10000 || chunk0 > 0x7FFFFFFFFFFF) continue;

        // verify: first name entry should have a short string
        uint16_t header = 0;
        if (!r.read(chunk0, &header, 2)) continue;
        int len = header >> 6;
        if (len <= 0) len = header & 0x3FF;
        if (len > 2 && len < 64) {
            char name[64] = {};
            r.read(chunk0 + 2, name, std::min<size_t>(len, 63));
            // common first names: "None", "ByteProperty", etc.
            if (std::strcmp(name, "None") == 0 ||
                std::strstr(name, "Property") ||
                std::strstr(name, "Object")) {
                return base + i;
            }
        }
    }
    return 0;
}

ue_sdk_dump_t dump_ue_sdk(const reader_t& r, uint64_t module_base,
                           uint32_t module_size, size_t max_objects) {
    ue_sdk_dump_t sdk;
    sdk.gobjects_addr = find_gobjects(r, module_base, module_size);
    sdk.gnames_addr = find_gnames(r, module_base, module_size);

    if (!sdk.gobjects_addr) {
        sdk.warnings.push_back("GObjects not found — try a different module or manual offset");
        return sdk;
    }
    if (!sdk.gnames_addr) {
        sdk.warnings.push_back("GNames not found — FName resolution will be limited");
    }

    // read the object array
    struct { uint64_t objects; uint64_t pad; int32_t max_elem, num_elem, max_chunks, num_chunks; } arr{};
    r.read(sdk.gobjects_addr, &arr, sizeof(arr));
    sdk.object_count = arr.num_elem;

    if (arr.num_elem <= 0 || arr.num_elem > static_cast<int32_t>(max_objects)) {
        sdk.warnings.push_back("object count out of range: " + std::to_string(arr.num_elem));
        return sdk;
    }

    // walk objects: each chunk holds up to 64K objects
    const int chunk_size = 65536;
    std::map<uint64_t, ue_class_t> classes_by_addr;

    for (int chunk = 0; chunk < arr.num_chunks && chunk < 1000; ++chunk) {
        uint64_t chunk_ptr = 0;
        r.read(arr.objects + chunk * 8, &chunk_ptr, 8);
        if (!chunk_ptr) continue;

        const int start = chunk * chunk_size;
        const int end = std::min(start + chunk_size, arr.num_elem);

        for (int idx = start; idx < end; ++idx) {
            // each entry is typically 24 bytes: Object*, SerialNumber, pad
            uint64_t obj_ptr = 0;
            r.read(chunk_ptr + (idx - start) * 24, &obj_ptr, 8);
            if (!obj_ptr) continue;

            // read UObject fields:
            //   +0x00: vtable
            //   +0x08: ObjectFlags (int32)
            //   +0x0C: InternalIndex (int32)
            //   +0x10: ClassPrivate (UClass*)
            //   +0x18: NamePrivate (FName = 2x int32)
            //   +0x20: OuterPrivate (UObject*)
            uint8_t uobj[0x30] = {};
            if (!r.read(obj_ptr, uobj, sizeof(uobj))) continue;

            uint64_t class_ptr = 0;
            std::memcpy(&class_ptr, uobj + 0x10, 8);
            int32_t name_idx = 0;
            std::memcpy(&name_idx, uobj + 0x18, 4);

            // resolve the name via GNames
            std::string obj_name;
            if (sdk.gnames_addr && name_idx >= 0 && name_idx < 10000000) {
                obj_name = projection::read_ue_fname(r, sdk.gnames_addr, name_idx);
            }
            if (obj_name.empty()) {
                char hex[24];
                std::snprintf(hex, sizeof(hex), "Object_%X", static_cast<unsigned>(idx));
                obj_name = hex;
            }

            // check if this is a UClass (vtable slot check: UClass has ClassPrivate == itself or its metaclass)
            if (class_ptr == obj_ptr || obj_name.find("Class") != std::string::npos) {
                ue_class_t cls;
                cls.name = obj_name;
                cls.address = obj_ptr;

                // read super class
                uint64_t super = 0;
                r.read(obj_ptr + 0x40, &super, 8); // SuperStruct offset varies
                if (super && sdk.gnames_addr) {
                    int32_t super_name = 0;
                    r.read(super + 0x18, &super_name, 4);
                    cls.super_class = projection::read_ue_fname(r, sdk.gnames_addr, super_name);
                }

                // read properties size
                int32_t prop_size = 0;
                r.read(obj_ptr + 0x58, &prop_size, 4); // PropertiesSize offset
                cls.size = prop_size;

                classes_by_addr[obj_ptr] = std::move(cls);
            }

            if (classes_by_addr.size() >= max_objects / 10) break;
        }
    }

    for (auto& [addr, cls] : classes_by_addr) {
        sdk.classes.push_back(std::move(cls));
    }
    std::sort(sdk.classes.begin(), sdk.classes.end(),
              [](const auto& a, const auto& b) { return a.name < b.name; });

    return sdk;
}

bool export_ue_sdk(const ue_sdk_dump_t& sdk, const std::string& dir) {
    std::filesystem::create_directories(dir);
    std::ofstream f(dir + "/SDK.h");
    if (!f) return false;
    f << "// Auto-generated UE SDK by the engine\n";
    f << "// Classes: " << sdk.classes.size() << "\n";
    f << "// GObjects: 0x" << std::hex << sdk.gobjects_addr << "\n";
    f << "// GNames: 0x" << sdk.gnames_addr << "\n\n";
    f << "#pragma once\n#include <cstdint>\n\n";
    for (const auto& cls : sdk.classes) {
        f << "// " << cls.name << " (size: 0x" << std::hex << cls.size << ")\n";
        f << "class " << cls.name;
        if (!cls.super_class.empty()) f << " : public " << cls.super_class;
        f << " {\npublic:\n";
        for (const auto& p : cls.properties) {
            f << "    " << p.type << " " << p.name
              << "; // 0x" << std::hex << p.offset << "\n";
        }
        f << "}; // Size: 0x" << std::hex << cls.size << "\n\n";
    }
    return true;
}

// ═══ IL2CPP DUMPER ═══════════════════════════════════════════════════════

uint64_t find_il2cpp_metadata(const reader_t& r, uint64_t base, uint32_t size) {
    // scan for the Il2Cpp metadata registration signature
    // il2cpp_codegen_register() stores pointers to CodeGenModules array
    // and the metadata registration struct
    const size_t scan_sz = std::min<size_t>(size, 16 * 1024 * 1024);
    std::vector<uint8_t> buf(scan_sz);
    if (!r.read(base, buf.data(), scan_sz)) return 0;

    // look for the "global-metadata.dat" magic: AF 1B B1 FA
    const uint8_t magic[] = { 0xAF, 0x1B, 0xB1, 0xFA };
    for (size_t i = 0; i + 4 <= scan_sz; ++i) {
        if (std::memcmp(buf.data() + i, magic, 4) == 0) {
            return base + i;
        }
    }
    return 0;
}

il2cpp_dump_t dump_il2cpp(const reader_t& r, uint64_t ga_base,
                           uint32_t ga_size, size_t max_classes) {
    il2cpp_dump_t dump;

    // find the metadata registration
    dump.metadata_addr = find_il2cpp_metadata(r, ga_base, ga_size);

    // scan for il2cpp_codegen_register pattern:
    // LEA RCX, [rip + offset] ; address of s_Il2CppCodeGenRegistration
    // this gives us the codegenmodules array
    const size_t scan_sz = std::min<size_t>(ga_size, 8 * 1024 * 1024);
    std::vector<uint8_t> code(scan_sz);
    if (!r.read(ga_base, code.data(), scan_sz)) return dump;

    // search for "il2cpp_codegen_register" string reference
    const char marker[] = "il2cpp_codegen_register";
    for (size_t i = 0; i + sizeof(marker) <= scan_sz; ++i) {
        if (std::memcmp(code.data() + i, marker, sizeof(marker) - 1) == 0) {
            dump.warnings.push_back("il2cpp_codegen_register string found at +" +
                                     std::to_string(i));
            break;
        }
    }

    // alternative: scan for Il2CppClass** array pattern
    // each Il2CppClass has: image, gc_desc, name, namespaze, byval_arg, ...
    // scan .data section for an array of pointers where each target has
    // a valid name pointer
    for (size_t i = 0; i + 8 <= scan_sz; i += 8) {
        uint64_t cls_ptr = 0;
        std::memcpy(&cls_ptr, code.data() + i, 8);
        if (cls_ptr < 0x10000 || cls_ptr > 0x7FFFFFFFFFFF) continue;

        // read Il2CppClass header:
        //   +0x00: image (Il2CppImage*)
        //   +0x08: gc_desc (void*)
        //   +0x10: name (const char*)
        //   +0x18: namespaze (const char*)
        //   +0x20: byval_arg (Il2CppType)
        //   +0x28: this_arg (Il2CppType)
        //   +0x???: parent (Il2CppClass*)
        uint8_t cls[0x100] = {};
        if (!r.read(cls_ptr, cls, sizeof(cls))) continue;

        uint64_t name_ptr = 0, ns_ptr = 0;
        std::memcpy(&name_ptr, cls + 0x10, 8);
        std::memcpy(&ns_ptr, cls + 0x18, 8);

        if (name_ptr < 0x10000 || name_ptr > 0x7FFFFFFFFFFF) continue;

        char name[128] = {}, ns[128] = {};
        r.read(name_ptr, name, sizeof(name) - 1);
        if (ns_ptr > 0x10000) r.read(ns_ptr, ns, sizeof(ns) - 1);

        // validate: name should be a valid C# identifier
        if (name[0] < 'A' || (name[0] > 'Z' && name[0] < 'a') || name[0] > 'z')
            continue;
        bool valid = true;
        for (int j = 0; name[j] && j < 64; ++j) {
            if (!std::isalnum(name[j]) && name[j] != '_' && name[j] != '<' &&
                name[j] != '>' && name[j] != '`') {
                valid = false; break;
            }
        }
        if (!valid) continue;

        il2cpp_class_t c;
        c.name = name;
        c.namespace_name = ns;
        c.full_name = ns[0] ? std::string(ns) + "." + name : name;
        c.address = cls_ptr;

        // read instance size
        uint32_t inst_size = 0;
        std::memcpy(&inst_size, cls + 0x80, 4); // varies by version
        if (inst_size > 0 && inst_size < 0x100000) c.instance_size = inst_size;

        // read parent
        uint64_t parent = 0;
        std::memcpy(&parent, cls + 0x58, 8); // varies
        if (parent > 0x10000) {
            char pname[64] = {};
            uint64_t pname_ptr = 0;
            r.read(parent + 0x10, &pname_ptr, 8);
            if (pname_ptr > 0x10000) r.read(pname_ptr, pname, sizeof(pname) - 1);
            c.parent = pname;
        }

        dump.classes.push_back(std::move(c));
        if (dump.classes.size() >= max_classes) break;
    }

    dump.class_count = dump.classes.size();
    std::sort(dump.classes.begin(), dump.classes.end(),
              [](const auto& a, const auto& b) { return a.full_name < b.full_name; });
    return dump;
}

bool export_il2cpp_cs(const il2cpp_dump_t& dump, const std::string& path) {
    std::ofstream f(path);
    if (!f) return false;
    f << "// Auto-generated by the engine Il2Cpp dumper\n";
    f << "// Classes: " << dump.classes.size() << "\n\n";
    for (const auto& c : dump.classes) {
        f << "// Namespace: " << c.namespace_name << "\n";
        if (!c.parent.empty()) f << "// Parent: " << c.parent << "\n";
        f << "public class " << c.name;
        if (!c.parent.empty()) f << " : " << c.parent;
        f << " // Size: 0x" << std::hex << c.instance_size << "\n{\n";
        for (const auto& field : c.fields) {
            f << "    public " << field.type << " " << field.name
              << "; // 0x" << std::hex << field.offset << "\n";
        }
        for (const auto& m : c.methods) {
            f << "    " << (m.is_static ? "static " : "")
              << m.return_type << " " << m.name << "(";
            for (size_t i = 0; i < m.params.size(); ++i) {
                if (i > 0) f << ", ";
                f << m.params[i].second << " " << m.params[i].first;
            }
            f << "); // RVA: 0x" << std::hex << (m.method_ptr ? m.method_ptr : 0) << "\n";
        }
        f << "}\n\n";
    }
    return true;
}

bool export_il2cpp_header(const il2cpp_dump_t& dump, const std::string& path) {
    std::ofstream f(path);
    if (!f) return false;
    f << "// Auto-generated Il2Cpp header by the engine\n#pragma once\n\n";
    for (const auto& c : dump.classes) {
        f << "struct " << c.name << " {\n";
        for (const auto& field : c.fields) {
            f << "    " << field.type << " " << field.name
              << "; // +0x" << std::hex << field.offset << "\n";
        }
        if (c.fields.empty()) {
            f << "    char _pad[0x" << std::hex << c.instance_size << "];\n";
        }
        f << "}; // 0x" << std::hex << c.instance_size << "\n\n";
    }
    return true;
}

// ═══ TELESCOPE ═══════════════════════════════════════════════════════════

std::vector<telescope_entry_t> telescope(
    const reader_t& r, uint64_t start,
    const std::vector<runtime::module_info_t>& modules,
    const std::vector<runtime::region_info_t>& regions,
    int max_depth)
{
    std::vector<telescope_entry_t> chain;

    auto classify = [&](uint64_t addr) -> std::string {
        for (const auto& m : modules) {
            if (addr >= m.base && addr < m.base + m.size) {
                return "→ " + m.name;
            }
        }
        for (const auto& r : regions) {
            if (addr >= r.base && addr < r.base + r.size) {
                if (r.protect & 0x10) return "→ code (exec)";
                if (r.type == 0x20000) return "→ heap (private)";
                if (r.type == 0x1000000) return "→ image";
                return "→ data";
            }
        }
        return "→ ?";
    };

    uint64_t addr = start;
    for (int depth = 0; depth < max_depth; ++depth) {
        telescope_entry_t e;
        e.address = addr;
        e.depth = depth;

        uint64_t val = 0;
        if (!r.read(addr, &val, 8)) {
            e.value = 0;
            e.annotation = "(unreadable)";
            e.is_pointer = false;
            chain.push_back(e);
            break;
        }

        e.value = val;

        // check if it's a string
        char str[32] = {};
        if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
            r.read(val, str, sizeof(str) - 1);
            bool printable = true;
            int printable_count = 0;
            for (int i = 0; str[i] && i < 30; ++i) {
                if (str[i] >= 32 && str[i] < 127) ++printable_count;
                else { printable = false; break; }
            }
            if (printable && printable_count >= 4) {
                e.annotation = "→ \"" + std::string(str, std::min<size_t>(printable_count, 24)) + "\"";
                e.is_pointer = true;
                chain.push_back(e);
                break; // string is terminal
            }
        }

        // check if it's a valid pointer
        if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
            e.is_pointer = true;
            e.annotation = classify(val);
            chain.push_back(e);
            addr = val; // follow the pointer
        } else {
            e.is_pointer = false;
            if (val == 0) e.annotation = "(null)";
            else if (val <= 0xFFFF) e.annotation = "(small int)";
            else {
                float fval;
                std::memcpy(&fval, &val, 4);
                if (std::isfinite(fval) && std::abs(fval) > 0.001f && std::abs(fval) < 1e6f) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "(float: %.3f)", fval);
                    e.annotation = buf;
                } else {
                    e.annotation = "(value)";
                }
            }
            chain.push_back(e);
            break; // not a pointer, stop
        }
    }
    return chain;
}

// ═══ API SCHEMA INFERENCE ════════════════════════════════════════════════

api_schema_t infer_api_schema(const network::traffic_store_t& store,
                               uint32_t filter_pid) {
    api_schema_t schema;
    auto page = store.packets(0, 10000);

    std::map<std::string, api_endpoint_t> endpoints;

    for (const auto& pkt : page.items) {
        if (pkt.direction != 0) continue; // outbound only
        if (filter_pid && pkt.pid != filter_pid) continue;
        if (pkt.payload.size() < 16) continue;

        // try to parse as HTTP
        std::string payload(pkt.payload.begin(),
                             pkt.payload.begin() + std::min<size_t>(pkt.payload.size(), 2048));

        // look for HTTP method
        std::string method, path;
        if (payload.substr(0, 4) == "GET " || payload.substr(0, 5) == "POST " ||
            payload.substr(0, 4) == "PUT " || payload.substr(0, 7) == "DELETE " ||
            payload.substr(0, 6) == "PATCH ") {
            size_t sp1 = payload.find(' ');
            size_t sp2 = payload.find(' ', sp1 + 1);
            if (sp1 != std::string::npos && sp2 != std::string::npos) {
                method = payload.substr(0, sp1);
                path = payload.substr(sp1 + 1, sp2 - sp1 - 1);
            }
        }
        if (method.empty()) continue;

        // extract host header
        std::string host = pkt.remote_addr + ":" + std::to_string(pkt.remote_port);
        auto host_pos = payload.find("Host: ");
        if (host_pos != std::string::npos) {
            auto host_end = payload.find("\r\n", host_pos);
            if (host_end != std::string::npos) {
                host = payload.substr(host_pos + 6, host_end - host_pos - 6);
            }
        }

        std::string key = method + " " + path;
        auto& ep = endpoints[key];
        ep.method = method;
        ep.path = path;
        ep.host = host;
        ep.port = pkt.remote_port;
        ep.request_count++;

        // extract content-type
        auto ct_pos = payload.find("Content-Type: ");
        if (ct_pos != std::string::npos) {
            auto ct_end = payload.find("\r\n", ct_pos);
            if (ct_end != std::string::npos) {
                std::string ct = payload.substr(ct_pos + 14, ct_end - ct_pos - 14);
                if (std::find(ep.content_types.begin(), ep.content_types.end(), ct) == ep.content_types.end())
                    ep.content_types.push_back(ct);
            }
        }

        // extract body (after \r\n\r\n)
        auto body_pos = payload.find("\r\n\r\n");
        if (body_pos != std::string::npos && ep.sample_bodies.size() < 3) {
            ep.sample_bodies.push_back(
                payload.substr(body_pos + 4, std::min<size_t>(512, payload.size() - body_pos - 4)));
        }
    }

    for (auto& [key, ep] : endpoints) {
        schema.endpoints.push_back(std::move(ep));
        schema.total_requests += ep.request_count;
    }
    std::sort(schema.endpoints.begin(), schema.endpoints.end(),
              [](const auto& a, const auto& b) { return a.request_count > b.request_count; });
    return schema;
}

bool export_openapi(const api_schema_t& schema, const std::string& path) {
    std::ofstream f(path);
    if (!f) return false;
    f << "openapi: '3.0.0'\n";
    f << "info:\n  title: Auto-discovered API\n  version: '1.0'\n";
    if (!schema.base_url.empty()) {
        f << "servers:\n  - url: " << schema.base_url << "\n";
    }
    f << "paths:\n";
    for (const auto& ep : schema.endpoints) {
        f << "  " << ep.path << ":\n";
        std::string method_lower = ep.method;
        for (char& c : method_lower) c = static_cast<char>(std::tolower(c));
        f << "    " << method_lower << ":\n";
        f << "      summary: 'Auto-discovered (" << ep.request_count << " requests)'\n";
        if (!ep.content_types.empty()) {
            f << "      requestBody:\n        content:\n";
            for (const auto& ct : ep.content_types) {
                f << "          " << ct << ": {}\n";
            }
        }
        f << "      responses:\n        '200':\n          description: OK\n";
    }
    return true;
}

} // namespace slop::core::runtime::engine_dump
