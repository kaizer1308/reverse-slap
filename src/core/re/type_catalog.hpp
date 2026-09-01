#pragma once

// the struct and enum catalog over the loaded binary, computed layouts,
// a mini c parser, field reads from the file image or live memory,
// persisted per binary hash

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::re::type_catalog {

struct field_t {
    std::string name;
    std::string type;            // "u8..u64,i8..i64,f32,f64,ptr,<StructName>,char[N]"
    uint64_t    offset = 0;
    uint64_t    size   = 0;
    uint32_t    array_count = 0; // 0 = scalar
};

struct struct_def_t {
    std::string          name;
    uint64_t             size = 0;
    bool                 packed = false;
    std::vector<field_t> fields;
};

struct enum_def_t {
    std::string name;
    std::string underlying = "u32";
    std::vector<std::pair<std::string, int64_t>> values;
};

// binary binding

// rebind to a binary hash and load its persisted types, safe to repeat
void bind_binary(const uint8_t* bytes, size_t len);

// queries

std::optional<struct_def_t> get_struct(const std::string& name);
std::optional<enum_def_t>   get_enum(const std::string& name);
std::vector<struct_def_t>   list_structs(const std::string& filter = "");
std::vector<enum_def_t>     list_enums(const std::string& filter = "");

// mutations (persist immediately)

bool create_struct(struct_def_t def, std::string* error = nullptr);
bool add_member(const std::string& struct_name, const field_t& field,
                std::string* error = nullptr);
bool remove_struct(const std::string& name);
bool create_enum(enum_def_t def, std::string* error = nullptr);
bool remove_enum(const std::string& name);

// Layout helper: compute offsets/sizes for a struct definition in place
void layout_struct(struct_def_t& def);

// the mini c declaration parser, accepts one or more definitions
//   struct Name { u32 a; char b[16]; Other* c; i64 d; };
//   enum Tag : u8 { A = 1, B, C = 0x10 };
// base types are the iN uN float double family, pointers via trailing *

struct decl_parse_result_t {
    std::vector<struct_def_t> structs;
    std::vector<enum_def_t>   enums;
    std::string               error;
};

decl_parse_result_t parse_decls(const std::string& text);

// Type size lookup used by the parser and field readers (bytes)
uint64_t base_type_size(const std::string& type);

// field reads

struct field_value_t {
    bool        ok = false;
    std::string error;
    std::string hex;
    uint64_t    uint_val = 0;
    int64_t     int_val  = 0;
    double      dbl_val  = 0;
};

// read one field at base va from the file image or the live reader
using read_cb_t = bool (*)(uint64_t addr, void* dst, size_t len, void* user);
field_value_t read_field(const struct_def_t& strct, const std::string& field_name,
                         uint64_t base_va,
                         const uint8_t* file_bytes, size_t file_len,
                         read_cb_t reader, void* reader_user);

} // namespace slop::core::re::type_catalog
