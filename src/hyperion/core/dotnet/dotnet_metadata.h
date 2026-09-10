#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <array>
#include <unordered_map>

// ECMA-335 (CLI) metadata reader. Given the metadata root (the "BSJB" region a
// managed PE points to from its CLI header) this parses the stream directory,
// the #~ / #- table stream with correct per-table row sizes, and the #Strings /
// #US / #Blob / #GUID heaps. It exposes typed row accessors for the tables the
// IL disassembler needs plus token -> human-readable-name resolution and blob
// signature decoding.
//
// Row sizes are the crux of a correct reader: every table's start offset is the
// running sum of the preceding tables' (row_count * row_size), and a row size is
// the sum of its columns' widths, where heap-index, simple-rid and coded-index
// columns are 2 or 4 bytes depending on heap-size flags and row counts. Get one
// width wrong and every later table is misaligned, so the full 45-table schema
// (II.22) is encoded rather than guessed.

namespace hype {

// Metadata table indices (ECMA-335 II.22). Values are the table numbers used in
// the Valid bitmask and the high byte of metadata tokens.
namespace mdt {
enum : u32 {
    Module = 0x00, TypeRef = 0x01, TypeDef = 0x02, FieldPtr = 0x03, Field = 0x04,
    MethodPtr = 0x05, MethodDef = 0x06, ParamPtr = 0x07, Param = 0x08,
    InterfaceImpl = 0x09, MemberRef = 0x0A, Constant = 0x0B, CustomAttribute = 0x0C,
    FieldMarshal = 0x0D, DeclSecurity = 0x0E, ClassLayout = 0x0F, FieldLayout = 0x10,
    StandAloneSig = 0x11, EventMap = 0x12, EventPtr = 0x13, Event = 0x14,
    PropertyMap = 0x15, PropertyPtr = 0x16, Property = 0x17, MethodSemantics = 0x18,
    MethodImpl = 0x19, ModuleRef = 0x1A, TypeSpec = 0x1B, ImplMap = 0x1C,
    FieldRVA = 0x1D, EncLog = 0x1E, EncMap = 0x1F, Assembly = 0x20,
    AssemblyProcessor = 0x21, AssemblyOS = 0x22, AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24, AssemblyRefOS = 0x25, File = 0x26,
    ExportedType = 0x27, ManifestResource = 0x28, NestedClass = 0x29,
    GenericParam = 0x2A, MethodSpec = 0x2B, GenericParamConstraint = 0x2C,
    kCount = 64
};
}

class MetadataReader {
public:
    // Parse from the metadata root region [root, root+size). Returns false if the
    // BSJB signature, stream directory or #~ table header is malformed.
    bool init(const u8* root, size_t size);
    bool valid() const { return valid_; }

    // Version string from the metadata root header, e.g. "v4.0.30319".
    const std::string& version() const { return version_; }

    // Assembly name from the Assembly table (empty for a netmodule).
    std::string assembly_name() const;

    u32  table_rows(u32 table) const {
        return table < mdt::kCount ? tables_[table].rows : 0;
    }
    bool has_table(u32 table) const { return table_rows(table) > 0; }

    // ---- Heaps -----------------------------------------------------------
    std::string string_at(u32 off) const;        // #Strings, UTF-8, NUL terminated
    std::string user_string_at(u32 off) const;   // #US, UTF-16 -> displayable
    const u8*   blob_at(u32 off, u32& len) const; // #Blob, length-prefixed

    // ---- Coded index decode ---------------------------------------------
    // Coded index kinds (II.24.2.6), used both for row-size computation and for
    // turning a stored coded value back into a (table, rid) pair.
    enum class Coded : u8 {
        TypeDefOrRef, HasConstant, HasCustomAttribute, HasFieldMarshal,
        HasDeclSecurity, MemberRefParent, HasSemantics, MethodDefOrRef,
        MemberForwarded, Implementation, CustomAttributeType, ResolutionScope,
        TypeOrMethodDef, kCount
    };
    struct TokenRef { u32 table; u32 rid; };
    TokenRef decode_coded(Coded kind, u32 value) const;

    // ---- Typed row accessors for the tables the disassembler consumes -----
    struct TypeDefRow  { u32 flags; u32 name; u32 ns; u32 extends; u32 field_list; u32 method_list; };
    struct MethodDefRow{ u32 rva; u16 impl_flags; u16 flags; u32 name; u32 sig; u32 param_list; };
    struct FieldRow    { u16 flags; u32 name; u32 sig; };
    struct ParamRow    { u16 flags; u16 seq; u32 name; };
    struct PropertyRow { u16 flags; u32 name; u32 sig; };
    struct EventRow    { u16 flags; u32 name; u32 event_type; };  // event_type = TypeDefOrRef coded
    struct SemanticsRow{ u16 flags; u32 method; u32 assoc; };     // assoc = HasSemantics coded
    struct IfaceImplRow{ u32 cls; u32 iface; };                   // iface = TypeDefOrRef coded
    struct NestedRow   { u32 nested; u32 enclosing; };            // both TypeDef rids
    struct CustomAttrRow{ u32 parent; u32 type; };                // HasCustomAttribute / CustomAttributeType coded

    TypeDefRow   type_def(u32 rid) const;
    MethodDefRow method_def(u32 rid) const;
    FieldRow     field(u32 rid) const;
    ParamRow     param(u32 rid) const;
    PropertyRow  property(u32 rid) const;
    EventRow     event_row(u32 rid) const;
    SemanticsRow method_semantics(u32 rid) const;
    IfaceImplRow iface_impl(u32 rid) const;
    NestedRow    nested_class(u32 rid) const;
    CustomAttrRow custom_attribute(u32 rid) const;

    // Declaring TypeDef rid that owns a given MethodDef / Field / Property /
    // Event rid (0 if none). Property/Event owners come from the Property/Event
    // Map tables, built once in compute_layout().
    u32 method_decl_type(u32 method_rid) const;
    u32 field_decl_type(u32 field_rid) const;
    u32 property_decl_type(u32 property_rid) const;
    u32 event_decl_type(u32 event_rid) const;

    // Enclosing TypeDef rid of a nested type (0 if top-level).
    u32 nested_enclosing(u32 type_rid) const;

    // Property type (return type of a PROPERTY signature blob).
    std::string property_type(u32 blob_off) const;

    // Rendered constant literal (Constant table) for a Field/Property/Param rid,
    // or "" when the member carries no default. `table` is mdt::Field etc.
    std::string constant_for(u32 parent_table, u32 parent_rid) const;

    // Resolved signature facts about a call/newobj target, for the C# body
    // decompiler. Handles MethodDef / MemberRef / MethodSpec tokens.
    struct CallInfo {
        u32         arg_count = 0;      // signature parameter count (no `this`)
        bool        has_this = false;
        bool        returns_void = true;
        std::string simple_name;        // method name only (".ctor", "WriteLine", ...)
        std::string decl_type;          // declaring type full name
    };
    CallInfo call_info(u32 token) const;

    // ---- Name resolution -------------------------------------------------
    // token is a full 4-byte metadata token (high byte = table). These never
    // throw; on a bad token they return a "<table:rid>" placeholder.
    std::string type_name(u32 token) const;     // TypeDef/TypeRef/TypeSpec
    std::string method_name(u32 token) const;   // MethodDef/MemberRef/MethodSpec
    std::string field_name(u32 token) const;    // Field/MemberRef
    std::string token_name(u32 token) const;    // ldtoken: dispatch on table

    // ---- Signature parsing ----------------------------------------------
    struct MethodSig {
        std::string              ret;
        std::vector<std::string> params;
        bool                     has_this = false;
        bool                     vararg   = false;
        u32                      gen_params = 0;
    };
    MethodSig                parse_method_sig(u32 blob_off) const;
    std::vector<std::string> parse_local_sig(u32 standalone_sig_token) const;
    std::string              field_type(u32 blob_off) const;

private:
    // Per-table geometry, filled by compute_layout().
    struct TableInfo {
        u32                 rows = 0;
        u32                 row_size = 0;
        const u8*           data = nullptr;      // first row
        std::array<u8, 16>  col_off{};           // byte offset of each column in a row
        std::array<u8, 16>  col_size{};          // width (2 or 4) of each column
        u8                  col_count = 0;
    };

    bool parse_streams(const u8* root, size_t size);
    bool parse_table_header();
    void compute_layout();

    // Width helpers used during layout.
    u8 heap_index_size(u8 which) const;          // 0=Str 1=Guid 2=Blob
    u8 rid_size(u32 table) const;                // simple table index width
    u8 coded_size(Coded kind) const;             // coded index width

    // Read a single column value (raw stored integer) from a decoded row.
    u32 read_col(u32 table, u32 rid, u32 col) const;

    // Signature element reader shared by method/field/local parsers.
    std::string read_type(const u8*& p, const u8* end) const;

    bool valid_ = false;
    std::string version_;

    // Stream regions (pointers into the caller-owned metadata root buffer).
    const u8* strings_ = nullptr; size_t strings_sz_ = 0;
    const u8* us_      = nullptr; size_t us_sz_      = 0;
    const u8* blob_    = nullptr; size_t blob_sz_    = 0;
    const u8* guid_    = nullptr; size_t guid_sz_    = 0;
    const u8* tables_stream_ = nullptr; size_t tables_stream_sz_ = 0;

    u8 heap_sizes_ = 0;
    u8 str_idx_ = 2, guid_idx_ = 2, blob_idx_ = 2;
    u64 valid_mask_ = 0;
    size_t tables_data_start_ = 0;   // offset of first row past the #~ header

    std::array<TableInfo, mdt::kCount> tables_{};

    // member_rid -> owning TypeDef rid, all built once in compute_layout().
    std::vector<u32> method_owner_;
    std::vector<u32> field_owner_;
    std::vector<u32> property_owner_;
    std::vector<u32> event_owner_;
    std::vector<u32> nested_enclosing_;   // type_rid -> enclosing type rid

    // (parent_table<<24 | parent_rid) -> Constant table rid, for default values.
    std::unordered_map<u32, u32> constant_index_;
};

}
