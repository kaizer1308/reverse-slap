#include "dotnet_metadata.h"
#include <fmt/format.h>
#include <cstring>
#include <algorithm>

namespace hype {

namespace {

// ---- ECMA-335 element types (II.23.1.16) --------------------------------
enum : u8 {
    ET_END = 0x00, ET_VOID = 0x01, ET_BOOLEAN = 0x02, ET_CHAR = 0x03,
    ET_I1 = 0x04, ET_U1 = 0x05, ET_I2 = 0x06, ET_U2 = 0x07,
    ET_I4 = 0x08, ET_U4 = 0x09, ET_I8 = 0x0A, ET_U8 = 0x0B,
    ET_R4 = 0x0C, ET_R8 = 0x0D, ET_STRING = 0x0E, ET_PTR = 0x0F,
    ET_BYREF = 0x10, ET_VALUETYPE = 0x11, ET_CLASS = 0x12, ET_VAR = 0x13,
    ET_ARRAY = 0x14, ET_GENERICINST = 0x15, ET_TYPEDBYREF = 0x16,
    ET_I = 0x18, ET_U = 0x19, ET_FNPTR = 0x1B, ET_OBJECT = 0x1C,
    ET_SZARRAY = 0x1D, ET_MVAR = 0x1E, ET_CMOD_REQD = 0x1F, ET_CMOD_OPT = 0x20,
    ET_INTERNAL = 0x21, ET_SENTINEL = 0x41, ET_PINNED = 0x45
};

// Calling-convention low-nibble kinds and modifier flags (II.23.2.3).
enum : u8 {
    SIG_DEFAULT = 0x00, SIG_VARARG = 0x05, SIG_FIELD = 0x06, SIG_LOCAL = 0x07,
    SIG_PROPERTY = 0x08, SIG_GENERICINST = 0x0A,
    SIG_GENERIC = 0x10, SIG_HASTHIS = 0x20, SIG_EXPLICITTHIS = 0x40
};

using Coded = MetadataReader::Coded;

// Column kinds for the table schema. Rid/Cod carry a payload (the referenced
// table id, or the coded-index kind) so widths can be computed generically.
enum class CK : u8 { U16, U32, Str, Guid, Blob, Rid, Cod };
struct ColDef { CK kind; u8 arg; };

ColDef c16()          { return {CK::U16, 0}; }
ColDef c32()          { return {CK::U32, 0}; }
ColDef cstr()         { return {CK::Str, 0}; }
ColDef cguid()        { return {CK::Guid, 0}; }
ColDef cblob()        { return {CK::Blob, 0}; }
ColDef crid(u32 t)    { return {CK::Rid, static_cast<u8>(t)}; }
ColDef ccod(Coded k)  { return {CK::Cod, static_cast<u8>(k)}; }

// Full per-table column schema (ECMA-335 II.22). Every present table must be
// described so its row size (and therefore the next table's start) is exact.
std::vector<ColDef> columns_for(u32 table) {
    switch (table) {
    case mdt::Module:        return {c16(), cstr(), cguid(), cguid(), cguid()};
    case mdt::TypeRef:       return {ccod(Coded::ResolutionScope), cstr(), cstr()};
    case mdt::TypeDef:       return {c32(), cstr(), cstr(), ccod(Coded::TypeDefOrRef),
                                     crid(mdt::Field), crid(mdt::MethodDef)};
    case mdt::FieldPtr:      return {crid(mdt::Field)};
    case mdt::Field:         return {c16(), cstr(), cblob()};
    case mdt::MethodPtr:     return {crid(mdt::MethodDef)};
    case mdt::MethodDef:     return {c32(), c16(), c16(), cstr(), cblob(), crid(mdt::Param)};
    case mdt::ParamPtr:      return {crid(mdt::Param)};
    case mdt::Param:         return {c16(), c16(), cstr()};
    case mdt::InterfaceImpl: return {crid(mdt::TypeDef), ccod(Coded::TypeDefOrRef)};
    case mdt::MemberRef:     return {ccod(Coded::MemberRefParent), cstr(), cblob()};
    case mdt::Constant:      return {c16(), ccod(Coded::HasConstant), cblob()};
    case mdt::CustomAttribute: return {ccod(Coded::HasCustomAttribute),
                                       ccod(Coded::CustomAttributeType), cblob()};
    case mdt::FieldMarshal:  return {ccod(Coded::HasFieldMarshal), cblob()};
    case mdt::DeclSecurity:  return {c16(), ccod(Coded::HasDeclSecurity), cblob()};
    case mdt::ClassLayout:   return {c16(), c32(), crid(mdt::TypeDef)};
    case mdt::FieldLayout:   return {c32(), crid(mdt::Field)};
    case mdt::StandAloneSig: return {cblob()};
    case mdt::EventMap:      return {crid(mdt::TypeDef), crid(mdt::Event)};
    case mdt::EventPtr:      return {crid(mdt::Event)};
    case mdt::Event:         return {c16(), cstr(), ccod(Coded::TypeDefOrRef)};
    case mdt::PropertyMap:   return {crid(mdt::TypeDef), crid(mdt::Property)};
    case mdt::PropertyPtr:   return {crid(mdt::Property)};
    case mdt::Property:      return {c16(), cstr(), cblob()};
    case mdt::MethodSemantics: return {c16(), crid(mdt::MethodDef), ccod(Coded::HasSemantics)};
    case mdt::MethodImpl:    return {crid(mdt::TypeDef), ccod(Coded::MethodDefOrRef),
                                     ccod(Coded::MethodDefOrRef)};
    case mdt::ModuleRef:     return {cstr()};
    case mdt::TypeSpec:      return {cblob()};
    case mdt::ImplMap:       return {c16(), ccod(Coded::MemberForwarded), cstr(), crid(mdt::ModuleRef)};
    case mdt::FieldRVA:      return {c32(), crid(mdt::Field)};
    case mdt::EncLog:        return {c32(), c32()};
    case mdt::EncMap:        return {c32()};
    case mdt::Assembly:      return {c32(), c16(), c16(), c16(), c16(), c32(),
                                     cblob(), cstr(), cstr()};
    case mdt::AssemblyProcessor: return {c32()};
    case mdt::AssemblyOS:    return {c32(), c32(), c32()};
    case mdt::AssemblyRef:   return {c16(), c16(), c16(), c16(), c32(),
                                     cblob(), cstr(), cstr(), cblob()};
    case mdt::AssemblyRefProcessor: return {c32(), crid(mdt::AssemblyRef)};
    case mdt::AssemblyRefOS: return {c32(), c32(), c32(), crid(mdt::AssemblyRef)};
    case mdt::File:          return {c32(), cstr(), cblob()};
    case mdt::ExportedType:  return {c32(), c32(), cstr(), cstr(), ccod(Coded::Implementation)};
    case mdt::ManifestResource: return {c32(), c32(), cstr(), ccod(Coded::Implementation)};
    case mdt::NestedClass:   return {crid(mdt::TypeDef), crid(mdt::TypeDef)};
    case mdt::GenericParam:  return {c16(), c16(), ccod(Coded::TypeOrMethodDef), cstr()};
    case mdt::MethodSpec:    return {ccod(Coded::MethodDefOrRef), cblob()};
    case mdt::GenericParamConstraint: return {crid(mdt::GenericParam), ccod(Coded::TypeDefOrRef)};
    default:                 return {};
    }
}

// Coded-index descriptors: the tables each kind can point at (in tag order,
// 0xFF for reserved slots) and the number of tag bits.
struct CodedDesc { u8 tables[24]; u8 count; u8 bits; };

const CodedDesc& coded_desc(Coded k) {
    static const CodedDesc descs[] = {
        /*TypeDefOrRef*/    {{mdt::TypeDef, mdt::TypeRef, mdt::TypeSpec}, 3, 2},
        /*HasConstant*/     {{mdt::Field, mdt::Param, mdt::Property}, 3, 2},
        /*HasCustomAttribute*/ {{mdt::MethodDef, mdt::Field, mdt::TypeRef, mdt::TypeDef,
            mdt::Param, mdt::InterfaceImpl, mdt::MemberRef, mdt::Module, mdt::DeclSecurity,
            mdt::Property, mdt::Event, mdt::StandAloneSig, mdt::ModuleRef, mdt::TypeSpec,
            mdt::Assembly, mdt::AssemblyRef, mdt::File, mdt::ExportedType, mdt::ManifestResource,
            mdt::GenericParam, mdt::GenericParamConstraint, mdt::MethodSpec}, 22, 5},
        /*HasFieldMarshal*/ {{mdt::Field, mdt::Param}, 2, 1},
        /*HasDeclSecurity*/ {{mdt::TypeDef, mdt::MethodDef, mdt::Assembly}, 3, 2},
        /*MemberRefParent*/ {{mdt::TypeDef, mdt::TypeRef, mdt::ModuleRef, mdt::MethodDef,
            mdt::TypeSpec}, 5, 3},
        /*HasSemantics*/    {{mdt::Event, mdt::Property}, 2, 1},
        /*MethodDefOrRef*/  {{mdt::MethodDef, mdt::MemberRef}, 2, 1},
        /*MemberForwarded*/ {{mdt::Field, mdt::MethodDef}, 2, 1},
        /*Implementation*/  {{mdt::File, mdt::AssemblyRef, mdt::ExportedType}, 3, 2},
        /*CustomAttributeType*/ {{0xFF, 0xFF, mdt::MethodDef, mdt::MemberRef, 0xFF}, 5, 3},
        /*ResolutionScope*/ {{mdt::Module, mdt::ModuleRef, mdt::AssemblyRef, mdt::TypeRef}, 4, 2},
        /*TypeOrMethodDef*/ {{mdt::TypeDef, mdt::MethodDef}, 2, 1},
    };
    return descs[static_cast<u8>(k)];
}

// Read an ECMA-335 compressed unsigned integer (II.23.2). Advances p.
bool read_compressed(const u8*& p, const u8* end, u32& out) {
    if (p >= end) return false;
    u8 b0 = *p;
    if ((b0 & 0x80) == 0) { out = b0; p += 1; return true; }
    if ((b0 & 0xC0) == 0x80) {
        if (p + 2 > end) return false;
        out = (static_cast<u32>(b0 & 0x3F) << 8) | p[1];
        p += 2; return true;
    }
    if ((b0 & 0xE0) == 0xC0) {
        if (p + 4 > end) return false;
        out = (static_cast<u32>(b0 & 0x1F) << 24) | (static_cast<u32>(p[1]) << 16) |
              (static_cast<u32>(p[2]) << 8) | p[3];
        p += 4; return true;
    }
    return false;
}

const char* primitive_name(u8 et) {
    switch (et) {
    case ET_VOID:       return "void";
    case ET_BOOLEAN:    return "bool";
    case ET_CHAR:       return "char";
    case ET_I1:         return "sbyte";
    case ET_U1:         return "byte";
    case ET_I2:         return "short";
    case ET_U2:         return "ushort";
    case ET_I4:         return "int";
    case ET_U4:         return "uint";
    case ET_I8:         return "long";
    case ET_U8:         return "ulong";
    case ET_R4:         return "float";
    case ET_R8:         return "double";
    case ET_STRING:     return "string";
    case ET_OBJECT:     return "object";
    case ET_I:          return "IntPtr";
    case ET_U:          return "UIntPtr";
    case ET_TYPEDBYREF: return "TypedReference";
    default:            return nullptr;
    }
}

} // anon

// -------------------------------------------------------------------------

bool MetadataReader::init(const u8* root, size_t size) {
    valid_ = false;
    tables_.fill(TableInfo{});
    if (!root || size < 20) return false;

    u32 sig = 0;
    std::memcpy(&sig, root, 4);
    if (sig != 0x424A5342) return false;   // 'BSJB'

    if (!parse_streams(root, size)) return false;
    if (!parse_table_header()) return false;
    compute_layout();
    valid_ = true;
    return true;
}

bool MetadataReader::parse_streams(const u8* root, size_t size) {
    // Metadata root header: signature(4) major(2) minor(2) reserved(4)
    // version_len(4) version[..] flags(2) streams(2), then stream headers.
    u32 ver_len = 0;
    std::memcpy(&ver_len, root + 12, 4);
    if (ver_len > size) return false;
    size_t pos = 16 + ((static_cast<size_t>(ver_len) + 3) & ~size_t(3));
    if (pos + 4 > size) return false;

    version_.assign(reinterpret_cast<const char*>(root + 16),
                    strnlen(reinterpret_cast<const char*>(root + 16), ver_len));

    u16 num_streams = 0;
    std::memcpy(&num_streams, root + pos + 2, 2);
    pos += 4;

    for (u16 i = 0; i < num_streams && pos + 8 <= size; ++i) {
        u32 off = 0, sz = 0;
        std::memcpy(&off, root + pos, 4);
        std::memcpy(&sz, root + pos + 4, 4);
        pos += 8;

        const char* name = reinterpret_cast<const char*>(root + pos);
        size_t name_max = size - pos;
        size_t name_len = strnlen(name, name_max);
        pos += (name_len + 4) & ~size_t(3);     // NUL-terminated, padded to 4

        // Clamp the stream to the metadata region; a corrupt offset/size just
        // yields an empty heap rather than an out-of-bounds pointer.
        if (static_cast<size_t>(off) > size) continue;
        size_t avail = size - off;
        if (sz > avail) sz = static_cast<u32>(avail);
        const u8* data = root + off;

        if (name_len == 2 && (name[0] == '#') && (name[1] == '~')) {
            tables_stream_ = data; tables_stream_sz_ = sz;
        } else if (name_len == 2 && name[0] == '#' && name[1] == '-') {
            tables_stream_ = data; tables_stream_sz_ = sz;   // uncompressed variant
        } else if (std::strcmp(name, "#Strings") == 0) {
            strings_ = data; strings_sz_ = sz;
        } else if (std::strcmp(name, "#US") == 0) {
            us_ = data; us_sz_ = sz;
        } else if (std::strcmp(name, "#Blob") == 0) {
            blob_ = data; blob_sz_ = sz;
        } else if (std::strcmp(name, "#GUID") == 0) {
            guid_ = data; guid_sz_ = sz;
        }
    }
    return tables_stream_ != nullptr;
}

bool MetadataReader::parse_table_header() {
    const u8* t = tables_stream_;
    if (tables_stream_sz_ < 24) return false;

    heap_sizes_ = t[6];
    str_idx_  = (heap_sizes_ & 0x01) ? 4 : 2;
    guid_idx_ = (heap_sizes_ & 0x02) ? 4 : 2;
    blob_idx_ = (heap_sizes_ & 0x04) ? 4 : 2;

    std::memcpy(&valid_mask_, t + 8, 8);

    // Row counts follow the 24-byte fixed header, one u32 per present table.
    u32 present = 0;
    for (u32 i = 0; i < mdt::kCount; ++i)
        if (valid_mask_ & (1ULL << i)) ++present;

    size_t need = 24 + static_cast<size_t>(present) * 4;
    if (need > tables_stream_sz_) return false;

    const u8* rc = t + 24;
    u32 idx = 0;
    for (u32 i = 0; i < mdt::kCount; ++i) {
        if (valid_mask_ & (1ULL << i)) {
            u32 rows = 0;
            std::memcpy(&rows, rc + idx * 4, 4);
            tables_[i].rows = rows;
            ++idx;
        }
    }

    // Extra 4-byte value after the row counts when bit 0x40 is set.
    size_t data_start = need + ((heap_sizes_ & 0x40) ? 4 : 0);
    if (data_start > tables_stream_sz_) return false;

    // Stash the data start by pointing every present table's data at it for now;
    // compute_layout() re-walks and assigns exact per-table pointers.
    tables_data_start_ = data_start;
    return true;
}

u8 MetadataReader::heap_index_size(u8 which) const {
    return which == 0 ? str_idx_ : which == 1 ? guid_idx_ : blob_idx_;
}

u8 MetadataReader::rid_size(u32 table) const {
    return table_rows(table) >= (1u << 16) ? 4 : 2;
}

u8 MetadataReader::coded_size(Coded kind) const {
    const CodedDesc& d = coded_desc(kind);
    u32 max_rows = 0;
    for (u8 i = 0; i < d.count; ++i)
        if (d.tables[i] != 0xFF)
            max_rows = (std::max)(max_rows, table_rows(d.tables[i]));
    return max_rows < (1u << (16 - d.bits)) ? 2 : 4;
}

void MetadataReader::compute_layout() {
    // First pass: geometry (column offsets/widths, row size) for every table.
    for (u32 tbl = 0; tbl < mdt::kCount; ++tbl) {
        TableInfo& ti = tables_[tbl];
        if (ti.rows == 0) continue;
        auto cols = columns_for(tbl);
        u8 off = 0;
        ti.col_count = static_cast<u8>((std::min)(cols.size(), size_t(16)));
        for (u8 c = 0; c < ti.col_count; ++c) {
            u8 w = 2;
            switch (cols[c].kind) {
            case CK::U16:  w = 2; break;
            case CK::U32:  w = 4; break;
            case CK::Str:  w = heap_index_size(0); break;
            case CK::Guid: w = heap_index_size(1); break;
            case CK::Blob: w = heap_index_size(2); break;
            case CK::Rid:  w = rid_size(cols[c].arg); break;
            case CK::Cod:  w = coded_size(static_cast<Coded>(cols[c].arg)); break;
            }
            ti.col_off[c] = off;
            ti.col_size[c] = w;
            off = static_cast<u8>(off + w);
        }
        ti.row_size = off;
    }

    // Second pass: assign data pointers in table order; each table's rows follow
    // the previous present table's.
    size_t cursor = tables_data_start_;
    for (u32 tbl = 0; tbl < mdt::kCount; ++tbl) {
        TableInfo& ti = tables_[tbl];
        if (ti.rows == 0) continue;
        if (cursor <= tables_stream_sz_) ti.data = tables_stream_ + cursor;
        cursor += static_cast<size_t>(ti.rows) * ti.row_size;
    }

    // method_rid -> owning TypeDef, field_rid -> owning TypeDef. A TypeDef owns
    // the method/field rids from its list column up to the next TypeDef's.
    u32 type_rows = table_rows(mdt::TypeDef);
    u32 meth_rows = table_rows(mdt::MethodDef);
    u32 fld_rows  = table_rows(mdt::Field);
    method_owner_.assign(meth_rows + 2, 0);
    field_owner_.assign(fld_rows + 2, 0);
    for (u32 t = 1; t <= type_rows; ++t) {
        TypeDefRow cur = type_def(t);
        u32 m_end = (t < type_rows) ? type_def(t + 1).method_list : meth_rows + 1;
        u32 f_end = (t < type_rows) ? type_def(t + 1).field_list  : fld_rows + 1;
        for (u32 m = cur.method_list; m < m_end && m <= meth_rows; ++m) method_owner_[m] = t;
        for (u32 f = cur.field_list;  f < f_end && f <= fld_rows;  ++f) field_owner_[f] = t;
    }

    // property_rid / event_rid -> owning TypeDef, via the PropertyMap / EventMap
    // ranges (each map row names a TypeDef and the first property/event it owns;
    // the run ends where the next map row begins).
    u32 prop_rows  = table_rows(mdt::Property);
    u32 event_rows = table_rows(mdt::Event);
    property_owner_.assign(prop_rows + 2, 0);
    event_owner_.assign(event_rows + 2, 0);
    u32 pmap_rows = table_rows(mdt::PropertyMap);
    for (u32 i = 1; i <= pmap_rows; ++i) {
        u32 parent = read_col(mdt::PropertyMap, i, 0);
        u32 start  = read_col(mdt::PropertyMap, i, 1);
        u32 end    = (i < pmap_rows) ? read_col(mdt::PropertyMap, i + 1, 1) : prop_rows + 1;
        for (u32 p = start; p < end && p <= prop_rows; ++p) property_owner_[p] = parent;
    }
    u32 emap_rows = table_rows(mdt::EventMap);
    for (u32 i = 1; i <= emap_rows; ++i) {
        u32 parent = read_col(mdt::EventMap, i, 0);
        u32 start  = read_col(mdt::EventMap, i, 1);
        u32 end    = (i < emap_rows) ? read_col(mdt::EventMap, i + 1, 1) : event_rows + 1;
        for (u32 e = start; e < end && e <= event_rows; ++e) event_owner_[e] = parent;
    }

    // nested type -> enclosing type, straight from the NestedClass table.
    nested_enclosing_.assign(type_rows + 2, 0);
    u32 nest_rows = table_rows(mdt::NestedClass);
    for (u32 i = 1; i <= nest_rows; ++i) {
        u32 nested = read_col(mdt::NestedClass, i, 0);
        u32 encl   = read_col(mdt::NestedClass, i, 1);
        if (nested >= 1 && nested <= type_rows) nested_enclosing_[nested] = encl;
    }

    // Constant table: index by decoded parent so a Field/Property/Param default
    // is one map lookup rather than a per-member linear scan.
    constant_index_.clear();
    u32 const_rows = table_rows(mdt::Constant);
    for (u32 i = 1; i <= const_rows; ++i) {
        TokenRef parent = decode_coded(Coded::HasConstant, read_col(mdt::Constant, i, 1));
        if (parent.table == 0xFFFFFFFF || parent.rid == 0) continue;
        constant_index_[(parent.table << 24) | (parent.rid & 0x00FFFFFF)] = i;
    }
}

u32 MetadataReader::read_col(u32 table, u32 rid, u32 col) const {
    if (table >= mdt::kCount) return 0;
    const TableInfo& t = tables_[table];
    if (rid == 0 || rid > t.rows || col >= t.col_count || !t.data) return 0;
    const u8* p = t.data + static_cast<size_t>(rid - 1) * t.row_size + t.col_off[col];
    u8 w = t.col_size[col];
    if (p < tables_stream_ || p + w > tables_stream_ + tables_stream_sz_) return 0;
    if (w == 2) { u16 v = 0; std::memcpy(&v, p, 2); return v; }
    u32 v = 0; std::memcpy(&v, p, 4); return v;
}

MetadataReader::TokenRef MetadataReader::decode_coded(Coded kind, u32 value) const {
    const CodedDesc& d = coded_desc(kind);
    u32 mask = (1u << d.bits) - 1;
    u32 tag = value & mask;
    u32 rid = value >> d.bits;
    if (tag >= d.count || d.tables[tag] == 0xFF) return {0xFFFFFFFF, rid};
    return {d.tables[tag], rid};
}

// ---- Typed rows ---------------------------------------------------------

MetadataReader::TypeDefRow MetadataReader::type_def(u32 rid) const {
    return {read_col(mdt::TypeDef, rid, 0), read_col(mdt::TypeDef, rid, 1),
            read_col(mdt::TypeDef, rid, 2), read_col(mdt::TypeDef, rid, 3),
            read_col(mdt::TypeDef, rid, 4), read_col(mdt::TypeDef, rid, 5)};
}

MetadataReader::MethodDefRow MetadataReader::method_def(u32 rid) const {
    return {read_col(mdt::MethodDef, rid, 0),
            static_cast<u16>(read_col(mdt::MethodDef, rid, 1)),
            static_cast<u16>(read_col(mdt::MethodDef, rid, 2)),
            read_col(mdt::MethodDef, rid, 3), read_col(mdt::MethodDef, rid, 4),
            read_col(mdt::MethodDef, rid, 5)};
}

MetadataReader::FieldRow MetadataReader::field(u32 rid) const {
    return {static_cast<u16>(read_col(mdt::Field, rid, 0)),
            read_col(mdt::Field, rid, 1), read_col(mdt::Field, rid, 2)};
}

MetadataReader::ParamRow MetadataReader::param(u32 rid) const {
    return {static_cast<u16>(read_col(mdt::Param, rid, 0)),
            static_cast<u16>(read_col(mdt::Param, rid, 1)),
            read_col(mdt::Param, rid, 2)};
}

MetadataReader::PropertyRow MetadataReader::property(u32 rid) const {
    return {static_cast<u16>(read_col(mdt::Property, rid, 0)),
            read_col(mdt::Property, rid, 1), read_col(mdt::Property, rid, 2)};
}

MetadataReader::EventRow MetadataReader::event_row(u32 rid) const {
    return {static_cast<u16>(read_col(mdt::Event, rid, 0)),
            read_col(mdt::Event, rid, 1), read_col(mdt::Event, rid, 2)};
}

MetadataReader::SemanticsRow MetadataReader::method_semantics(u32 rid) const {
    return {static_cast<u16>(read_col(mdt::MethodSemantics, rid, 0)),
            read_col(mdt::MethodSemantics, rid, 1),
            read_col(mdt::MethodSemantics, rid, 2)};
}

MetadataReader::IfaceImplRow MetadataReader::iface_impl(u32 rid) const {
    return {read_col(mdt::InterfaceImpl, rid, 0),
            read_col(mdt::InterfaceImpl, rid, 1)};
}

MetadataReader::NestedRow MetadataReader::nested_class(u32 rid) const {
    return {read_col(mdt::NestedClass, rid, 0),
            read_col(mdt::NestedClass, rid, 1)};
}

MetadataReader::CustomAttrRow MetadataReader::custom_attribute(u32 rid) const {
    return {read_col(mdt::CustomAttribute, rid, 0),
            read_col(mdt::CustomAttribute, rid, 1)};
}

std::string MetadataReader::assembly_name() const {
    // Assembly columns: HashAlgId,Major,Minor,Build,Rev,Flags,PublicKey,Name(7),Culture.
    if (!has_table(mdt::Assembly)) return {};
    return string_at(read_col(mdt::Assembly, 1, 7));
}

u32 MetadataReader::method_decl_type(u32 method_rid) const {
    return method_rid < method_owner_.size() ? method_owner_[method_rid] : 0;
}

u32 MetadataReader::field_decl_type(u32 field_rid) const {
    return field_rid < field_owner_.size() ? field_owner_[field_rid] : 0;
}

u32 MetadataReader::property_decl_type(u32 property_rid) const {
    return property_rid < property_owner_.size() ? property_owner_[property_rid] : 0;
}

u32 MetadataReader::event_decl_type(u32 event_rid) const {
    return event_rid < event_owner_.size() ? event_owner_[event_rid] : 0;
}

u32 MetadataReader::nested_enclosing(u32 type_rid) const {
    return type_rid < nested_enclosing_.size() ? nested_enclosing_[type_rid] : 0;
}

// ---- Heaps --------------------------------------------------------------

std::string MetadataReader::string_at(u32 off) const {
    if (!strings_ || off >= strings_sz_) return {};
    const char* s = reinterpret_cast<const char*>(strings_ + off);
    size_t len = strnlen(s, strings_sz_ - off);
    return std::string(s, len);
}

std::string MetadataReader::user_string_at(u32 off) const {
    if (!us_ || off >= us_sz_) return {};
    const u8* p = us_ + off;
    const u8* end = us_ + us_sz_;
    u32 len = 0;
    if (!read_compressed(p, end, len) || len == 0) return {};
    if (p + len > end) len = static_cast<u32>(end - p);
    // The blob is UTF-16LE char data plus a trailing 1-byte flag.
    u32 char_bytes = (len > 0) ? len - 1 : 0;
    std::string out;
    out.reserve(char_bytes / 2);
    for (u32 i = 0; i + 1 < char_bytes; i += 2) {
        char16_t ch = static_cast<char16_t>(p[i] | (p[i + 1] << 8));
        if (ch == 0) { out += "\\0"; }
        else if (ch == '\n') { out += "\\n"; }
        else if (ch == '\r') { out += "\\r"; }
        else if (ch == '\t') { out += "\\t"; }
        else if (ch == '"')  { out += "\\\""; }
        else if (ch >= 0x20 && ch < 0x7F) { out += static_cast<char>(ch); }
        else { out += fmt::format("\\u{:04x}", static_cast<u32>(ch)); }
    }
    return out;
}

const u8* MetadataReader::blob_at(u32 off, u32& len) const {
    len = 0;
    if (!blob_ || off >= blob_sz_) return nullptr;
    const u8* p = blob_ + off;
    const u8* end = blob_ + blob_sz_;
    u32 l = 0;
    if (!read_compressed(p, end, l)) return nullptr;
    if (p + l > end) l = static_cast<u32>(end - p);
    len = l;
    return p;
}

// ---- Name resolution ----------------------------------------------------

namespace {
// Guard against pathological nested-type cycles.
constexpr int kMaxNestDepth = 16;
}

std::string MetadataReader::type_name(u32 token) const {
    u32 table = token >> 24;
    u32 rid = token & 0x00FFFFFF;
    if (rid == 0) return "";
    switch (table) {
    case mdt::TypeDef: {
        // Nested types resolve their enclosing type via the NestedClass table.
        u32 enclosing = 0;
        u32 nrows = table_rows(mdt::NestedClass);
        for (u32 i = 1; i <= nrows; ++i) {
            if (read_col(mdt::NestedClass, i, 0) == rid) {
                enclosing = read_col(mdt::NestedClass, i, 1);
                break;
            }
        }
        TypeDefRow td = type_def(rid);
        std::string name = string_at(td.name);
        std::string ns = string_at(td.ns);
        std::string self = ns.empty() ? name : ns + "." + name;
        int depth = 0;
        while (enclosing && depth++ < kMaxNestDepth) {
            TypeDefRow et = type_def(enclosing);
            std::string en = string_at(et.name);
            std::string ens = string_at(et.ns);
            self = (ens.empty() ? en : ens + "." + en) + "/" + self;
            u32 next = 0;
            for (u32 i = 1; i <= nrows; ++i) {
                if (read_col(mdt::NestedClass, i, 0) == enclosing) {
                    next = read_col(mdt::NestedClass, i, 1);
                    break;
                }
            }
            enclosing = next;
        }
        return self;
    }
    case mdt::TypeRef: {
        u32 rs = read_col(mdt::TypeRef, rid, 0);
        std::string name = string_at(read_col(mdt::TypeRef, rid, 1));
        std::string ns = string_at(read_col(mdt::TypeRef, rid, 2));
        std::string self = ns.empty() ? name : ns + "." + name;
        // A TypeRef whose scope is another TypeRef is a nested type.
        TokenRef scope = decode_coded(Coded::ResolutionScope, rs);
        if (scope.table == mdt::TypeRef && scope.rid) {
            std::string outer = type_name((mdt::TypeRef << 24) | scope.rid);
            if (!outer.empty()) self = outer + "/" + self;
        }
        return self;
    }
    case mdt::TypeSpec: {
        u32 len = 0;
        const u8* p = blob_at(read_col(mdt::TypeSpec, rid, 0), len);
        if (!p) return fmt::format("TypeSpec[{:X}]", rid);
        const u8* end = p + len;
        return read_type(p, end);
    }
    default:
        return fmt::format("<0x{:08X}>", token);
    }
}

std::string MetadataReader::method_name(u32 token) const {
    u32 table = token >> 24;
    u32 rid = token & 0x00FFFFFF;
    if (rid == 0) return "";
    switch (table) {
    case mdt::MethodDef: {
        u32 owner = method_decl_type(rid);
        std::string tn = owner ? type_name((mdt::TypeDef << 24) | owner) : std::string();
        std::string mn = string_at(method_def(rid).name);
        return tn.empty() ? mn : tn + "::" + mn;
    }
    case mdt::MemberRef: {
        std::string parent;
        TokenRef p = decode_coded(Coded::MemberRefParent, read_col(mdt::MemberRef, rid, 0));
        switch (p.table) {
        case mdt::TypeDef:  parent = type_name((mdt::TypeDef << 24) | p.rid); break;
        case mdt::TypeRef:  parent = type_name((mdt::TypeRef << 24) | p.rid); break;
        case mdt::TypeSpec: parent = type_name((mdt::TypeSpec << 24) | p.rid); break;
        case mdt::ModuleRef: parent = string_at(read_col(mdt::ModuleRef, p.rid, 0)); break;
        case mdt::MethodDef: {
            u32 owner = method_decl_type(p.rid);
            parent = owner ? type_name((mdt::TypeDef << 24) | owner) : std::string();
            break;
        }
        default: break;
        }
        std::string mn = string_at(read_col(mdt::MemberRef, rid, 1));
        return parent.empty() ? mn : parent + "::" + mn;
    }
    case mdt::MethodSpec: {
        TokenRef m = decode_coded(Coded::MethodDefOrRef, read_col(mdt::MethodSpec, rid, 0));
        u32 base_tok = (m.table == mdt::MethodDef) ? ((mdt::MethodDef << 24) | m.rid)
                                                   : ((mdt::MemberRef << 24) | m.rid);
        std::string base = method_name(base_tok);
        // Append the generic instantiation from the blob (GENERICINST count types).
        u32 len = 0;
        const u8* p = blob_at(read_col(mdt::MethodSpec, rid, 1), len);
        if (p && len) {
            const u8* end = p + len;
            if (p < end && *p == SIG_GENERICINST) ++p;
            u32 argc = 0;
            if (read_compressed(p, end, argc) && argc && argc < 64) {
                std::string args;
                for (u32 i = 0; i < argc; ++i) {
                    if (i) args += ",";
                    args += read_type(p, end);
                }
                base += "<" + args + ">";
            }
        }
        return base;
    }
    default:
        return fmt::format("<0x{:08X}>", token);
    }
}

std::string MetadataReader::field_name(u32 token) const {
    u32 table = token >> 24;
    u32 rid = token & 0x00FFFFFF;
    if (rid == 0) return "";
    if (table == mdt::Field) {
        u32 owner = field_decl_type(rid);
        std::string tn = owner ? type_name((mdt::TypeDef << 24) | owner) : std::string();
        std::string fn = string_at(field(rid).name);
        return tn.empty() ? fn : tn + "::" + fn;
    }
    if (table == mdt::MemberRef) return method_name(token);   // same Class::Name shape
    return fmt::format("<0x{:08X}>", token);
}

std::string MetadataReader::token_name(u32 token) const {
    u32 table = token >> 24;
    switch (table) {
    case mdt::TypeDef: case mdt::TypeRef: case mdt::TypeSpec:
        return type_name(token);
    case mdt::MethodDef: case mdt::MethodSpec:
        return method_name(token);
    case mdt::Field:
        return field_name(token);
    case mdt::MemberRef:
        return method_name(token);
    default:
        return fmt::format("<0x{:08X}>", token);
    }
}

// ---- Signatures ---------------------------------------------------------

std::string MetadataReader::read_type(const u8*& p, const u8* end) const {
    if (p >= end) return "?";
    u8 et = *p++;

    // Skip custom modifiers, keep the underlying type.
    while (et == ET_CMOD_REQD || et == ET_CMOD_OPT) {
        u32 tok = 0;
        read_compressed(p, end, tok);
        if (p >= end) return "?";
        et = *p++;
    }

    if (const char* prim = primitive_name(et)) return prim;

    switch (et) {
    case ET_PINNED: {
        return read_type(p, end) + " pinned";
    }
    case ET_BYREF: {
        return read_type(p, end) + "&";
    }
    case ET_PTR: {
        return read_type(p, end) + "*";
    }
    case ET_SZARRAY: {
        return read_type(p, end) + "[]";
    }
    case ET_ARRAY: {
        std::string elem = read_type(p, end);
        u32 rank = 0;
        read_compressed(p, end, rank);
        u32 num_sizes = 0;
        read_compressed(p, end, num_sizes);
        for (u32 i = 0; i < num_sizes; ++i) { u32 s = 0; read_compressed(p, end, s); }
        u32 num_lo = 0;
        read_compressed(p, end, num_lo);
        for (u32 i = 0; i < num_lo; ++i) { u32 s = 0; read_compressed(p, end, s); }
        std::string dims(rank ? rank - 1 : 0, ',');
        return elem + "[" + dims + "]";
    }
    case ET_VALUETYPE:
    case ET_CLASS: {
        u32 coded = 0;
        read_compressed(p, end, coded);
        TokenRef r = decode_coded(Coded::TypeDefOrRef, coded);
        u32 tok = (r.table << 24) | r.rid;
        return type_name(tok);
    }
    case ET_GENERICINST: {
        std::string base = read_type(p, end);   // CLASS/VALUETYPE + token
        u32 argc = 0;
        read_compressed(p, end, argc);
        std::string args;
        for (u32 i = 0; i < argc && i < 64; ++i) {
            if (i) args += ",";
            args += read_type(p, end);
        }
        // Strip the CLR arity marker (`Name`1) for a cleaner C#-style rendering.
        auto tick = base.rfind('`');
        if (tick != std::string::npos) base.erase(tick);
        return base + "<" + args + ">";
    }
    case ET_VAR: {
        u32 n = 0; read_compressed(p, end, n);
        return fmt::format("!{}", n);
    }
    case ET_MVAR: {
        u32 n = 0; read_compressed(p, end, n);
        return fmt::format("!!{}", n);
    }
    case ET_FNPTR: {
        // Skip the embedded method signature; render as a function pointer.
        // Best-effort: consume calling conv + param count + (params+1) types.
        if (p < end) ++p;                        // calling convention
        u32 pc = 0; read_compressed(p, end, pc);
        for (u32 i = 0; i <= pc && i < 256; ++i) read_type(p, end);
        return "method*";
    }
    case ET_OBJECT: return "object";
    case ET_VOID:   return "void";
    default:
        return fmt::format("type(0x{:02X})", et);
    }
}

MetadataReader::MethodSig MetadataReader::parse_method_sig(u32 blob_off) const {
    MethodSig sig;
    u32 len = 0;
    const u8* p = blob_at(blob_off, len);
    if (!p || len == 0) return sig;
    const u8* end = p + len;

    u8 cc = *p++;
    sig.has_this = (cc & SIG_HASTHIS) != 0;
    sig.vararg = (cc & 0x0F) == SIG_VARARG;
    if (cc & SIG_GENERIC) read_compressed(p, end, sig.gen_params);

    u32 param_count = 0;
    read_compressed(p, end, param_count);
    sig.ret = read_type(p, end);
    for (u32 i = 0; i < param_count && i < 4096; ++i) {
        if (p < end && *p == ET_SENTINEL) { ++p; }   // vararg sentinel
        sig.params.push_back(read_type(p, end));
    }
    return sig;
}

std::vector<std::string> MetadataReader::parse_local_sig(u32 standalone_sig_token) const {
    std::vector<std::string> locals;
    u32 rid = standalone_sig_token & 0x00FFFFFF;
    if ((standalone_sig_token >> 24) != mdt::StandAloneSig || rid == 0) return locals;
    u32 len = 0;
    const u8* p = blob_at(read_col(mdt::StandAloneSig, rid, 0), len);
    if (!p || len == 0) return locals;
    const u8* end = p + len;

    u8 cc = *p++;
    if (cc != SIG_LOCAL) return locals;   // must be a LOCAL_SIG
    u32 count = 0;
    read_compressed(p, end, count);
    for (u32 i = 0; i < count && i < 65536; ++i)
        locals.push_back(read_type(p, end));
    return locals;
}

std::string MetadataReader::field_type(u32 blob_off) const {
    u32 len = 0;
    const u8* p = blob_at(blob_off, len);
    if (!p || len == 0) return "?";
    const u8* end = p + len;
    if (p < end && *p == SIG_FIELD) ++p;   // FIELD calling convention
    return read_type(p, end);
}

std::string MetadataReader::property_type(u32 blob_off) const {
    // PROPERTY sig: cc(0x08 [|0x20 HASTHIS]) paramCount RetType Param*  (II.23.2.5)
    u32 len = 0;
    const u8* p = blob_at(blob_off, len);
    if (!p || len == 0) return "?";
    const u8* end = p + len;
    if (p < end) ++p;                       // calling convention byte
    u32 pc = 0; read_compressed(p, end, pc);
    return read_type(p, end);               // the property's own type
}

std::string MetadataReader::constant_for(u32 parent_table, u32 parent_rid) const {
    auto it = constant_index_.find((parent_table << 24) | (parent_rid & 0x00FFFFFF));
    if (it == constant_index_.end()) return {};
    u32 crid = it->second;
    u8 et = static_cast<u8>(read_col(mdt::Constant, crid, 0) & 0xFF);
    u32 len = 0;
    const u8* p = blob_at(read_col(mdt::Constant, crid, 2), len);
    if (!p) return (et == ET_CLASS) ? "null" : std::string();
    const u8* e = p + len;

    auto rd_u = [&](int n) -> u64 {
        u64 v = 0;
        for (int i = 0; i < n && p < e; ++i) v |= static_cast<u64>(*p++) << (8 * i);
        return v;
    };
    switch (et) {
    case ET_BOOLEAN: return (len && p[0]) ? "true" : "false";
    case ET_CHAR: {
        u16 c = static_cast<u16>(rd_u(2));
        if (c >= 0x20 && c < 0x7F && c != '\'' && c != '\\')
            return fmt::format("'{}'", static_cast<char>(c));
        return fmt::format("'\\u{:04x}'", c);
    }
    case ET_I1: return fmt::format("{}", static_cast<i8>(rd_u(1)));
    case ET_U1: return fmt::format("{}", static_cast<u8>(rd_u(1)));
    case ET_I2: return fmt::format("{}", static_cast<i16>(rd_u(2)));
    case ET_U2: return fmt::format("{}", static_cast<u16>(rd_u(2)));
    case ET_I4: return fmt::format("{}", static_cast<i32>(rd_u(4)));
    case ET_U4: return fmt::format("{}", static_cast<u32>(rd_u(4)));
    case ET_I8: return fmt::format("{}", static_cast<i64>(rd_u(8)));
    case ET_U8: return fmt::format("{}", static_cast<u64>(rd_u(8)));
    case ET_R4: { u32 r = static_cast<u32>(rd_u(4)); float f; std::memcpy(&f, &r, 4); return fmt::format("{}f", f); }
    case ET_R8: { u64 r = rd_u(8); double d; std::memcpy(&d, &r, 8); return fmt::format("{}", d); }
    case ET_STRING: {
        std::string out = "\"";
        for (u32 i = 0; i + 1 < len; i += 2) {
            char16_t ch = static_cast<char16_t>(p[i] | (p[i + 1] << 8));
            if (ch == '"') out += "\\\"";
            else if (ch == '\\') out += "\\\\";
            else if (ch == '\n') out += "\\n";
            else if (ch == '\r') out += "\\r";
            else if (ch == '\t') out += "\\t";
            else if (ch >= 0x20 && ch < 0x7F) out += static_cast<char>(ch);
            else out += fmt::format("\\u{:04x}", static_cast<u32>(ch));
        }
        return out + "\"";
    }
    case ET_CLASS: return "null";
    default: return {};
    }
}

MetadataReader::CallInfo MetadataReader::call_info(u32 token) const {
    CallInfo ci;
    u32 table = token >> 24;
    u32 rid   = token & 0x00FFFFFF;
    if (rid == 0) return ci;

    auto from_sig = [&](u32 sig_blob) {
        MethodSig s = parse_method_sig(sig_blob);
        ci.arg_count    = static_cast<u32>(s.params.size());
        ci.has_this     = s.has_this;
        ci.returns_void = s.ret.empty() || s.ret == "void";
    };

    switch (table) {
    case mdt::MethodDef: {
        MethodDefRow mr = method_def(rid);
        from_sig(mr.sig);
        ci.simple_name = string_at(mr.name);
        u32 owner = method_decl_type(rid);
        ci.decl_type = owner ? type_name((mdt::TypeDef << 24) | owner) : std::string();
        break;
    }
    case mdt::MemberRef: {
        from_sig(read_col(mdt::MemberRef, rid, 2));
        ci.simple_name = string_at(read_col(mdt::MemberRef, rid, 1));
        TokenRef pr = decode_coded(Coded::MemberRefParent, read_col(mdt::MemberRef, rid, 0));
        switch (pr.table) {
        case mdt::TypeDef:  ci.decl_type = type_name((mdt::TypeDef << 24) | pr.rid); break;
        case mdt::TypeRef:  ci.decl_type = type_name((mdt::TypeRef << 24) | pr.rid); break;
        case mdt::TypeSpec: ci.decl_type = type_name((mdt::TypeSpec << 24) | pr.rid); break;
        case mdt::ModuleRef: ci.decl_type = string_at(read_col(mdt::ModuleRef, pr.rid, 0)); break;
        default: break;
        }
        break;
    }
    case mdt::MethodSpec: {
        TokenRef m = decode_coded(Coded::MethodDefOrRef, read_col(mdt::MethodSpec, rid, 0));
        u32 base_tok = (m.table == mdt::MethodDef) ? ((mdt::MethodDef << 24) | m.rid)
                                                   : ((mdt::MemberRef << 24) | m.rid);
        return call_info(base_tok);
    }
    default: break;
    }
    return ci;
}

}
