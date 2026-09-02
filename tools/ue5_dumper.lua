-- ============================================================================
-- ue5_dumper.lua
-- reverse-slop Lua SDK dumper for Unreal Engine 5.x targets
--
-- Runs against an attached target via slop.mem.read_hex through the kernel
-- backend. Emits a Dumpspace-style JSON per class (ClassesInfo/StructsInfo/
-- EnumsInfo/FunctionsInfo) plus a flat FNames.txt.
--
-- Usage: fill GObjects_VA and GNames_VA below (find via aob or xref), then
-- run via mcp__reverse-slop__script action=run with a big timeout_ms.
--
-- Tested layout: UE 5.3.x (The Finals / Marvel Rivals / Fortnite build family)
-- ============================================================================

-- ==== CONFIG ================================================================
local GObjects_VA   = 0x0    -- FUObjectArray base (in target .data)
local GNames_VA     = 0x0    -- FNamePool base (in target .data)
local OUTPUT_DIR    = [[C:\Dumper-slop\Discovery-d]]
local MAX_OBJECTS   = 400000 -- hard cap to protect the walk
local VERBOSE       = false

-- ==== UE 5.x LAYOUT CONSTANTS ==============================================
-- FUObjectArray (UE 5.3.x)
local UOA_OBJOBJECTS_OFFSET   = 0x10   -- ObjObjects: FChunkedFixedUObjectArray
-- FChunkedFixedUObjectArray
local CFA_OBJECTS_OFFSET      = 0x00   -- Objects: FUObjectItem**
local CFA_MAXELEMENTS_OFFSET  = 0x14   -- MaxElements
local CFA_NUMELEMENTS_OFFSET  = 0x18   -- NumElements
local CFA_MAXCHUNKS_OFFSET    = 0x1C   -- MaxChunks
local CFA_NUMCHUNKS_OFFSET    = 0x20   -- NumChunks
local ELEMENTS_PER_CHUNK      = 64 * 1024 -- 65536
-- FUObjectItem (24 bytes on x64)
local UOI_SIZE                = 24
local UOI_OBJECT_OFFSET       = 0x00   -- UObject*
local UOI_FLAGS_OFFSET        = 0x08
local UOI_CLUSTER_OFFSET      = 0x0C
local UOI_SERIAL_OFFSET       = 0x10

-- UObject layout (UE 5.x, no editor)
local UO_VTABLE_OFFSET        = 0x00
local UO_OBJECTFLAGS_OFFSET   = 0x08
local UO_INTERNALINDEX_OFFSET = 0x0C
local UO_CLASSPRIVATE_OFFSET  = 0x10
local UO_NAMEPRIVATE_OFFSET   = 0x18   -- FName (8 bytes: ComparisonIndex + Number)
local UO_OUTERPRIVATE_OFFSET  = 0x20

-- UStruct layout (extends UObject)
local US_SUPERSTRUCT_OFFSET   = 0x40   -- UStruct*
local US_CHILDREN_OFFSET      = 0x48   -- UField* (only functions in UE5.3)
local US_CHILDPROPS_OFFSET    = 0x50   -- FField* (all FProperties)
local US_PROPERTIES_SIZE_OFF  = 0x58   -- int32 PropertiesSize
local US_MIN_ALIGN_OFFSET     = 0x5C   -- int32 MinAlignment

-- UFunction extra fields (extends UStruct)
local UFN_FUNCTIONFLAGS_OFFSET = 0xB0  -- EFunctionFlags (varies by build)

-- FField (UE 5.x FProperty base)
local FF_VTABLE_OFFSET        = 0x00
local FF_CLASSPRIVATE_OFFSET  = 0x08   -- FFieldClass*
local FF_NEXT_OFFSET          = 0x20   -- FField* (linked list of fields)
local FF_NAMEPRIVATE_OFFSET   = 0x28   -- FName

-- FProperty (extends FField)
local FP_ARRAYDIM_OFFSET      = 0x38
local FP_ELEMENTSIZE_OFFSET   = 0x3C
local FP_OFFSET_OFFSET        = 0x4C   -- int32 Offset_Internal
local FP_PROPERTYFLAGS_OFFSET = 0x40   -- EPropertyFlags (uint64)

-- FName (UE 5.x): { uint32 ComparisonIndex; uint32 Number; } == 8 bytes
-- FNamePool block resolution:
--   PoolAlignment = 2 (bytes) → block_index = idx >> 16, byte_offset = (idx & 0xFFFF) * 2
--   Blocks[block_index] + byte_offset → FNameEntry
-- FNameEntry: uint16 header, then string bytes
--   header layout: bit 0 = bIsWide, next 5 = LowercaseProbeHash, next 10 = Len

-- FNamePool layout (UE 5.3.x default: 0x10 header + blocks array)
local NP_HEADER_SIZE          = 0x10
local NP_BLOCKS_OFFSET        = NP_HEADER_SIZE
local NP_STRIDE_SHIFT         = 1     -- entries are 2-byte aligned within a block
local NP_BLOCK_SIZE_BYTES     = 128 * 1024 -- 128KB per block (2^16 * 2)

-- ==== MEMORY HELPERS ========================================================
local function bswap_le4(hex)
  -- hex is 8 chars little-endian, return integer
  local b0 = tonumber(hex:sub(1,2), 16) or 0
  local b1 = tonumber(hex:sub(3,4), 16) or 0
  local b2 = tonumber(hex:sub(5,6), 16) or 0
  local b3 = tonumber(hex:sub(7,8), 16) or 0
  return b0 + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000
end

local function bswap_le8(hex)
  local lo = bswap_le4(hex:sub(1,8))
  local hi = bswap_le4(hex:sub(9,16))
  return lo + hi * 0x100000000
end

local function bswap_le2(hex)
  return (tonumber(hex:sub(1,2), 16) or 0) + (tonumber(hex:sub(3,4), 16) or 0) * 0x100
end

local read_cache = {}
local function read_hex_cached(addr, len)
  local key = string.format("%X_%d", addr, len)
  if read_cache[key] then return read_cache[key] end
  local h = slop.mem.read_hex(addr, len)
  if h then read_cache[key] = h end
  return h
end

local function read_u64(addr)
  local h = read_hex_cached(addr, 8); if not h then return 0 end
  return bswap_le8(h)
end
local function read_u32(addr)
  local h = read_hex_cached(addr, 4); if not h then return 0 end
  return bswap_le4(h)
end
local function read_u16(addr)
  local h = read_hex_cached(addr, 2); if not h then return 0 end
  return bswap_le2(h)
end
local function read_cstr(addr, maxlen)
  maxlen = maxlen or 256
  local h = slop.mem.read_hex(addr, maxlen); if not h then return "" end
  local out = {}
  for i = 1, #h, 2 do
    local b = tonumber(h:sub(i, i+1), 16); if not b or b == 0 then break end
    out[#out+1] = string.char(b)
  end
  return table.concat(out)
end

-- ==== FNAME RESOLUTION ======================================================
local fname_cache = {}
local function fname_string(comparison_index)
  if fname_cache[comparison_index] then return fname_cache[comparison_index] end
  if comparison_index == 0 then return "None" end

  local block_idx = comparison_index >> 16
  local byte_off  = (comparison_index & 0xFFFF) << NP_STRIDE_SHIFT
  local block_ptr_va = GNames_VA + NP_BLOCKS_OFFSET + block_idx * 8
  local block_base = read_u64(block_ptr_va)
  if block_base == 0 then
    local s = string.format("<bad_block_%d>", block_idx)
    fname_cache[comparison_index] = s
    return s
  end
  local entry_va = block_base + byte_off
  local header = read_u16(entry_va)
  local is_wide = header & 0x1
  local len = header >> 6
  if len == 0 or len > 1024 then
    local s = string.format("<bad_entry_len_%d>", len)
    fname_cache[comparison_index] = s
    return s
  end

  local s
  if is_wide == 0 then
    s = read_cstr(entry_va + 2, len)
  else
    local h = slop.mem.read_hex(entry_va + 2, len * 2)
    local out = {}
    for i = 1, #h, 4 do
      local lo = tonumber(h:sub(i, i+1), 16) or 0
      out[#out+1] = string.char(lo)
    end
    s = table.concat(out) .. " [W]"
  end
  fname_cache[comparison_index] = s
  return s
end

local function fname_of(name_priv_va)
  local comp = read_u32(name_priv_va)
  local num  = read_u32(name_priv_va + 4)
  local s = fname_string(comp)
  if num > 0 then return s .. "_" .. tostring(num - 1) end
  return s
end

-- ==== FUOBJECTARRAY WALKER ==================================================
local function get_object_by_index(chunks_ptr, idx)
  local chunk_idx = idx // ELEMENTS_PER_CHUNK
  local within    = idx % ELEMENTS_PER_CHUNK
  local chunk_ptr = read_u64(chunks_ptr + chunk_idx * 8)
  if chunk_ptr == 0 then return 0 end
  local item_va = chunk_ptr + within * UOI_SIZE
  return read_u64(item_va + UOI_OBJECT_OFFSET), item_va
end

local function walk_objects()
  local obj_obj_va = GObjects_VA + UOA_OBJOBJECTS_OFFSET
  local chunks_ptr = read_u64(obj_obj_va + CFA_OBJECTS_OFFSET)
  local num_elems  = read_u32(obj_obj_va + CFA_NUMELEMENTS_OFFSET)
  local num_chunks = read_u32(obj_obj_va + CFA_NUMCHUNKS_OFFSET)
  print(string.format("[GObjects] Chunks=0x%X NumElems=%d NumChunks=%d",
                       chunks_ptr, num_elems, num_chunks))
  if num_elems > MAX_OBJECTS then num_elems = MAX_OBJECTS end

  local by_index = {}       -- idx -> {va, class_va, name, outer_idx}
  for i = 0, num_elems - 1 do
    local uobj_va = get_object_by_index(chunks_ptr, i)
    if uobj_va ~= 0 then
      local class_va = read_u64(uobj_va + UO_CLASSPRIVATE_OFFSET)
      local outer_va = read_u64(uobj_va + UO_OUTERPRIVATE_OFFSET)
      local name     = fname_of(uobj_va + UO_NAMEPRIVATE_OFFSET)
      by_index[i] = { va=uobj_va, class_va=class_va, outer_va=outer_va, name=name }
    end
    if VERBOSE and i % 5000 == 0 then print("  walked "..i) end
  end
  print("[GObjects] indexed " .. tostring((function()local c=0;for _ in pairs(by_index) do c=c+1 end;return c end)()) .. " live objects")
  return by_index
end

-- ==== FIELD/PROPERTY WALK ==================================================
local function walk_properties(struct_va)
  local props = {}
  local head = read_u64(struct_va + US_CHILDPROPS_OFFSET)
  local guard = 0
  while head ~= 0 and guard < 4096 do
    local pname   = fname_of(head + FF_NAMEPRIVATE_OFFSET)
    local pclass  = read_u64(head + FF_CLASSPRIVATE_OFFSET)  -- FFieldClass*
    local pclass_name_va = pclass ~= 0 and (pclass + 0x00) or 0  -- FFieldClass.Name is at 0
    local ptype = pclass_name_va ~= 0 and fname_of(pclass_name_va) or "<unknown>"
    local poff  = read_u32(head + FP_OFFSET_OFFSET)
    local psize = read_u32(head + FP_ELEMENTSIZE_OFFSET)
    local pdim  = read_u32(head + FP_ARRAYDIM_OFFSET)
    local pflag = read_u64(head + FP_PROPERTYFLAGS_OFFSET)
    props[#props+1] = { name=pname, type=ptype, offset=poff, size=psize, dim=pdim, flags=pflag }
    head = read_u64(head + FF_NEXT_OFFSET)
    guard = guard + 1
  end
  return props
end

local function walk_functions(struct_va)
  local fns = {}
  local head = read_u64(struct_va + US_CHILDREN_OFFSET)
  local guard = 0
  while head ~= 0 and guard < 4096 do
    local fname = fname_of(head + UO_NAMEPRIVATE_OFFSET)
    local flags = read_u32(head + UFN_FUNCTIONFLAGS_OFFSET)
    local params = walk_properties(head)
    fns[#fns+1] = { name=fname, flags=flags, params=params }
    head = read_u64(head + FF_NEXT_OFFSET)
    guard = guard + 1
  end
  return fns
end

-- ==== JSON EMIT =============================================================
local function json_escape(s)
  return (s or ""):gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n"):gsub("\r", "\\r")
end
local function json_val(v)
  if type(v) == "string" then return string.format('"%s"', json_escape(v)) end
  if type(v) == "number" then
    if v == math.floor(v) then return string.format("%d", v) end
    return tostring(v)
  end
  if type(v) == "boolean" then return v and "true" or "false" end
  if v == nil then return "null" end
  return tostring(v)
end
local function emit_kv_pairs(t, keys)
  local parts = {}
  for _, k in ipairs(keys) do parts[#parts+1] = string.format('"%s":%s', k, json_val(t[k])) end
  return "{" .. table.concat(parts, ",") .. "}"
end

-- ==== DRIVER ================================================================
local function main()
  if GObjects_VA == 0 or GNames_VA == 0 then
    print("!! set GObjects_VA and GNames_VA at the top of the script")
    return "missing anchors"
  end

  slop.fs = slop.fs or {}
  os.execute(string.format('mkdir "%s" 2>nul', OUTPUT_DIR))

  local start = os.clock()
  local objects = walk_objects()
  print(string.format("walked in %.1fs", os.clock() - start))

  -- classify: which indices point to UStructs (classes/structs)?
  local structs, enums, functions = {}, {}, {}
  for idx, info in pairs(objects) do
    if info.class_va and info.class_va ~= 0 then
      local cname = objects[read_u32((info.class_va or 0) + UO_INTERNALINDEX_OFFSET)]
      cname = cname and cname.name or "?"
      if cname == "Class" or cname == "ScriptStruct" then
        info.props = walk_properties(info.va)
        info.fns   = walk_functions(info.va)
        info.super = read_u64(info.va + US_SUPERSTRUCT_OFFSET)
        structs[#structs+1] = info
      elseif cname == "Enum" then
        enums[#enums+1] = info
      elseif cname == "Function" then
        functions[#functions+1] = info
      end
    end
  end
  print(string.format("classified: %d struct-like, %d enums, %d functions",
                       #structs, #enums, #functions))

  -- emit ClassesInfo.json
  local f = io.open(OUTPUT_DIR .. "\\ClassesInfo.json", "w")
  if f then
    f:write("[\n")
    for i, s in ipairs(structs) do
      f:write("  {\n")
      f:write(string.format('    "name": %s,\n', json_val(s.name)))
      f:write(string.format('    "va": %d,\n', s.va))
      f:write(string.format('    "super": %d,\n', s.super or 0))
      f:write('    "properties": [\n')
      for j, p in ipairs(s.props or {}) do
        f:write("      " .. emit_kv_pairs(p, {"name","type","offset","size","dim","flags"}))
        f:write(j < #(s.props or {}) and ",\n" or "\n")
      end
      f:write("    ],\n")
      f:write('    "functions": [\n')
      for j, fn in ipairs(s.fns or {}) do
        f:write("      " .. emit_kv_pairs({name=fn.name, flags=fn.flags}, {"name","flags"}))
        f:write(j < #(s.fns or {}) and ",\n" or "\n")
      end
      f:write("    ]\n")
      f:write(i < #structs and "  },\n" or "  }\n")
    end
    f:write("]\n")
    f:close()
    print("wrote ClassesInfo.json (" .. tostring(#structs) .. " classes)")
  end

  -- FNames.txt
  local nf = io.open(OUTPUT_DIR .. "\\FNames.txt", "w")
  if nf then
    for k, v in pairs(fname_cache) do nf:write(string.format("%d\t%s\n", k, v)) end
    nf:close()
  end
  print("done. output at " .. OUTPUT_DIR)
end

return main()
