#pragma once

// src/core/script/lua_engine.hpp
// embedded lua 5.4 over the core services on the raw c api
// the static analysis surface is the lua to reverse slop as python to ida
// layer, it all operates on the shared session so renames and comments
// made from lua or mcp appear everywhere:
//
//   slop.image.load(path[, base])     load a binary into the shared session
//   slop.image.load_from_target()     load the attached target's main module
//   slop.image.unload()               tear the session down
//   slop.image.status()               {ready,name,base,entry,hype={...}}
//   slop.image.wait_ready([ms])       block until hyperion analysis lands
//
//   slop.disasm.decode(addr[, n])     {addr,len,text,bytes,target,...} rows
//   slop.disasm.functions([limit])    {va,size,name[,blocks,loops,...]} rows
//   slop.disasm.function_at(va)       owning function row (nil outside)
//   slop.disasm.xrefs_to(va)          {from,kind} rows (hyperion-enriched)
//   slop.disasm.strings([min[,lim]])  {va,text,utf16} rows
//   slop.disasm.pe()                  headers, sections, imports, exports
//   slop.disasm.bytes(addr[, len])    raw file-image bytes (binary string)
//   slop.disasm.name(va) / set_name(va, name)       persisted rename
//   slop.disasm.comment(va) / set_comment(va, text) persisted annotation
//   slop.disasm.bookmark_toggle(va) / bookmarks()
//
//   slop.decomp.decompile(va)        pseudo-C lines + signature (hyperion)
//   slop.decomp.blocks(va)            CFG blocks + loops for a function
//   slop.decomp.vtables() / globals() / rtti()   rich analysis DB views
//
// legacy live analysis surface:
//   slop.version() / slop.log(msg)
//   slop.target.list() / attach(pid) / status()
//   slop.mem.read_hex(addr,len) / write_hex(addr,hexstr) / scan(cfg)
//   slop.disasm.disassemble(addr,count)     live-process disassembly
//   slop.analyze.packer([path])
//
// every script runs under an instruction count hook for the hard timeout,
// print output is captured and the return value lands in the output as
// return: ...

#include <string>

namespace slop::core::script {

struct lua_run_result_t {
    bool        ok  = false;
    std::string output;   // captured print/slop.log stream
    std::string error;    // non-empty on failure
};

lua_run_result_t lua_run(const std::string& code, int timeout_ms = 5000);

} // namespace slop::core::script
