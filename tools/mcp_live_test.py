# Live MCP battery against running reverse-slop (SlopTarget.exe loaded, hype.ready)
import json, urllib.request, time, sys

URL = "http://127.0.0.1:8765/mcp"
results = []

def call(name, params, timeout=60):
    body = json.dumps({"jsonrpc":"2.0","id":int(time.time()*1000)%100000,
                       "method":"tools/call",
                       "params":{"name":name,"arguments":params}}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type":"application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
        dt = time.time()-t0
        res = d.get("result", {})
        content = res.get("content", [])
        text = content[0].get("text","") if content else ""
        try: payload = json.loads(text)
        except Exception: payload = {"_raw": text[:500]}
        err = res.get("isError", False) or "error" in d
        if isinstance(payload, dict) and "error" in payload:
            err = True
        return {"ok": not err, "dt": round(dt,2), "payload": payload}
    except Exception as e:
        return {"ok": False, "dt": round(time.time()-t0,2), "payload": {"exception": str(e)[:300]}}

def test(label, name, params, check=None, timeout=60):
    r = call(name, params, timeout)
    note = ""
    if r["ok"] and check:
        try:
            note = check(r["payload"]) or ""
        except Exception as e:
            note = "check-threw: " + str(e)[:200]
    results.append({"label": label, "tool": name, "params": params,
                    "ok": r["ok"], "dt": r["dt"], "note": note,
                    "brief": json.dumps(r["payload"])[:300]})
    flag = "PASS" if r["ok"] else "FAIL"
    print(f"[{flag}] {label} ({r['dt']}s) {note}")
    if not r["ok"]:
        print("   ->", json.dumps(r["payload"])[:250])
    return r

# state / context
st = call("target", {"action":"status"})
base = st["payload"]["image"]["base"]
entry = st["payload"]["image"]["entry_va"]
print("base=%X entry=%X hype.ready=%s" % (base, entry, st["payload"]["image"]["hype"].get("ready")))

# target
test("target.status", "target", {"action":"status"})
test("target.list", "target", {"action":"list"})
test("target.modules (no attach)", "target", {"action":"modules"})
test("target.bad action", "target", {"action":"nope"})

# disasm core
test("disasm.loaded", "disasm", {"action":"loaded"})
pe = call("disasm", {"action":"pe"})
print("pe ok:", pe["ok"], "sections:", len(pe["payload"].get("sections",[])))
results.append({"label":"disasm.pe","tool":"disasm","params":{"action":"pe"},"ok":pe["ok"],"dt":pe["dt"],"note":"","brief":json.dumps(pe["payload"])[:300]})

fns = call("disasm", {"action":"functions", "limit": 50})
fn0 = fns["payload"]["functions"][0]["va"] if fns["ok"] and fns["payload"].get("functions") else entry
print("first fn va:", hex(fn0), "total:", fns["payload"].get("total"))
results.append({"label":"disasm.functions","tool":"disasm","params":{"limit":50},"ok":fns["ok"],"dt":fns["dt"],
                "note":"total=%s hype-fns=%s" % (fns["payload"].get("total"), (fns["payload"].get("hype") or {}).get("functions")),
                "brief":json.dumps(fns["payload"])[:300]})

test("disasm.disassemble at entry", "disasm", {"action":"disassemble","addr":entry,"count":8},
     lambda p: "got %d insns, first=%s" % (p["count"], p["instructions"][0]["text"]))
test("disasm.disassemble garbage addr", "disasm", {"action":"disassemble","addr":"0x1400","count":4})
test("disasm.xrefs at entry", "disasm", {"action":"xrefs","addr":entry},
     lambda p: "engine=%s count=%d" % (p.get("engine","legacy"), p["count"]))
test("disasm.blocks at fn", "disasm", {"action":"blocks","addr":fn0},
     lambda p: "%d blocks, name=%s" % (p["count"], p.get("name")))
test("disasm.vtables", "disasm", {"action":"vtables"}, lambda p: "%d vtables" % p["count"])
test("disasm.globals", "disasm", {"action":"globals"}, lambda p: "%d globals" % p["count"])
test("disasm.strings", "disasm", {"action":"strings","limit":20}, lambda p: "%d strings" % len(p["strings"]))
test("disasm.symbols", "disasm", {"action":"symbols"}, lambda p: "%d symbols" % p["count"])
test("disasm.assemble", "disasm", {"action":"assemble","text":"mov rax, rbx"},
     lambda p: "bytes=%s" % p["bytes"])
test("disasm.assemble bad", "disasm", {"action":"assemble","text":"frobnicate rax"})
test("disasm.unknown action", "disasm", {"action":"zzz"})

# decomp
d = test("decomp.function at fn0", "decomp", {"action":"function","addr":fn0},
     lambda p: "sig=%s lines=%d vars=%d" % (p["signature"][:60], len(p["lines"]), len(p["vars"])), timeout=120)
if d["ok"]:
    lines = d["payload"]["lines"]
    print("   sample:", [l["text"] for l in lines[:3]])
test("decomp.function bad addr", "decomp", {"action":"function","addr":"0x12345678"})
test("decomp bad action", "decomp", {"action":"nope"})

# re
r = test("re.rtti_scan", "re", {"action":"rtti_scan"}, lambda p: "engine=%s classes=%d" % (p.get("engine","legacy"), p["count"]))
vt_va = None
if r["ok"] and r["payload"].get("classes"):
    vt_va = r["payload"]["classes"][0].get("vtable_va")
    print("   class0:", r["payload"]["classes"][0]["name"], "vt:", hex(vt_va) if vt_va else None)
if vt_va:
    test("re.vftable", "re", {"action":"vftable","addr":vt_va}, lambda p: "engine=%s count=%d" % (p.get("engine","legacy"), p["count"]))
test("re.danger", "re", {"action":"danger"}, lambda p: "%d hits" % p["count"])
# KEY SUSPECT: re with explicit path, xref/function index never built?
test("re.danger with explicit path", "re", {"action":"danger","path":"E:\\reverse-slop\\build\\src\\app\\SlopTarget.exe"},
     lambda p: "PATH-VARIANT hits=%d (compare with shared count!)" % p["count"])
test("re.libsig bad", "re", {"action":"libsig","sigset":"{}"})

# analyze
test("analyze.packer", "analyze", {"action":"packer"},
     lambda p: "packed=%s family=%s hype=%s" % (p.get("packed"), p.get("family"), len(p.get("hype_packer",[]))))
sig = call("analyze", {"action":"signatures"})
print("analyze.signatures: crypto=%s flirt=%s" % (sig["payload"].get("count"), sig["payload"].get("flirt_count")))
results.append({"label":"analyze.signatures","tool":"analyze","params":{"action":"signatures"},"ok":sig["ok"],"dt":sig["dt"],
                "note":"crypto=%s flirt_count=%s flirt_sample=%s" % (sig["payload"].get("count"), sig["payload"].get("flirt_count"), json.dumps((sig["payload"].get("flirt") or [])[:3])),
                "brief":json.dumps(sig["payload"])[:300]})
test("analyze.diff self", "analyze", {"action":"diff","path_a":"E:\\reverse-slop\\build\\src\\app\\SlopTarget.exe","path_b":"E:\\reverse-slop\\build\\src\\app\\SlopTarget.exe"},
     lambda p: "totals=%s (identical expected)" % json.dumps(p.get("totals")), timeout=300)

# xray
test("xray.cfg at fn0", "xray", {"action":"cfg","addr":fn0}, lambda p: "blocks=%d cyc=%s" % (p.get("block_count",0), p.get("cyclomatic_complexity")))
test("xray.complexity at fn0", "xray", {"action":"complexity","addr":fn0})
test("xray.cff at fn0", "xray", {"action":"cff","addr":fn0})
test("xray.obfuscation at fn0", "xray", {"action":"obfuscation","addr":fn0})
test("xray.indirect_calls at fn0", "xray", {"action":"indirect_calls","addr":fn0})
test("xray.anti_analysis at fn0", "xray", {"action":"anti_analysis","addr":fn0})
test("xray.hooks", "xray", {"action":"hooks"}, lambda p: "checked=%s found=%s" % (p.get("functions_checked"), p.get("hooks_found")))
test("xray.syscalls", "xray", {"action":"syscalls"})
test("xray.apihash ror13", "xray", {"action":"apihash","hash":"0xC2B9DBB1","algorithm":"ror13"},
     lambda p: "resolved=%s" % json.dumps(p.get("resolved",[])[:2]))
test("xray.entropy", "xray", {"action":"entropy","addr":entry,"size":2048}, lambda p: "overall=%.2f verdict=%s" % (p.get("overall_entropy",0), p.get("verdict")))
test("xray.pages", "xray", {"action":"pages","addr":entry,"size":8192})
test("xray.crypto_range", "xray", {"action":"crypto_range","addr":base,"size":65536})
test("xray.gadgets", "xray", {"action":"gadgets","limit":20}, lambda p: "count=%d" % p["count"])
test("xray strings_recon", "xray", {"action":"strings_recon","addr":fn0})

# types
test("types.declare struct", "types", {"action":"declare","decl":"struct TestHdr { u32 magic; u32 len; char tag[8]; } packed;"})
test("types.get_struct", "types", {"action":"get_struct","name":"TestHdr"})
test("types.list_structs", "types", {"action":"list_structs"})
test("types.read_field (file)", "types", {"action":"read_field","struct":"TestHdr","field":"magic","addr":base})
test("types.format_at", "types", {"action":"format_at","type":"TestHdr","addr":base,"size":16},
     lambda p: "rendered=%s" % p.get("rendered","")[:120])
test("types.create_enum + get", "types", {"action":"create_enum","name":"TestTag","values":[{"name":"A","value":1},{"name":"B","value":2}]})
test("types.get_enum", "types", {"action":"get_enum","name":"TestTag"})
test("types.remove_struct", "types", {"action":"remove_struct","name":"TestHdr"})

# notes
test("notes.set_comment", "notes", {"action":"set_comment","addr":entry,"text":"entry point - ENI audit"})
test("notes.get_comment", "notes", {"action":"get_comment","addr":entry}, lambda p: "comment=%s" % p.get("comment"))
test("notes.comments", "notes", {"action":"comments"})
test("notes.bookmark_toggle", "notes", {"action":"bookmark_toggle","addr":entry})
test("notes.bookmarks", "notes", {"action":"bookmarks"})
test("notes.bookmark_toggle (undo)", "notes", {"action":"bookmark_toggle","addr":entry})
test("notes.set_comment (clear)", "notes", {"action":"set_comment","addr":entry,"text":""})

# persist
ps = test("persist.save", "persist", {"action":"save","name":"eni_audit","data":{"foo":"bar"}})
pid_ = ps["payload"].get("id") if ps["ok"] else None
test("persist.list", "persist", {"action":"list"})
if pid_: test("persist.load", "persist", {"action":"load","id":pid_})
test("persist.kv_set/get", "persist", {"action":"kv_set","key":"testk","value":{"x":1}})
test("persist.kv_get", "persist", {"action":"kv_get","key":"testk"})
if pid_: test("persist.delete", "persist", {"action":"delete","id":pid_})
test("persist.hype_save", "persist", {"action":"hype_save","dir":"C:\\Users\\kozydot\\AppData\\Local\\Temp\\eni_hdb_test"}, timeout=120)
test("persist.hype_load", "persist", {"action":"hype_load","dir":"C:\\Users\\kozydot\\AppData\\Local\\Temp\\eni_hdb_test"}, timeout=120)

# emulate
test("emulate.run hex", "emulate", {"action":"run","hex":"B839050000C3","count":16},
     lambda p: "ok=%s reason=%s rax=%s" % (p.get("ok"), p.get("stopped_reason"), (p.get("regs") or {}).get("rax")))
test("emulate.run file_addr", "emulate", {"action":"run","file_addr":entry,"code_len":64,"count":32},
     lambda p: "reason=%s insns=%s" % (p.get("stopped_reason"), p.get("instructions"))
     if p.get("ok") or "stopped_reason" in p else "err=%s" % p.get("error"))
test("emulate.run taint", "emulate", {"action":"run","hex":"8B0425AABBCCDD","count":8,"taint":[{"addr":"0xAABBCCDD","len":4}]})

# memory (no target attached, image fallback path)
test("memory.read hex @entry", "memory", {"action":"read","addr":entry,"len":32},
     lambda p: "len=%s" % p.get("len"))
test("memory.read utf8", "memory", {"action":"read","addr":entry,"len":16,"format":"utf8"})
test("memory.read u32", "memory", {"action":"read","addr":base,"len":16,"format":"u32"})
test("memory.read unmapped", "memory", {"action":"read","addr":"0xFFFFFFFFFFF00000","len":16})
test("memory.scan (no target)", "memory", {"action":"scan","value":42})
test("memory.snapshots", "memory", {"action":"snapshots"})

# patch (journal only, no mutation)
test("patch.journal", "patch", {"action":"journal"})
test("patch.nop_junk dry-ish on fn0", "patch", {"action":"nop_junk","addr":fn0,"aggressive":False})

# devirt
test("devirt.iat_audit", "devirt", {"action":"iat_audit"}, lambda p: "slots=%s named=%s" % (p.get("slots_scanned"), p.get("named")))
test("devirt.identify at fn0", "devirt", {"action":"identify","addr":fn0})
test("devirt.prove_predicates fn0", "devirt", {"action":"prove_predicates","addr":fn0,"runs":2}, timeout=120)
test("devirt.invariants fn0", "devirt", {"action":"invariants","addr":fn0,"runs":2}, timeout=120)

# network / proxy / detect
test("network.status", "network", {"action":"status"})
test("network.packets", "network", {"action":"packets"})
test("network.connections", "network", {"action":"connections"})
test("network.stats", "network", {"action":"stats"})
test("network.bad action", "network", {"action":"zzz"})
test("proxy.status", "proxy", {"action":"status"})
test("proxy.entries", "proxy", {"action":"entries"})
test("detect.hidden_modules", "detect", {"action":"hidden_modules"})
test("detect.minifilters", "detect", {"action":"minifilters"})
test("detect.etw_sessions", "detect", {"action":"etw_sessions"})
test("detect.kernel_callbacks", "detect", {"action":"kernel_callbacks"})

# driver (backend reported kernel!)
test("driver.status", "driver", {"action":"status"})
test("driver.kernel_modules", "driver", {"action":"kernel_modules"})
test("driver.symbols_load", "driver", {"action":"symbols_load"}, timeout=180)
test("driver.ssdt", "driver", {"action":"ssdt"})
test("driver.peb (no target)", "driver", {"action":"peb"})

# debugger (no attach)
test("debugger.status", "debugger", {"action":"status"})
test("debugger.regs (not paused)", "debugger", {"action":"regs"})

# fs
test("fs.write_file", "fs", {"action":"write_file","path":"C:\\Users\\kozydot\\AppData\\Local\\Temp\\eni_test.txt","text":"hello from mcp"})
test("fs.read_file", "fs", {"action":"read_file","path":"C:\\Users\\kozydot\\AppData\\Local\\Temp\\eni_test.txt"})
test("fs.list_directory", "fs", {"action":"list_directory","path":"E:\\reverse-slop\\build\\src\\app"})
test("fs.grep_in_files", "fs", {"action":"grep_in_files","root":"E:\\reverse-slop\\src\\core\\mcp","needle":"unknown action","suffix":".cpp","limit":5})
test("fs.delete_path", "fs", {"action":"delete_path","path":"C:\\Users\\kozydot\\AppData\\Local\\Temp\\eni_test.txt"})

# web
test("web.fetch", "web", {"action":"fetch","url":"http://127.0.0.1:8765/mcp","timeout_ms":5000})
test("web.fetch bad host", "web", {"action":"fetch","url":"http://nonexistent.invalid/x"})

# script
test("script.run", "script", {"action":"run","code":"return 'hello from lua'"},
     lambda p: "ok=%s out=%s" % (p.get("ok"), p.get("output","")[:80]))
test("script.run infinite (timeout)", "script", {"action":"run","code":"while true do end","timeout_ms":2000}, timeout=30)

# unknown tool
test("unknown tool", "zzztool", {"action":"x"})

json.dump(results, open("mcp_live_results.json","w"), indent=1)
print("\n=== SUMMARY: %d/%d passed ===" % (sum(1 for r in results if r["ok"]), len(results)))
