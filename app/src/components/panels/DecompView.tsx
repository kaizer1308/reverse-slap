// app/src/components/panels/DecompView.tsx
// Pseudocode decompiler view — like IDA's F5

import { useState } from "react";
import { Code, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

export default function DecompView() {
  const [addr, setAddr] = useState("");
  const [code, setCode] = useState("");
  const [funcName, setFuncName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decompile = async () => {
    if (!addr.trim()) return;
    setBusy(true); setError(null);
    try {
      const r = await call<{ code: string; name: string }>("decomp", "decompile", { addr });
      setCode(r.code);
      setFuncName(r.name);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label"><Code size={12} style={{ marginRight: 4 }} />Decompiler</div>
        <input className="addr-input" placeholder="function address or name" value={addr}
          onChange={(e) => setAddr(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void decompile(); }}
          style={{ width: 200 }} />
        <button className="row-action" disabled={busy} onClick={() => void decompile()}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Decompile"}
        </button>
        <div className="spacer" />
        {funcName && <span className="faint" style={{ fontSize: 11 }}>{funcName}</span>}
      </div>
      <div className="panel-body" style={{ overflow: "auto" }}>
        {error && <div className="settings-status" style={{ margin: "var(--pad-md)" }}>{error}</div>}
        {code ? (
          <pre className="code-area" style={{ height: "100%", whiteSpace: "pre-wrap" }}>{code}</pre>
        ) : (
          <div className="empty">
            <div className="empty-glyph"><Code size={28} strokeWidth={1.5} /></div>
            <div className="empty-title">Enter a function address and press Decompile.</div>
            <div className="empty-hint">Generates C-like pseudocode from disassembly.</div>
          </div>
        )}
      </div>
    </div>
  );
}
