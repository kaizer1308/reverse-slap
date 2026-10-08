// app/src/components/panels/PointerScanView.tsx
// Pointer chain visualization for memory.pointerscan results

import { useState } from "react";
import { Link, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type PointerChain = { base: string; base_name: string; offsets: number[]; value: string; depth: number };

export default function PointerScanView() {
  const [addr, setAddr] = useState("");
  const [depth, setDepth] = useState("5");
  const [chains, setChains] = useState<PointerChain[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scan = async () => {
    if (!addr.trim()) return;
    setBusy(true); setError(null);
    try {
      const r = await call<{ chains: PointerChain[] }>("memory", "pointerscan", {
        addr, depth: parseInt(depth) || 5, max_offset: 0x2000, alignment: 4,
      });
      setChains(r.chains);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const formatChain = (c: PointerChain): string =>
    `[${c.base_name || c.base}]` + c.offsets.map((o) => ` + 0x${o.toString(16)}`).join(" →");

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label"><Link size={12} style={{ marginRight: 4 }} />Pointer Scan</div>
        <input className="addr-input" placeholder="target address" value={addr}
          onChange={(e) => setAddr(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void scan(); }}
          style={{ width: 160 }} />
        <input className="addr-input" placeholder="depth" value={depth} onChange={(e) => setDepth(e.target.value)} style={{ width: 50 }} />
        <button className="row-action" disabled={busy} onClick={() => void scan()}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Scan"}
        </button>
        <div className="spacer" />
        {chains.length > 0 && <span className="faint" style={{ fontSize: 11 }}>{chains.length} chains</span>}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}
        {chains.length > 0 ? (
          <table className="table">
            <thead><tr><th>Depth</th><th>Base</th><th>Chain</th><th>Value</th></tr></thead>
            <tbody>
              {chains.map((c, i) => (
                <tr key={i}>
                  <td>{c.depth}</td>
                  <td className="mono">{c.base_name || c.base}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{formatChain(c)}</td>
                  <td className="mono">{c.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : !busy && (
          <div className="empty">
            <div className="empty-glyph"><Link size={28} strokeWidth={1.5} /></div>
            <div className="empty-title">Find stable pointer chains to a target address.</div>
            <div className="empty-hint">Scans for multi-level pointers rooted in static module bases.</div>
          </div>
        )}
      </div>
    </div>
  );
}
