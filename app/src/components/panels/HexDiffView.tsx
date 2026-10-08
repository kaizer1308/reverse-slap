// app/src/components/panels/HexDiffView.tsx
// Side-by-side binary diff viewer using analyze.diff

import { useState } from "react";
import { GitCompare, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type DiffPair = { addr_a: string; addr_b: string; name_a: string; name_b: string; similarity: number; changes: string[] };

export default function HexDiffView() {
  const [pathA, setPathA] = useState("");
  const [pathB, setPathB] = useState("");
  const [pairs, setPairs] = useState<DiffPair[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startDiff = async () => {
    if (!pathA.trim() || !pathB.trim()) return;
    setBusy(true); setError(null);
    try {
      await call("analyze", "diff_start", { path_a: pathA, path_b: pathB });
      // Poll for results
      const r = await call<{ pairs: DiffPair[] }>("analyze", "diff", { path_a: pathA, path_b: pathB, limit: 200 });
      setPairs(r.pairs);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label"><GitCompare size={12} style={{ marginRight: 4 }} />Binary Diff</div>
        <input className="addr-input" placeholder="binary A" value={pathA} onChange={(e) => setPathA(e.target.value)} style={{ flex: 1 }} />
        <input className="addr-input" placeholder="binary B" value={pathB} onChange={(e) => setPathB(e.target.value)} style={{ flex: 1 }} />
        <button className="row-action" disabled={busy} onClick={() => void startDiff()}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Diff"}
        </button>
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}
        {pairs.length > 0 ? (
          <table className="table">
            <thead><tr><th>Function A</th><th>Function B</th><th>Similarity</th><th>Changes</th></tr></thead>
            <tbody>
              {pairs.map((p, i) => (
                <tr key={i}>
                  <td><span className="mono">{p.addr_a}</span> {p.name_a}</td>
                  <td><span className="mono">{p.addr_b}</span> {p.name_b}</td>
                  <td style={{ color: p.similarity < 0.5 ? "var(--danger)" : p.similarity < 0.8 ? "var(--warning)" : "var(--text)" }}>
                    {(p.similarity * 100).toFixed(0)}%
                  </td>
                  <td className="faint">{p.changes.length} changes</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty">
            <div className="empty-glyph"><GitCompare size={28} strokeWidth={1.5} /></div>
            <div className="empty-title">Enter two binary paths and click Diff.</div>
            <div className="empty-hint">Compares functions across two versions to identify changes.</div>
          </div>
        )}
      </div>
    </div>
  );
}
