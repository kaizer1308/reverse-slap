// app/src/components/panels/CallGraphView.tsx
// Interactive call graph visualization from xrefs

import { useState } from "react";
import { GitBranch, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type GraphNode = { addr: string; name: string; callers: string[]; callees: string[] };

export default function CallGraphView() {
  const [addr, setAddr] = useState("");
  const [depth, setDepth] = useState("3");
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const buildGraph = async () => {
    if (!addr.trim()) return;
    setBusy(true); setError(null);
    try {
      // Use xrefs to build both caller and callee graphs
      const callees = await call<{ xrefs: { from: string; to: string; to_name: string }[] }>(
        "disasm", "xrefs", { addr, direction: "from", limit: 100 }
      );
      const callers = await call<{ xrefs: { from: string; from_name: string; to: string }[] }>(
        "disasm", "xrefs", { addr, direction: "to", limit: 100 }
      );

      // Build node map
      const nodeMap = new Map<string, GraphNode>();
      const getNode = (a: string, n: string): GraphNode => {
        if (!nodeMap.has(a)) nodeMap.set(a, { addr: a, name: n || a, callers: [], callees: [] });
        return nodeMap.get(a)!;
      };

      const root = getNode(addr, addr);
      for (const x of callees.xrefs) {
        getNode(x.to, x.to_name);
        if (!root.callees.includes(x.to)) root.callees.push(x.to);
      }
      for (const x of callers.xrefs) {
        getNode(x.from, x.from_name);
        if (!root.callers.includes(x.from)) root.callers.push(x.from);
      }

      setNodes(Array.from(nodeMap.values()));
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const rootNode = nodes.find((n) => n.addr === addr);

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label"><GitBranch size={12} style={{ marginRight: 4 }} />Call Graph</div>
        <input className="addr-input" placeholder="function address" value={addr}
          onChange={(e) => setAddr(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void buildGraph(); }}
          style={{ width: 160 }} />
        <input className="addr-input" placeholder="depth" value={depth} onChange={(e) => setDepth(e.target.value)} style={{ width: 50 }} />
        <button className="row-action" disabled={busy} onClick={() => void buildGraph()}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Build"}
        </button>
        <div className="spacer" />
        {nodes.length > 0 && <span className="faint" style={{ fontSize: 11 }}>{nodes.length} nodes</span>}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}
        {rootNode ? (
          <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: "var(--pad-lg)" }}>
            <div>
              <div className="settings-label">Callers ({rootNode.callers.length})</div>
              {rootNode.callers.map((c) => {
                const n = nodes.find((x) => x.addr === c);
                return (
                  <div key={c} className="fn-row" style={{ position: "relative", padding: "4px 8px", cursor: "pointer" }}
                    onClick={() => { setAddr(c); void buildGraph(); }}>
                    <span className="mono faint" style={{ fontSize: 11, marginRight: 8 }}>{c}</span>
                    <span>{n?.name ?? c}</span>
                    <span style={{ marginLeft: "auto", color: "var(--accent)" }}>→</span>
                  </div>
                );
              })}
            </div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <div style={{ padding: "var(--pad-md)", background: "var(--bg-2)", borderRadius: "var(--radius-md)", border: "2px solid var(--accent)", textAlign: "center" }}>
                <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{rootNode.addr}</div>
                <div style={{ fontWeight: 600 }}>{rootNode.name}</div>
              </div>
            </div>
            <div>
              <div className="settings-label">Callees ({rootNode.callees.length})</div>
              {rootNode.callees.map((c) => {
                const n = nodes.find((x) => x.addr === c);
                return (
                  <div key={c} className="fn-row" style={{ position: "relative", padding: "4px 8px", cursor: "pointer" }}
                    onClick={() => { setAddr(c); void buildGraph(); }}>
                    <span style={{ color: "var(--accent)", marginRight: 8 }}>→</span>
                    <span>{n?.name ?? c}</span>
                    <span className="mono faint" style={{ fontSize: 11, marginLeft: "auto" }}>{c}</span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="empty">
            <div className="empty-glyph"><GitBranch size={28} strokeWidth={1.5} /></div>
            <div className="empty-title">Enter a function address to build its call graph.</div>
            <div className="empty-hint">Shows callers and callees with interactive navigation.</div>
          </div>
        )}
      </div>
    </div>
  );
}
