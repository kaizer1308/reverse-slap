// app/src/components/panels/DevirtView.tsx
// VM deobfuscation: Themida, handler identification, opcode map, trace, lift, pseudocode

import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type ThemidaStatus = { running: boolean; progress: number; status: string };
type Handler = { id: number; address: string; opcode: number; name: string; effect: string };
type LiftResult = { address: string; il: string };

export default function DevirtView() {
  const [tab, setTab] = useState<"themida" | "handlers" | "trace" | "lift">("themida");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<ThemidaStatus | null>(null);
  const [handlers, setHandlers] = useState<Handler[]>([]);
  const [traceLog, setTraceLog] = useState<string[]>([]);
  const [lifted, setLifted] = useState<LiftResult[]>([]);
  const [pseudocode, setPseudocode] = useState("");
  const [addr, setAddr] = useState("");

  const refresh = async (action: string, setter: (v: unknown) => void, key: string, params?: Record<string, unknown>) => {
    setBusy(true); setError(null);
    try {
      const r = await call<Record<string, unknown>>(action.startsWith("themida") ? "devirt" : "devirt", action, params);
      setter(r[key]);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      <div className="view-bar">
        {(["themida", "handlers", "trace", "lift"] as const).map((t) => (
          <button key={t} className="row-action" data-active={tab === t} onClick={() => setTab(t)}>{t}</button>
        ))}
        <div className="spacer" />
        {busy && <RefreshCw size={12} className="spin" style={{ color: "var(--accent)" }} />}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

        {tab === "themida" && (
          <>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              <button className="row-action" disabled={busy}
                onClick={() => void refresh("themida_status", (v) => setStatus(v as ThemidaStatus), "status")}>
                Check Status
              </button>
              <button className="row-action" disabled={busy}
                onClick={() => void refresh("themida_start", (v) => setStatus(v as ThemidaStatus), "status")}>
                Start Unpack
              </button>
            </div>
            {status && (
              <div className="settings-rows mono">
                <div>running: {status.running ? "yes" : "no"}</div>
                <div>progress: {(status.progress * 100).toFixed(0)}%</div>
                <div>status: {status.status}</div>
              </div>
            )}
          </>
        )}

        {tab === "handlers" && (
          <>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              <input className="addr-input" placeholder="function address" value={addr} onChange={(e) => setAddr(e.target.value)} />
              <button className="row-action" disabled={busy}
                onClick={() => void refresh("handlers", (v) => setHandlers(v as Handler[]), "handlers", addr ? { addr } : {})}>
                Identify Handlers
              </button>
            </div>
            <table className="table"><thead><tr><th>ID</th><th>Opcode</th><th>Address</th><th>Name</th><th>Effect</th></tr></thead><tbody>
              {handlers.map((h) => (
                <tr key={h.id}><td>{h.id}</td><td className="mono">0x{h.opcode.toString(16)}</td><td className="mono">{h.address}</td><td>{h.name}</td><td className="faint">{h.effect}</td></tr>
              ))}
            </tbody></table>
          </>
        )}

        {tab === "trace" && (
          <>
            <button className="row-action" disabled={busy}
              onClick={() => void refresh("trace", (v) => setTraceLog(v as string[]), "log", addr ? { addr } : {})}
              style={{ marginBottom: "var(--pad-md)" }}>
              Trace VM Execution
            </button>
            <div className="log">
              {traceLog.map((l, i) => <div key={i} className="log-row mono">{l}</div>)}
            </div>
          </>
        )}

        {tab === "lift" && (
          <>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              <button className="row-action" disabled={busy}
                onClick={() => void refresh("lift", (v) => setLifted(v as LiftResult[]), "blocks", addr ? { addr } : {})}>
                Lift to IL
              </button>
              <button className="row-action" disabled={busy}
                onClick={() => void refresh("pseudocode", (v) => setPseudocode(v as string), "code", addr ? { addr } : {})}>
                Decompile
              </button>
            </div>
            {pseudocode && <pre className="code-area" style={{ height: "auto", minHeight: 200 }}>{pseudocode}</pre>}
            {lifted.length > 0 && !pseudocode && (
              <table className="table"><thead><tr><th>Address</th><th>IL</th></tr></thead><tbody>
                {lifted.map((l, i) => <tr key={i}><td className="mono">{l.address}</td><td className="mono">{l.il}</td></tr>)}
              </tbody></table>
            )}
          </>
        )}
      </div>
    </div>
  );
}
