// app/src/components/panels/AnalyzeView.tsx
// Binary diff, packer detection, dangerous imports, RTTI, vtables, lib signatures

import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type PackerResult = { name: string; confidence: number; details: string };
type DangerImport = { module: string; function: string; reason: string; severity: string };
type RttiClass = { address: string; name: string; vtable: string; parents: string[] };
type VfTable = { address: string; name: string; count: number; methods: string[] };
type LibSig = { address: string; name: string; library: string; confidence: number };

export default function AnalyzeView() {
  const [tab, setTab] = useState<"packer" | "danger" | "rtti" | "vtable" | "libsig">("packer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [packers, setPackers] = useState<PackerResult[]>([]);
  const [dangers, setDangers] = useState<DangerImport[]>([]);
  const [rttiClasses, setRttiClasses] = useState<RttiClass[]>([]);
  const [vtables, setVtables] = useState<VfTable[]>([]);
  const [libsigs, setLibsigs] = useState<LibSig[]>([]);

  const run = async <T,>(tool: string, action: string, setter: (v: T) => void, key: string) => {
    setBusy(true); setError(null);
    try {
      const r = await call<Record<string, T>>(tool, action);
      setter(r[key] as T);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      <div className="view-bar">
        {(["packer", "danger", "rtti", "vtable", "libsig"] as const).map((t) => (
          <button key={t} className="row-action" data-active={tab === t} onClick={() => setTab(t)}>{t}</button>
        ))}
        <div className="spacer" />
        {busy && <RefreshCw size={12} className="spin" style={{ color: "var(--accent)" }} />}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

        {tab === "packer" && (
          <>
            <button className="row-action" disabled={busy} onClick={() => void run<PackerResult[]>("analyze", "packer", setPackers, "results")} style={{ marginBottom: "var(--pad-md)" }}>Detect Packers</button>
            <table className="table"><thead><tr><th>Name</th><th>Confidence</th><th>Details</th></tr></thead><tbody>
              {packers.map((p, i) => <tr key={i}><td>{p.name}</td><td>{(p.confidence * 100).toFixed(0)}%</td><td className="faint">{p.details}</td></tr>)}
            </tbody></table>
          </>
        )}

        {tab === "danger" && (
          <>
            <button className="row-action" disabled={busy} onClick={() => void run<DangerImport[]>("re", "danger", setDangers, "results")} style={{ marginBottom: "var(--pad-md)" }}>Scan Dangerous Imports</button>
            <table className="table"><thead><tr><th>Module</th><th>Function</th><th>Reason</th><th>Severity</th></tr></thead><tbody>
              {dangers.map((d, i) => (
                <tr key={i}><td>{d.module}</td><td className="mono">{d.function}</td><td>{d.reason}</td>
                  <td style={{ color: d.severity === "high" ? "var(--danger)" : "var(--text-dim)" }}>{d.severity}</td></tr>
              ))}
            </tbody></table>
          </>
        )}

        {tab === "rtti" && (
          <>
            <button className="row-action" disabled={busy} onClick={() => void run<RttiClass[]>("re", "rtti_scan", setRttiClasses, "classes")} style={{ marginBottom: "var(--pad-md)" }}>Scan RTTI</button>
            <table className="table"><thead><tr><th>Address</th><th>Name</th><th>VTable</th><th>Parents</th></tr></thead><tbody>
              {rttiClasses.map((c, i) => <tr key={i}><td className="mono">{c.address}</td><td>{c.name}</td><td className="mono">{c.vtable}</td><td className="faint">{c.parents.join(", ")}</td></tr>)}
            </tbody></table>
          </>
        )}

        {tab === "vtable" && (
          <>
            <button className="row-action" disabled={busy} onClick={() => void run<VfTable[]>("re", "vftable", setVtables, "tables")} style={{ marginBottom: "var(--pad-md)" }}>Scan VTables</button>
            <table className="table"><thead><tr><th>Address</th><th>Name</th><th>Methods</th></tr></thead><tbody>
              {vtables.map((v, i) => <tr key={i}><td className="mono">{v.address}</td><td>{v.name}</td><td>{v.count}</td></tr>)}
            </tbody></table>
          </>
        )}

        {tab === "libsig" && (
          <>
            <button className="row-action" disabled={busy} onClick={() => void run<LibSig[]>("re", "libsig", setLibsigs, "matches")} style={{ marginBottom: "var(--pad-md)" }}>Match Library Signatures</button>
            <table className="table"><thead><tr><th>Address</th><th>Name</th><th>Library</th><th>Confidence</th></tr></thead><tbody>
              {libsigs.map((l, i) => <tr key={i}><td className="mono">{l.address}</td><td>{l.name}</td><td>{l.library}</td><td>{(l.confidence * 100).toFixed(0)}%</td></tr>)}
            </tbody></table>
          </>
        )}
      </div>
    </div>
  );
}
