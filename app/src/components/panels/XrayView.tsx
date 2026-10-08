// app/src/components/panels/XrayView.tsx
// Binary analysis: hooks, syscalls, entropy, gadgets, crypto, obfuscation, CFG

import { RefreshCw } from "lucide-react";
import { useXray } from "@/store/xray";

const kTabs = ["hooks", "syscalls", "gadgets", "entropy", "crypto", "obfuscation", "cfg"] as const;

export default function XrayView() {
  const s = useXray();

  return (
    <div className="stack">
      <div className="view-bar">
        {kTabs.map((t) => (
          <button key={t} className="row-action" data-active={s.activeTab === t} onClick={() => s.setTab(t)}>{t}</button>
        ))}
        <div className="spacer" />
        {s.busy && <RefreshCw size={12} className="spin" style={{ color: "var(--accent)" }} />}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {s.error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{s.error}</div>}

        {s.activeTab === "hooks" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runHooks()} style={{ marginBottom: "var(--pad-md)" }}>Scan for Hooks</button>
            <table className="table"><thead><tr><th>Address</th><th>Target</th><th>Module</th><th>Type</th></tr></thead><tbody>
              {s.hooks.map((h, i) => <tr key={i}><td className="mono">{h.address}</td><td className="mono">{h.target}</td><td>{h.module}</td><td><span className="pill">{h.type}</span></td></tr>)}
            </tbody></table>
          </>
        )}

        {s.activeTab === "syscalls" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runSyscalls()} style={{ marginBottom: "var(--pad-md)" }}>Extract Syscalls</button>
            <table className="table"><thead><tr><th>Address</th><th>Number</th><th>Name</th><th>Module</th></tr></thead><tbody>
              {s.syscalls.map((e, i) => <tr key={i}><td className="mono">{e.address}</td><td>{e.number}</td><td>{e.name}</td><td>{e.module}</td></tr>)}
            </tbody></table>
          </>
        )}

        {s.activeTab === "gadgets" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runGadgets()} style={{ marginBottom: "var(--pad-md)" }}>Find ROP Gadgets</button>
            <table className="table"><thead><tr><th>Address</th><th>Instructions</th><th>Type</th></tr></thead><tbody>
              {s.gadgets.map((g, i) => <tr key={i}><td className="mono">{g.address}</td><td className="mono">{g.insns}</td><td><span className="pill">{g.type}</span></td></tr>)}
            </tbody></table>
          </>
        )}

        {s.activeTab === "entropy" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runEntropy()} style={{ marginBottom: "var(--pad-md)" }}>Analyze Entropy</button>
            <table className="table"><thead><tr><th>Offset</th><th>Size</th><th>Entropy</th><th>Label</th></tr></thead><tbody>
              {s.entropy.map((b, i) => (
                <tr key={i}>
                  <td className="mono">{b.offset.toString(16)}</td><td>{b.size}</td>
                  <td style={{ color: b.entropy > 7.5 ? "var(--danger)" : b.entropy > 6 ? "var(--warning)" : "var(--text)" }}>{b.entropy.toFixed(3)}</td>
                  <td>{b.label}</td>
                </tr>
              ))}
            </tbody></table>
          </>
        )}

        {s.activeTab === "crypto" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runCrypto()} style={{ marginBottom: "var(--pad-md)" }}>Find Crypto Constants</button>
            <table className="table"><thead><tr><th>Address</th><th>Size</th><th>Algorithm</th><th>Confidence</th></tr></thead><tbody>
              {s.crypto.map((c, i) => <tr key={i}><td className="mono">{c.address}</td><td>{c.size}</td><td>{c.algorithm}</td><td>{(c.confidence * 100).toFixed(0)}%</td></tr>)}
            </tbody></table>
          </>
        )}

        {s.activeTab === "obfuscation" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runObfuscation()} style={{ marginBottom: "var(--pad-md)" }}>Detect Obfuscation</button>
            <table className="table"><thead><tr><th>Type</th><th>Count</th><th>Severity</th><th>Details</th></tr></thead><tbody>
              {s.obfuscation.map((o, i) => (
                <tr key={i}>
                  <td><span className="pill">{o.type}</span></td><td>{o.count}</td>
                  <td style={{ color: o.severity === "high" ? "var(--danger)" : "var(--text-dim)" }}>{o.severity}</td>
                  <td className="faint">{o.details}</td>
                </tr>
              ))}
            </tbody></table>
          </>
        )}

        {s.activeTab === "cfg" && (
          <>
            <button className="row-action" disabled={s.busy} onClick={() => void s.runCfg()} style={{ marginBottom: "var(--pad-md)" }}>Build CFG</button>
            <table className="table"><thead><tr><th>Address</th><th>Size</th><th>Label</th><th>Successors</th></tr></thead><tbody>
              {s.cfg.map((n, i) => <tr key={i}><td className="mono">{n.addr}</td><td>{n.size}</td><td>{n.label}</td><td className="mono faint">{n.succs.join(", ")}</td></tr>)}
            </tbody></table>
          </>
        )}
      </div>
    </div>
  );
}
