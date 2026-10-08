// app/src/components/panels/KernelPanel.tsx
// Left-rail panel: driver status, kernel modules, detections, injection, anti-debug

import { useEffect, useState } from "react";
import { Cpu, Eye, RefreshCw, Shield, Syringe } from "lucide-react";
import { useDriver } from "@/store/driver";
import { useInject } from "@/store/inject";
import { useEngine } from "@/store/engine";

const kTabs = [
  { id: "status", label: "Status" },
  { id: "modules", label: "Modules" },
  { id: "detect", label: "Detect" },
  { id: "inject", label: "Inject" },
  { id: "stealth", label: "Stealth" },
] as const;

function StatusTab() {
  const { status, refreshStatus } = useDriver();
  const backend = useEngine((s) => s.backend);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div className="settings-group">
        <div className="settings-label">Backend</div>
        <div className="settings-rows mono">
          <div>badge: {backend.badge}</div>
          <div>kernel: {backend.kernel ? "yes" : "no"}</div>
          <div>device: {status?.device ?? "n/a"}</div>
          <div>bridge: {status?.kernel_active ? "loaded" : "not loaded"}</div>
          <div>hwbp: {status?.hwbp_supported ? "supported" : "unsupported"}</div>
        </div>
      </div>
      <div className="settings-group">
        <div className="settings-label">Backend Preference</div>
        <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
          {["auto", "kernel", "user"].map((p) => (
            <button key={p} className="row-action" data-active={status?.preference === p}
              onClick={() => void useDriver.getState().setBackend(p)}>{p}</button>
          ))}
        </div>
      </div>
    </div>
  );
}

function ModulesTab() {
  const { modules, refreshModules, busy } = useDriver();
  const [filter, setFilter] = useState("");

  useEffect(() => { void refreshModules(); }, [refreshModules]);

  const filtered = filter
    ? modules.filter((m) => m.name.toLowerCase().includes(filter.toLowerCase()) || m.path.toLowerCase().includes(filter.toLowerCase()))
    : modules;

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0, height: "100%" }}>
      <div className="view-bar">
        <input className="addr-input" placeholder="filter..." value={filter} onChange={(e) => setFilter(e.target.value)} style={{ flex: 1 }} />
        <button className="icon-button" data-tip="Refresh" onClick={() => void refreshModules()}>
          <RefreshCw size={12} className={busy ? "spin" : undefined} />
        </button>
        <span className="faint" style={{ fontSize: 11 }}>{filtered.length} modules</span>
      </div>
      <div className="panel-body" style={{ overflow: "auto" }}>
        <table className="table">
          <thead><tr><th>Base</th><th>Size</th><th>Name</th><th>Path</th></tr></thead>
          <tbody>
            {filtered.map((m, i) => (
              <tr key={i}>
                <td className="mono">{m.base}</td>
                <td>{(m.size / 1024).toFixed(0)} KB</td>
                <td>{m.name}</td>
                <td className="faint" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>{m.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DetectTab() {
  const { detections, hiddenModules, minifilters, etwSessions, kernelCallbacks, busy } = useDriver();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)", flexWrap: "wrap" }}>
        <button className="row-action" disabled={busy} onClick={() => void hiddenModules()}>
          <Eye size={11} style={{ marginRight: 4 }} />Hidden Modules
        </button>
        <button className="row-action" disabled={busy} onClick={() => void minifilters()}>
          <Shield size={11} style={{ marginRight: 4 }} />Minifilters
        </button>
        <button className="row-action" disabled={busy} onClick={() => void etwSessions()}>
          <Cpu size={11} style={{ marginRight: 4 }} />ETW Sessions
        </button>
        <button className="row-action" disabled={busy} onClick={() => void kernelCallbacks()}>
          <Shield size={11} style={{ marginRight: 4 }} />Kernel Callbacks
        </button>
        {busy && <RefreshCw size={12} className="spin" style={{ color: "var(--accent)" }} />}
      </div>
      {detections.length > 0 && (
        <table className="table">
          <thead><tr><th>Type</th><th>Name</th><th>Address</th><th>Details</th></tr></thead>
          <tbody>
            {detections.map((d, i) => (
              <tr key={i}>
                <td><span className="pill">{d.type}</span></td>
                <td>{d.name}</td>
                <td className="mono">{d.address}</td>
                <td className="faint">{d.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {detections.length === 0 && !busy && (
        <div className="faint" style={{ textAlign: "center", marginTop: "var(--pad-lg)" }}>
          Run a detection scan to find hidden kernel artifacts.
        </div>
      )}
    </div>
  );
}

function InjectTab() {
  const [dllPath, setDllPath] = useState("");
  const { status, refreshStatus, loadLibrary, manualMap, unload, busy, error } = useInject();

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div className="settings-group">
        <div className="settings-label">DLL Injection</div>
        <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-sm)" }}>
          <input className="addr-input" placeholder="DLL path..." value={dllPath} onChange={(e) => setDllPath(e.target.value)} style={{ flex: 1 }} />
        </div>
        <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
          <button className="row-action" disabled={busy || !dllPath} onClick={() => void loadLibrary(dllPath)}>
            <Syringe size={11} style={{ marginRight: 4 }} />LoadLibrary
          </button>
          <button className="row-action" disabled={busy || !dllPath} onClick={() => void manualMap(dllPath)}>
            <Syringe size={11} style={{ marginRight: 4 }} />Manual Map
          </button>
          {status?.injected && (
            <button className="row-action" onClick={() => void unload()}>Unload</button>
          )}
        </div>
        {error && <div className="settings-status" style={{ marginTop: "var(--pad-sm)" }}>{error}</div>}
        {status && (
          <div className="settings-rows mono" style={{ marginTop: "var(--pad-sm)" }}>
            <div>injected: {status.injected ? "yes" : "no"}</div>
            {status.injected && <div>module: {status.module}</div>}
            {status.injected && <div>base: {status.base}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

function StealthTab() {
  const { antiDebugSpoof, sandboxProtect, sandboxUnprotect } = useDriver();
  const [log, setLog] = useState<string[]>([]);

  const run = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
      setLog((prev) => [...prev, `✓ ${name} applied`]);
    } catch (e: unknown) {
      setLog((prev) => [...prev, `✗ ${name}: ${(e as Error).message}`]);
    }
  };

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div className="settings-group">
        <div className="settings-label">Stealth Operations</div>
        <div style={{ display: "flex", gap: "var(--pad-sm)", flexWrap: "wrap" }}>
          <button className="row-action" onClick={() => void run("Anti-Debug Spoof", antiDebugSpoof)}>Anti-Debug Spoof</button>
          <button className="row-action" onClick={() => void run("Sandbox Protect", sandboxProtect)}>Sandbox Protect</button>
          <button className="row-action" onClick={() => void run("Sandbox Unprotect", sandboxUnprotect)}>Sandbox Unprotect</button>
        </div>
      </div>
      {log.length > 0 && (
        <div className="log" style={{ marginTop: "var(--pad-md)" }}>
          {log.map((l, i) => <div key={i} className="log-row">{l}</div>)}
        </div>
      )}
    </div>
  );
}

export default function KernelPanel() {
  const [tab, setTab] = useState<typeof kTabs[number]["id"]>("status");
  const { error } = useDriver();

  const body = () => {
    switch (tab) {
      case "status": return <StatusTab />;
      case "modules": return <ModulesTab />;
      case "detect": return <DetectTab />;
      case "inject": return <InjectTab />;
      case "stealth": return <StealthTab />;
      default: return null;
    }
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Kernel</span>
        <div className="spacer" />
      </div>
      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0 }}>
        <div className="tabs">
          {kTabs.map((t) => (
            <button key={t.id} className="tab" data-active={tab === t.id} onClick={() => setTab(t.id)}>{t.label}</button>
          ))}
        </div>
        <div className="panel-body">
          {error && <div className="settings-status">{error}</div>}
          {body()}
        </div>
      </div>
    </div>
  );
}
