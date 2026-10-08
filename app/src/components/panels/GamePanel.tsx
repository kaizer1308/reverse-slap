// app/src/components/panels/GamePanel.tsx
// Left-rail panel: AOB generator, crypto scan, exploit finder, overlay, position/speed, code caves

import { useState } from "react";
import { Crosshair, Eye, FileCode, Gauge, Globe, Map, RefreshCw, Search, Shield, Zap } from "lucide-react";
import { useGame } from "@/store/game";
import { useEngine } from "@/store/engine";

const kTabs = [
  { id: "aob", label: "AOB", Icon: Search },
  { id: "crypto", label: "Crypto", Icon: Shield },
  { id: "map", label: "Map", Icon: Map },
  { id: "exploits", label: "Exploits", Icon: Zap },
  { id: "caves", label: "Caves", Icon: FileCode },
  { id: "position", label: "Position", Icon: Crosshair },
  { id: "speed", label: "Speed", Icon: Gauge },
  { id: "server", label: "Server", Icon: Globe },
  { id: "overlay", label: "Overlay", Icon: Eye },
] as const;

function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="settings-status">{error}</div>;
}

function AobTab() {
  const [addr, setAddr] = useState("");
  const [len, setLen] = useState("32");
  const { aobResults, aobGenerate, busy } = useGame();

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <input className="addr-input" placeholder="address" value={addr} onChange={(e) => setAddr(e.target.value)} style={{ flex: 1 }} />
        <input className="addr-input" placeholder="len" value={len} onChange={(e) => setLen(e.target.value)} style={{ width: 60 }} />
        <button className="row-action" disabled={busy} onClick={() => void aobGenerate(addr, parseInt(len) || 32)}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Generate"}
        </button>
      </div>
      {aobResults.length > 0 && (
        <table className="table">
          <thead><tr><th>Label</th><th>Pattern</th><th>Unique</th></tr></thead>
          <tbody>
            {aobResults.map((r, i) => (
              <tr key={i}><td>{r.label}</td><td className="mono">{r.pattern}</td><td>{r.unique ? "✓" : "✗"}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CryptoTab() {
  const { cryptoHits, cryptoScan, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <button className="row-action" disabled={busy} onClick={() => void cryptoScan()}>
        {busy ? <RefreshCw size={11} className="spin" /> : "Scan for Crypto Constants"}
      </button>
      {cryptoHits.length > 0 && (
        <table className="table" style={{ marginTop: "var(--pad-md)" }}>
          <thead><tr><th>Address</th><th>Type</th><th>Size</th><th>Entropy</th></tr></thead>
          <tbody>
            {cryptoHits.map((h, i) => (
              <tr key={i}><td className="mono">{h.address}</td><td>{h.type}</td><td>{h.size}</td><td>{h.entropy.toFixed(2)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function MapTab() {
  const { mapBlocks, binaryMap, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <button className="row-action" disabled={busy} onClick={() => void binaryMap()}>
        {busy ? <RefreshCw size={11} className="spin" /> : "Generate Binary Map"}
      </button>
      {mapBlocks.length > 0 && (
        <table className="table" style={{ marginTop: "var(--pad-md)" }}>
          <thead><tr><th>Base</th><th>Size</th><th>Type</th><th>Label</th><th>Entropy</th></tr></thead>
          <tbody>
            {mapBlocks.map((b, i) => (
              <tr key={i}><td className="mono">{b.base}</td><td>{b.size}</td><td><span className="pill">{b.type}</span></td><td>{b.label}</td><td>{b.entropy.toFixed(2)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ExploitsTab() {
  const { exploits, findExploit, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        {["all", "ammo", "health", "currency", "cooldown", "speed"].map((t) => (
          <button key={t} className="row-action" disabled={busy} onClick={() => void findExploit(t === "all" ? undefined : t)}>{t}</button>
        ))}
      </div>
      {exploits.length > 0 && (
        <table className="table">
          <thead><tr><th>Type</th><th>Address</th><th>Severity</th><th>Description</th></tr></thead>
          <tbody>
            {exploits.map((e, i) => (
              <tr key={i}>
                <td><span className="pill">{e.type}</span></td>
                <td className="mono">{e.address}</td>
                <td style={{ color: e.severity === "critical" ? "var(--danger)" : e.severity === "high" ? "var(--warning)" : "var(--text-dim)" }}>{e.severity}</td>
                <td>{e.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CavesTab() {
  const [minSize, setMinSize] = useState("64");
  const { caves, findCodeCaves, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <input className="addr-input" placeholder="min size" value={minSize} onChange={(e) => setMinSize(e.target.value)} style={{ width: 80 }} />
        <button className="row-action" disabled={busy} onClick={() => void findCodeCaves(parseInt(minSize) || 64)}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Find Caves"}
        </button>
      </div>
      {caves.length > 0 && (
        <table className="table">
          <thead><tr><th>Address</th><th>Size</th><th>Module</th><th>Permissions</th></tr></thead>
          <tbody>
            {caves.map((c, i) => (
              <tr key={i}><td className="mono">{c.address}</td><td>{c.size}</td><td>{c.module}</td><td className="mono">{c.permissions}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function PositionTab() {
  const { positions, findPosition, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <button className="row-action" disabled={busy} onClick={() => void findPosition()}>
        {busy ? <RefreshCw size={11} className="spin" /> : "Find Player Position"}
      </button>
      {positions.length > 0 && (
        <table className="table" style={{ marginTop: "var(--pad-md)" }}>
          <thead><tr><th>Address</th><th>X</th><th>Y</th><th>Z</th><th>Confidence</th></tr></thead>
          <tbody>
            {positions.map((p, i) => (
              <tr key={i}><td className="mono">{p.address}</td><td>{p.x.toFixed(1)}</td><td>{p.y.toFixed(1)}</td><td>{p.z.toFixed(1)}</td><td>{(p.confidence * 100).toFixed(0)}%</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function SpeedTab() {
  const { speeds, findSpeed, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <button className="row-action" disabled={busy} onClick={() => void findSpeed()}>
        {busy ? <RefreshCw size={11} className="spin" /> : "Find Speed Values"}
      </button>
      {speeds.length > 0 && (
        <table className="table" style={{ marginTop: "var(--pad-md)" }}>
          <thead><tr><th>Address</th><th>Value</th><th>Type</th><th>Confidence</th></tr></thead>
          <tbody>
            {speeds.map((s, i) => (
              <tr key={i}><td className="mono">{s.address}</td><td>{s.value.toFixed(2)}</td><td>{s.type}</td><td>{(s.confidence * 100).toFixed(0)}%</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function ServerTab() {
  const { authority, testAuthority, busy } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <button className="row-action" disabled={busy} onClick={() => void testAuthority()}>
        {busy ? <RefreshCw size={11} className="spin" /> : "Test Authority"}
      </button>
      {authority.length > 0 && (
        <table className="table" style={{ marginTop: "var(--pad-md)" }}>
          <thead><tr><th>Field</th><th>Authority</th><th>Mutable</th><th>Details</th></tr></thead>
          <tbody>
            {authority.map((a, i) => (
              <tr key={i}>
                <td>{a.field}</td>
                <td><span className="pill">{a.authority}</span></td>
                <td>{a.mutable ? "✓" : "✗"}</td>
                <td className="faint">{a.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function OverlayTab() {
  const { overlayConnected, overlayConnect, overlayDisconnect, overlayClear } = useGame();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        {overlayConnected ? (
          <>
            <button className="row-action" onClick={() => void overlayDisconnect()}>Disconnect</button>
            <button className="row-action" onClick={() => void overlayClear()}>Clear</button>
          </>
        ) : (
          <button className="row-action" onClick={() => void overlayConnect()}>Connect to Discord Overlay</button>
        )}
      </div>
      <div className="faint" style={{ fontSize: "var(--type-small)" }}>
        Status: {overlayConnected ? "Connected" : "Disconnected"}
      </div>
    </div>
  );
}

export default function GamePanel() {
  const target = useEngine((s) => s.target);
  const { activeTab, setTab, error } = useGame();

  if (!target.attached) {
    return (
      <div className="panel">
        <div className="panel-head"><span className="panel-title">Game Tools</span></div>
        <div className="empty">
          <Crosshair size={28} strokeWidth={1.5} style={{ color: "var(--text-faint)" }} />
          <div className="empty-title">No target attached</div>
          <div className="empty-hint">Attach to a game process to use these tools.</div>
        </div>
      </div>
    );
  }

  const body = () => {
    switch (activeTab) {
      case "aob": return <AobTab />;
      case "crypto": return <CryptoTab />;
      case "map": return <MapTab />;
      case "exploits": return <ExploitsTab />;
      case "caves": return <CavesTab />;
      case "position": return <PositionTab />;
      case "speed": return <SpeedTab />;
      case "server": return <ServerTab />;
      case "overlay": return <OverlayTab />;
      default: return null;
    }
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Game Tools</span>
        <div className="spacer" />
      </div>
      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0 }}>
        <div className="tabs">
          {kTabs.map((t) => (
            <button key={t.id} className="tab" data-active={activeTab === t.id} onClick={() => setTab(t.id)} data-tip={t.label}>
              <t.Icon size={12} />
            </button>
          ))}
        </div>
        <div className="panel-body">
          <ErrorBanner error={error} />
          {body()}
        </div>
      </div>
    </div>
  );
}
