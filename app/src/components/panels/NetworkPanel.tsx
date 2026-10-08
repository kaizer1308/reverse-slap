// app/src/components/panels/NetworkPanel.tsx
// Left-rail panel: packet capture, connections, DNS, rules, bandwidth, interception

import { useEffect, useState } from "react";
import { Activity, Cable, Filter, Globe, Lock, Play, RefreshCw, Square, Wifi } from "lucide-react";
import { useNetwork } from "@/store/network";
import { useEngine } from "@/store/engine";

const kTabs = [
  { id: "capture", label: "Capture", Icon: Wifi },
  { id: "connections", label: "Connections", Icon: Cable },
  { id: "dns", label: "DNS", Icon: Globe },
  { id: "streams", label: "Streams", Icon: Activity },
  { id: "rules", label: "Rules", Icon: Filter },
  { id: "intercept", label: "Intercept", Icon: Lock },
] as const;

function CaptureTab() {
  const [filter, setFilter] = useState("");
  const { capturing, packets, captureStart, captureStop, refreshPackets, busy } = useNetwork();

  useEffect(() => { void refreshPackets(); }, [refreshPackets]);

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto auto 1fr", minHeight: 0, height: "100%" }}>
      <div className="view-bar">
        {capturing ? (
          <button className="row-action" onClick={() => void captureStop()}><Square size={10} /> Stop</button>
        ) : (
          <button className="row-action" onClick={() => void captureStart()}><Play size={10} /> Start</button>
        )}
        <input className="addr-input" placeholder="filter..." value={filter} onChange={(e) => setFilter(e.target.value)} style={{ flex: 1 }} />
        <button className="icon-button" data-tip="Refresh" onClick={() => void refreshPackets(200, filter || undefined)}>
          <RefreshCw size={12} className={busy ? "spin" : undefined} />
        </button>
        <span className="faint" style={{ fontSize: 11 }}>{packets.length} packets</span>
      </div>
      <div className="panel-body" style={{ overflow: "auto" }}>
        <table className="table">
          <thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead>
          <tbody>
            {packets.map((p) => (
              <tr key={p.id}>
                <td className="faint">{p.id}</td>
                <td className="mono" style={{ fontSize: 11 }}>{p.ts}</td>
                <td className="mono">{p.src}</td>
                <td className="mono">{p.dst}</td>
                <td><span className="pill">{p.protocol}</span></td>
                <td>{p.length}</td>
                <td className="faint" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ConnectionsTab() {
  const { connections, refreshConnections, busy } = useNetwork();
  const target = useEngine((s) => s.target);

  useEffect(() => { void refreshConnections(target.pid); }, [refreshConnections, target.pid]);

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <button className="row-action" disabled={busy} onClick={() => void refreshConnections(target.pid)}>
          {busy ? <RefreshCw size={11} className="spin" /> : "Refresh"}
        </button>
        <span className="faint" style={{ fontSize: 11 }}>{connections.length} connections</span>
      </div>
      <table className="table">
        <thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th><th>Module</th></tr></thead>
        <tbody>
          {connections.map((c, i) => (
            <tr key={i}>
              <td><span className="pill">{c.protocol}</span></td>
              <td className="mono">{c.local}</td>
              <td className="mono">{c.remote}</td>
              <td>{c.state}</td>
              <td>{c.pid}</td>
              <td className="faint">{c.module}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DnsTab() {
  const [domain, setDomain] = useState("");
  const [ip, setIp] = useState("");
  const { dns, refreshDns, addDnsSpoof, removeDnsSpoof } = useNetwork();

  useEffect(() => { void refreshDns(); }, [refreshDns]);

  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <input className="addr-input" placeholder="domain" value={domain} onChange={(e) => setDomain(e.target.value)} style={{ flex: 1 }} />
        <input className="addr-input" placeholder="spoof IP" value={ip} onChange={(e) => setIp(e.target.value)} style={{ width: 120 }} />
        <button className="row-action" onClick={() => { if (domain && ip) void addDnsSpoof(domain, ip); }}>Spoof</button>
      </div>
      <table className="table">
        <thead><tr><th>Domain</th><th>IP</th><th>TTL</th><th></th></tr></thead>
        <tbody>
          {dns.map((d, i) => (
            <tr key={i}>
              <td>{d.domain}</td><td className="mono">{d.ip}</td><td>{d.ttl}</td>
              <td><button className="row-action" onClick={() => void removeDnsSpoof(d.domain)}>✗</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StreamsTab() {
  const { streams, refreshStreams } = useNetwork();
  useEffect(() => { void refreshStreams(); }, [refreshStreams]);
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <table className="table">
        <thead><tr><th>ID</th><th>Source</th><th>Destination</th><th>Proto</th><th>Packets</th><th>Bytes</th></tr></thead>
        <tbody>
          {streams.map((s, i) => (
            <tr key={i}><td className="mono">{s.id}</td><td className="mono">{s.src}</td><td className="mono">{s.dst}</td><td><span className="pill">{s.protocol}</span></td><td>{s.packets}</td><td>{s.bytes}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RulesTab() {
  const { rules, clearRules } = useNetwork();
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <button className="row-action" onClick={() => void clearRules()}>Clear All Rules</button>
        <span className="faint" style={{ fontSize: 11 }}>{rules.length} rules</span>
      </div>
      <table className="table">
        <thead><tr><th>Action</th><th>Direction</th><th>Protocol</th><th>Port</th><th>PID</th></tr></thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}><td><span className="pill">{r.action}</span></td><td>{r.direction}</td><td>{r.protocol}</td><td>{r.port || "any"}</td><td>{r.pid || "any"}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InterceptTab() {
  const { intercepts, interceptStart, interceptStop, refreshIntercepts, interceptRelease } = useNetwork();
  useEffect(() => { void refreshIntercepts(); }, [refreshIntercepts]);
  return (
    <div style={{ padding: "var(--pad-md)" }}>
      <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
        <button className="row-action" onClick={() => void interceptStart()}>Start</button>
        <button className="row-action" onClick={() => void interceptStop()}>Stop</button>
        <button className="icon-button" onClick={() => void refreshIntercepts()}><RefreshCw size={12} /></button>
      </div>
      <table className="table">
        <thead><tr><th>#</th><th>Direction</th><th>Protocol</th><th>Payload</th><th></th></tr></thead>
        <tbody>
          {intercepts.map((e) => (
            <tr key={e.id}>
              <td>{e.id}</td><td>{e.direction}</td><td>{e.protocol}</td>
              <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{e.payload_hex}</td>
              <td><button className="row-action" onClick={() => void interceptRelease(e.payload_hex)}>Release</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function NetworkPanel() {
  const { activeTab, setTab, error } = useNetwork();

  const body = () => {
    switch (activeTab) {
      case "capture": return <CaptureTab />;
      case "connections": return <ConnectionsTab />;
      case "dns": return <DnsTab />;
      case "streams": return <StreamsTab />;
      case "rules": return <RulesTab />;
      case "intercept": return <InterceptTab />;
      default: return null;
    }
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Network</span>
        <div className="spacer" />
      </div>
      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0 }}>
        <div className="tabs">
          {kTabs.map((t) => (
            <button key={t.id} className="tab" data-active={activeTab === t.id} onClick={() => setTab(t.id)} data-tip={t.label}>
              <t.Icon size={12} style={{ marginRight: 4 }} />{t.label}
            </button>
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
