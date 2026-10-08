// app/src/components/panels/ProxyView.tsx
// HTTP intercept proxy with request/response viewer and replay

import { useEffect, useState } from "react";
import { Play, RefreshCw, RotateCcw, Square } from "lucide-react";
import { useProxy } from "@/store/proxy";

export default function ProxyView() {
  const { running, port, entries, selected, busy, error, start, stop, refreshStatus, refreshEntries, selectEntry, replay } = useProxy();
  const [portInput, setPortInput] = useState("8080");

  useEffect(() => { void refreshStatus(); void refreshEntries(); }, [refreshStatus, refreshEntries]);

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label">HTTP Proxy</div>
        {running ? (
          <button className="row-action" onClick={() => void stop()}><Square size={10} /> Stop</button>
        ) : (
          <>
            <input className="addr-input" value={portInput} onChange={(e) => setPortInput(e.target.value)} style={{ width: 60 }} placeholder="port" />
            <button className="row-action" onClick={() => void start(parseInt(portInput) || 8080)}><Play size={10} /> Start</button>
          </>
        )}
        <span className="faint" style={{ fontSize: 11 }}>{running ? `listening :${port}` : "stopped"}</span>
        <div className="spacer" />
        <button className="icon-button" onClick={() => void refreshEntries()}>
          <RefreshCw size={12} className={busy ? "spin" : undefined} />
        </button>
        <span className="faint" style={{ fontSize: 11 }}>{entries.length} requests</span>
      </div>
      {error && <div className="settings-status">{error}</div>}
      <div style={{ display: "grid", gridTemplateColumns: selected ? "1fr 1fr" : "1fr", minHeight: 0, height: "100%" }}>
        <div className="panel-body" style={{ overflow: "auto", borderRight: selected ? "1px solid var(--border-soft)" : undefined }}>
          <table className="table">
            <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Size</th></tr></thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} onClick={() => void selectEntry(e.id)} style={{ cursor: "pointer" }}
                  data-active={selected?.id === e.id}>
                  <td><span className="pill">{e.method}</span></td>
                  <td className="mono" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>{e.url}</td>
                  <td style={{ color: e.status >= 400 ? "var(--danger)" : e.status >= 300 ? "var(--warning)" : "var(--text)" }}>{e.status}</td>
                  <td className="faint">{e.content_type}</td>
                  <td>{e.size}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {selected && (
          <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              <span className="pill">{selected.method}</span>
              <span className="mono" style={{ fontSize: 11, flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{selected.url}</span>
              <button className="row-action" onClick={() => void replay(selected.id)}>
                <RotateCcw size={10} style={{ marginRight: 4 }} />Replay
              </button>
            </div>
            <div className="settings-label">Request Headers</div>
            <pre className="code-area" style={{ height: "auto", maxHeight: 120, marginBottom: "var(--pad-md)" }}>{selected.request_headers}</pre>
            {selected.request_body && (
              <>
                <div className="settings-label">Request Body</div>
                <pre className="code-area" style={{ height: "auto", maxHeight: 150, marginBottom: "var(--pad-md)" }}>{selected.request_body}</pre>
              </>
            )}
            <div className="settings-label">Response Headers</div>
            <pre className="code-area" style={{ height: "auto", maxHeight: 120, marginBottom: "var(--pad-md)" }}>{selected.response_headers}</pre>
            <div className="settings-label">Response Body</div>
            <pre className="code-area" style={{ height: "auto", maxHeight: 300 }}>{selected.response_body}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
