// app/src/components/panels/PersistView.tsx
// Session save/load and analysis export

import { useEffect, useState } from "react";
import { Download, RefreshCw, Save, Trash2, Upload } from "lucide-react";
import { usePersist } from "@/store/persist";

export default function PersistView() {
  const { sessions, busy, error, save, load, remove, refreshList, hypeSave, hypeLoad } = usePersist();
  const [name, setName] = useState("");

  useEffect(() => { void refreshList(); }, [refreshList]);

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label">Sessions</div>
        <div className="spacer" />
        <button className="icon-button" onClick={() => void refreshList()}>
          <RefreshCw size={12} className={busy ? "spin" : undefined} />
        </button>
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

        <div className="settings-group">
          <div className="settings-label">Save Session</div>
          <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
            <input className="addr-input" placeholder="session name..." value={name} onChange={(e) => setName(e.target.value)} style={{ flex: 1 }} />
            <button className="row-action" disabled={busy || !name.trim()} onClick={() => { void save(name); setName(""); }}>
              <Save size={11} style={{ marginRight: 4 }} />Save
            </button>
          </div>
        </div>

        <div className="settings-group">
          <div className="settings-label">Analysis Snapshots</div>
          <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
            <button className="row-action" disabled={busy} onClick={() => void hypeSave()}>
              <Download size={11} style={{ marginRight: 4 }} />Save Analysis
            </button>
            <button className="row-action" disabled={busy} onClick={() => void hypeLoad()}>
              <Upload size={11} style={{ marginRight: 4 }} />Load Analysis
            </button>
          </div>
        </div>

        <div className="settings-label">Saved Sessions ({sessions.length})</div>
        <table className="table">
          <thead><tr><th>Name</th><th>Date</th><th>Size</th><th></th></tr></thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.name}>
                <td>{s.name}</td>
                <td className="faint" style={{ fontSize: 11 }}>{s.ts}</td>
                <td className="faint">{(s.size / 1024).toFixed(0)} KB</td>
                <td style={{ display: "flex", gap: 4 }}>
                  <button className="row-action" onClick={() => void load(s.name)}>
                    <Upload size={10} style={{ marginRight: 2 }} />Load
                  </button>
                  <button className="row-action" onClick={() => void remove(s.name)} style={{ color: "var(--danger)" }}>
                    <Trash2 size={10} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
