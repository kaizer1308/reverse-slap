// app/src/components/panels/FilesPanel.tsx
// File system browser for target or local disk via the `fs` MCP tool

import { useState } from "react";
import { File, Folder, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type FsEntry = { name: string; is_dir: boolean; size: number; modified: string };

export default function FilesPanel() {
  const [cwd, setCwd] = useState("C:\\");
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [content, setContent] = useState<string | null>(null);
  const [viewPath, setViewPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const browse = async (dir: string) => {
    setBusy(true); setError(null); setContent(null);
    try {
      const r = await call<{ entries: FsEntry[] }>("fs", "list_directory", { path: dir });
      setEntries(r.entries);
      setCwd(dir);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const readFile = async (path: string) => {
    setBusy(true); setError(null);
    try {
      const r = await call<{ text: string }>("fs", "read_file", { path, max_bytes: 65536 });
      setContent(r.text);
      setViewPath(path);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const goUp = () => {
    const parts = cwd.replace(/[\\/]+$/, "").split(/[\\/]/);
    if (parts.length > 1) {
      parts.pop();
      void browse(parts.join("\\") + "\\");
    }
  };

  const openEntry = (e: FsEntry) => {
    const full = cwd.replace(/[\\/]+$/, "") + "\\" + e.name;
    if (e.is_dir) void browse(full + "\\");
    else void readFile(full);
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Files</span>
        <div className="spacer" />
      </div>
      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0 }}>
        <div className="view-bar">
          <button className="row-action" onClick={goUp}>↑</button>
          <input className="addr-input" value={cwd} onChange={(e) => setCwd(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void browse(cwd); }}
            style={{ flex: 1 }} />
          <button className="icon-button" onClick={() => void browse(cwd)}>
            <RefreshCw size={12} className={busy ? "spin" : undefined} />
          </button>
        </div>
        {error && <div className="settings-status">{error}</div>}
        <div style={{ display: "grid", gridTemplateColumns: content ? "1fr 1fr" : "1fr", minHeight: 0 }}>
          <div className="panel-body" style={{ overflow: "auto", borderRight: content ? "1px solid var(--border-soft)" : undefined }}>
            <table className="table">
              <thead><tr><th></th><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.name} onClick={() => openEntry(e)} style={{ cursor: "pointer" }}>
                    <td style={{ width: 20 }}>{e.is_dir ? <Folder size={12} /> : <File size={12} />}</td>
                    <td>{e.name}</td>
                    <td className="faint">{e.is_dir ? "" : `${(e.size / 1024).toFixed(1)} KB`}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{e.modified}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {content !== null && (
            <div className="panel-body" style={{ overflow: "auto" }}>
              <div className="view-bar">
                <span className="mono faint" style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis" }}>{viewPath}</span>
                <div className="spacer" />
                <button className="icon-button" onClick={() => setContent(null)}>✕</button>
              </div>
              <pre className="code-area" style={{ height: "auto" }}>{content}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
