// app/src/components/panels/PatchView2.tsx
// Patching workspace tab: NOP junk, opaque predicates, anti-debug, XOR unpack, journal

import { useEffect } from "react";
import { RefreshCw } from "lucide-react";
import { usePatch } from "@/store/patch";

export default function PatchView2() {
  const { patches, journal, busy, error, dryRun, setDryRun,
    nopJunk, resolveOpaque, patchAntidebug, unpackXor, decodeStrings,
    fullPass, revertAll, rebuild, refreshJournal } = usePatch();

  useEffect(() => { void refreshJournal(); }, [refreshJournal]);

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label">Patch Engine</div>
        <div className="spacer" />
        <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-dim)" }}>
          <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> dry run
        </label>
        {busy && <RefreshCw size={12} className="spin" style={{ color: "var(--accent)" }} />}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

        <div style={{ display: "flex", gap: "var(--pad-sm)", flexWrap: "wrap", marginBottom: "var(--pad-lg)" }}>
          <button className="row-action" disabled={busy} onClick={() => void nopJunk()}>NOP Junk</button>
          <button className="row-action" disabled={busy} onClick={() => void resolveOpaque()}>Resolve Opaque</button>
          <button className="row-action" disabled={busy} onClick={() => void patchAntidebug()}>Patch Anti-Debug</button>
          <button className="row-action" disabled={busy} onClick={() => void unpackXor()}>Unpack XOR</button>
          <button className="row-action" disabled={busy} onClick={() => void decodeStrings()}>Decode Strings</button>
          <button className="row-action" disabled={busy} onClick={() => void fullPass()}>Full Pass</button>
          <button className="row-action" disabled={busy} onClick={() => void rebuild()}>Rebuild PE</button>
          <button className="row-action" onClick={() => void revertAll()} style={{ color: "var(--danger)" }}>Revert All</button>
        </div>

        {patches.length > 0 && (
          <>
            <div className="settings-label">Results ({patches.length} patches{dryRun ? " — dry run" : ""})</div>
            <table className="table" style={{ marginBottom: "var(--pad-lg)" }}>
              <thead><tr><th>Address</th><th>Original</th><th>Patched</th><th>Description</th></tr></thead>
              <tbody>
                {patches.map((p, i) => (
                  <tr key={i}>
                    <td className="mono">{p.address}</td>
                    <td className="mono faint">{p.original_hex}</td>
                    <td className="mono">{p.patched_hex}</td>
                    <td>{p.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {journal.length > 0 && (
          <>
            <div className="settings-label">Patch Journal</div>
            <table className="table">
              <thead><tr><th>Time</th><th>Type</th><th>Address</th><th>Original</th><th>Patched</th></tr></thead>
              <tbody>
                {journal.map((j) => (
                  <tr key={j.id}>
                    <td className="faint" style={{ fontSize: 11 }}>{j.ts}</td>
                    <td><span className="pill">{j.type}</span></td>
                    <td className="mono">{j.address}</td>
                    <td className="mono faint">{j.original}</td>
                    <td className="mono">{j.patched}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
