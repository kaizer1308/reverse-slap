// app/src/components/panels/PluginPanel.tsx
// Plugin system: load custom JS panels that register via the MCP tool surface

import { useEffect, useState } from "react";
import { Package, RefreshCw } from "lucide-react";
import { call } from "@/lib/rpc";

type PluginInfo = { name: string; version: string; description: string; loaded: boolean; path: string };

export default function PluginPanel() {
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [log, setLog] = useState<string[]>([]);

  const refreshPlugins = async () => {
    setBusy(true);
    try {
      // List plugin scripts from the engine's plugin directory
      const r = await call<{ entries: { name: string; is_dir: boolean; size: number }[] }>(
        "fs", "list_directory", { path: "plugins" }
      );
      const found: PluginInfo[] = r.entries
        .filter((e) => e.name.endsWith(".lua") || e.name.endsWith(".js"))
        .map((e) => ({
          name: e.name.replace(/\.(lua|js)$/, ""),
          version: "1.0",
          description: `Plugin: ${e.name}`,
          loaded: false,
          path: `plugins/${e.name}`,
        }));
      setPlugins(found);
      setError(null);
    } catch (e: unknown) {
      // No plugins dir — show empty state
      setPlugins([]);
    }
    setBusy(false);
  };

  const loadPlugin = async (p: PluginInfo) => {
    try {
      const r = await call<{ text: string }>("fs", "read_file", { path: p.path });
      await call("script", "run", { code: r.text, timeout_ms: 30000 });
      setPlugins((prev) => prev.map((x) => x.name === p.name ? { ...x, loaded: true } : x));
      setLog((prev) => [...prev, `✓ Loaded ${p.name}`]);
    } catch (e: unknown) {
      setLog((prev) => [...prev, `✗ ${p.name}: ${(e as Error).message}`]);
    }
  };

  useEffect(() => { void refreshPlugins(); }, []);

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Plugins</span>
        <div className="spacer" />
        <button className="icon-button" data-tip="Refresh" onClick={() => void refreshPlugins()}>
          <RefreshCw size={14} className={busy ? "spin" : undefined} />
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateRows: "1fr auto", minHeight: 0 }}>
        <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
          {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

          {plugins.length > 0 ? (
            plugins.map((p) => (
              <div key={p.name} style={{
                display: "flex", alignItems: "center", gap: "var(--pad-sm)",
                padding: "var(--pad-sm) var(--pad-md)", marginBottom: 4,
                background: "var(--bg-0)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-soft)",
              }}>
                <Package size={14} style={{ color: p.loaded ? "var(--success)" : "var(--text-faint)" }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: "var(--type-small)", fontWeight: 500 }}>{p.name}</div>
                  <div className="faint" style={{ fontSize: 11 }}>{p.description}</div>
                </div>
                <span className="pill">{p.loaded ? "loaded" : "available"}</span>
                {!p.loaded && (
                  <button className="row-action" onClick={() => void loadPlugin(p)}>Load</button>
                )}
              </div>
            ))
          ) : (
            <div className="empty">
              <div className="empty-glyph"><Package size={28} strokeWidth={1.5} /></div>
              <div className="empty-title">No plugins found.</div>
              <div className="empty-hint">
                Place .lua or .js scripts in the <code className="mono">plugins/</code> directory next to the engine.
              </div>
            </div>
          )}
        </div>

        {log.length > 0 && (
          <div className="log" style={{ borderTop: "1px solid var(--border-soft)", maxHeight: 120, overflow: "auto" }}>
            {log.map((l, i) => <div key={i} className="log-row">{l}</div>)}
          </div>
        )}
      </div>
    </div>
  );
}
