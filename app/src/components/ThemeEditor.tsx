// app/src/components/ThemeEditor.tsx
// Custom theme editor beyond the 3 presets

import { useState } from "react";
import { kThemes, useTheme } from "@/store/theme";

const kTokens = [
  { key: "--bg-0", label: "Background" },
  { key: "--bg-1", label: "Surface" },
  { key: "--bg-2", label: "Elevated" },
  { key: "--text", label: "Text" },
  { key: "--text-dim", label: "Text Dim" },
  { key: "--text-faint", label: "Text Faint" },
  { key: "--accent", label: "Accent" },
  { key: "--border", label: "Border" },
  { key: "--border-soft", label: "Border Soft" },
  { key: "--danger", label: "Danger" },
  { key: "--warning", label: "Warning" },
  { key: "--success", label: "Success" },
] as const;

type Props = { onClose: () => void };

export default function ThemeEditor({ onClose }: Props) {
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);

  // Read current computed values as starting points
  const [overrides, setOverrides] = useState<Record<string, string>>(() => {
    const style = getComputedStyle(document.documentElement);
    const out: Record<string, string> = {};
    for (const t of kTokens) {
      out[t.key] = style.getPropertyValue(t.key).trim();
    }
    return out;
  });



  const updateToken = (key: string, value: string) => {
    setOverrides((prev) => ({ ...prev, [key]: value }));
    document.documentElement.style.setProperty(key, value);
  };

  const reset = () => {
    for (const t of kTokens) {
      document.documentElement.style.removeProperty(t.key);
    }
    // Re-read computed
    const style = getComputedStyle(document.documentElement);
    const out: Record<string, string> = {};
    for (const t of kTokens) out[t.key] = style.getPropertyValue(t.key).trim();
    setOverrides(out);
  };

  const exportCss = () => {
    const lines = [`:root {`];
    for (const [key, val] of Object.entries(overrides)) {
      lines.push(`  ${key}: ${val};`);
    }
    lines.push("}");
    void navigator.clipboard.writeText(lines.join("\n"));
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: "min(500px, 88vw)" }}>
        <div className="panel-head">
          <span className="panel-title">Theme Editor</span>
          <div className="spacer" />
          <button className="icon-button" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div className="settings-group">
            <div className="settings-label">Base Theme</div>
            <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
              {kThemes.map((t) => (
                <button key={t.id} className="row-action" data-active={theme === t.id}
                  onClick={() => { setTheme(t.id); setTimeout(reset, 50); }}>{t.label}</button>
              ))}
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-label">Color Tokens</div>
            {kTokens.map((t) => (
              <div key={t.key} style={{ display: "flex", alignItems: "center", gap: "var(--pad-sm)", marginBottom: 4 }}>
                <input
                  type="color"
                  value={overrides[t.key] || "#000000"}
                  onChange={(e) => updateToken(t.key, e.target.value)}
                  style={{ width: 28, height: 22, padding: 0, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", cursor: "pointer" }}
                />
                <span style={{ fontSize: "var(--type-small)", width: 100 }}>{t.label}</span>
                <input className="addr-input" value={overrides[t.key] || ""} onChange={(e) => updateToken(t.key, e.target.value)}
                  style={{ flex: 1, fontSize: 11 }} />
              </div>
            ))}
          </div>

          <div style={{ display: "flex", gap: "var(--pad-sm)", marginTop: "var(--pad-md)" }}>
            <button className="row-action" onClick={exportCss}>Copy CSS</button>
            <button className="row-action" onClick={reset}>Reset</button>
          </div>
        </div>
      </div>
    </div>
  );
}
