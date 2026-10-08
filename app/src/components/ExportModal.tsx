// app/src/components/ExportModal.tsx
// Export findings, patches, and analysis to Markdown report

import { useState } from "react";
import { Download } from "lucide-react";
import { call } from "@/lib/rpc";
import { useEngine } from "@/store/engine";

type Props = { onClose: () => void };

const kSections = [
  { id: "target", label: "Target Info", checked: true },
  { id: "functions", label: "Functions", checked: true },
  { id: "strings", label: "Strings", checked: false },
  { id: "imports", label: "Imports", checked: true },
  { id: "xrefs", label: "Cross References", checked: false },
  { id: "patches", label: "Applied Patches", checked: true },
  { id: "comments", label: "Comments & Bookmarks", checked: true },
  { id: "hooks", label: "Detected Hooks", checked: false },
  { id: "rtti", label: "RTTI Classes", checked: false },
  { id: "network", label: "Network Captures", checked: false },
  { id: "game", label: "Game Analysis Results", checked: false },
] as const;

export default function ExportModal({ onClose }: Props) {
  const [sections, setSections] = useState(() =>
    Object.fromEntries(kSections.map((s) => [s.id, s.checked]))
  );
  const [format, setFormat] = useState<"markdown" | "json">("markdown");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const target = useEngine((s) => s.target);

  const toggle = (id: string) =>
    setSections((prev) => ({ ...prev, [id]: !prev[id] }));

  const generate = async () => {
    setBusy(true);
    const enabled = Object.entries(sections).filter(([, v]) => v).map(([k]) => k);
    try {
      await call<{ report: string }>("persist", "save", {
        name: `report-${Date.now()}`,
        data: JSON.stringify({ format, sections: enabled, target: target.name }),
      });
      // Build report locally from available data
      const lines: string[] = [];
      lines.push(`# Reverse-Slop Analysis Report`);
      lines.push(`**Target:** ${target.name ?? "none"} (PID ${target.pid ?? "n/a"})`);
      lines.push(`**Date:** ${new Date().toISOString()}`);
      lines.push(`**Sections:** ${enabled.join(", ")}`);
      lines.push("");

      for (const sec of enabled) {
        lines.push(`## ${kSections.find((s) => s.id === sec)?.label ?? sec}`);
        try {
          if (sec === "functions") {
            const r = await call<{ functions: { addr: string; name: string }[] }>("disasm", "functions");
            r.functions.slice(0, 50).forEach((f) => lines.push(`- \`${f.addr}\` ${f.name}`));
            if (r.functions.length > 50) lines.push(`... +${r.functions.length - 50} more`);
          } else if (sec === "patches") {
            const r = await call<{ entries: { address: string; type: string; original: string; patched: string }[] }>("patch", "journal");
            r.entries.forEach((e) => lines.push(`- \`${e.address}\` [${e.type}] ${e.original} → ${e.patched}`));
          } else if (sec === "comments") {
            const r = await call<{ comments: { address: string; text: string }[] }>("notes", "comments");
            r.comments.forEach((c) => lines.push(`- \`${c.address}\`: ${c.text}`));
          } else {
            lines.push("*Data collection pending.*");
          }
        } catch {
          lines.push("*Not available.*");
        }
        lines.push("");
      }

      setResult(lines.join("\n"));
    } catch (e: unknown) {
      setResult(`Error: ${(e as Error).message}`);
    }
    setBusy(false);
  };

  const download = () => {
    if (!result) return;
    const blob = new Blob([result], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: "min(620px, 88vw)" }}>
        <div className="panel-head">
          <span className="panel-title">Export Report</span>
          <div className="spacer" />
          <button className="icon-button" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {!result ? (
            <>
              <div className="settings-group">
                <div className="settings-label">Format</div>
                <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
                  {(["markdown", "json"] as const).map((f) => (
                    <button key={f} className="row-action" data-active={format === f} onClick={() => setFormat(f)}>{f}</button>
                  ))}
                </div>
              </div>
              <div className="settings-group">
                <div className="settings-label">Sections</div>
                {kSections.map((s) => (
                  <label key={s.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", fontSize: "var(--type-small)" }}>
                    <input type="checkbox" checked={sections[s.id]} onChange={() => toggle(s.id)} />
                    {s.label}
                  </label>
                ))}
              </div>
              <button className="row-action" disabled={busy} onClick={() => void generate()} style={{ marginTop: "var(--pad-md)" }}>
                <Download size={11} style={{ marginRight: 4 }} />{busy ? "Generating..." : "Generate Report"}
              </button>
            </>
          ) : (
            <>
              <div style={{ display: "flex", gap: "var(--pad-sm)", marginBottom: "var(--pad-md)" }}>
                <button className="row-action" onClick={download}>
                  <Download size={11} style={{ marginRight: 4 }} />Download .md
                </button>
                <button className="row-action" onClick={() => { void navigator.clipboard.writeText(result); }}>Copy</button>
                <button className="row-action" onClick={() => setResult(null)}>Back</button>
              </div>
              <pre className="code-area" style={{ height: 400 }}>{result}</pre>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
