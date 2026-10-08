// app/src/components/panels/ScriptsPanel.tsx
// Lua scratchpad with syntax-highlighted overlay, line numbers, and Tab support

import { useCallback, useRef, useState } from "react";
import { Play, RotateCcw, Trash2 } from "lucide-react";
import { call } from "@/lib/rpc";

const kSample = `-- engine Lua: the bindings the script tool exposes
local st = slop.target.status()
print("backend:", st.backend)
print("attached:", st.attached, st.name or "", st.pid or 0)
for _, p in ipairs(slop.target.list()) do
  if p.name:find("chrome") then print(p.pid, p.name, p.arch) end
end
`;

const kKeywords = /\b(and|break|do|else|elseif|end|false|for|function|goto|if|in|local|nil|not|or|repeat|return|then|true|until|while)\b/g;
const kBuiltins = /\b(print|pairs|ipairs|tostring|tonumber|type|require|error|assert|pcall|xpcall|next|select|unpack|table|string|math|io|os|slop)\b/g;
const kNumbers = /\b(0x[0-9a-fA-F]+|\d+\.?\d*(?:e[+-]?\d+)?)\b/g;
const kStrings = /(["'])(?:(?=(\\?))\2.)*?\1/g;
const kComments = /--.*$/gm;

function highlightLua(code: string): string {
  // Order matters: comments last override prior matches in the HTML
  let html = code
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(kStrings, '<span style="color:var(--success)">$&</span>')
    .replace(kNumbers, '<span style="color:var(--warning)">$&</span>')
    .replace(kKeywords, '<span style="color:#c586c0">$&</span>')
    .replace(kBuiltins, '<span style="color:#dcdcaa">$&</span>')
    .replace(kComments, '<span style="color:var(--text-faint)">$&</span>');
  return html;
}

type Run = { ok: boolean; output: string; error?: string; ms: number };

export default function ScriptsPanel() {
  const [code, setCode] = useState(kSample);
  const [runs, setRuns] = useState<Run[]>([]);
  const [busy, setBusy] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const run = async () => {
    setBusy(true);
    const started = Date.now();
    try {
      const res = await call<{ ok: boolean; output: string; error?: string }>("script", "run", {
        code, timeout_ms: 10000,
      });
      setRuns((r) => [...r.slice(-19), { ...res, ms: Date.now() - started }]);
    } catch (e) {
      setRuns((r) => [
        ...r.slice(-19),
        { ok: false, output: "", error: e instanceof Error ? e.message : String(e), ms: Date.now() - started },
      ]);
    } finally {
      setBusy(false);
    }
  };

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      void run();
      return;
    }
    // Tab inserts 2 spaces instead of moving focus
    if (e.key === "Tab") {
      e.preventDefault();
      const ta = e.currentTarget;
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      const newCode = code.substring(0, start) + "  " + code.substring(end);
      setCode(newCode);
      requestAnimationFrame(() => { ta.selectionStart = ta.selectionEnd = start + 2; });
    }
  }, [code]);

  const lineCount = code.split("\n").length;
  const lineNums = Array.from({ length: lineCount }, (_, i) => i + 1);

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Scripts</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: 11 }}>{lineCount} lines</span>
        <button className="icon-button" data-tip="Clear output" onClick={() => setRuns([])}>
          <Trash2 size={14} />
        </button>
        <button className="icon-button" data-tip="Reset" onClick={() => setCode(kSample)}>
          <RotateCcw size={14} />
        </button>
        <button className="icon-button" data-tip="Run (Ctrl+Enter)" disabled={busy} onClick={() => void run()}>
          <Play size={14} />
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateRows: "1fr auto 1fr", minHeight: 0 }}>
        <div style={{ position: "relative", overflow: "auto", minHeight: 0 }}>
          {/* Line numbers */}
          <div style={{
            position: "absolute", left: 0, top: 0, width: 36, padding: "var(--pad-sm) 4px",
            textAlign: "right", fontSize: "var(--type-mono)", lineHeight: 1.5,
            color: "var(--text-faint)", userSelect: "none", fontFamily: "var(--font-mono)",
          }}>
            {lineNums.map((n) => <div key={n}>{n}</div>)}
          </div>

          {/* Highlighted overlay */}
          <pre
            aria-hidden
            style={{
              position: "absolute", left: 36, top: 0, right: 0,
              margin: 0, padding: "var(--pad-sm) var(--pad-md)",
              fontSize: "var(--type-mono)", lineHeight: 1.5, fontFamily: "var(--font-mono)",
              whiteSpace: "pre-wrap", wordBreak: "break-word", pointerEvents: "none",
              color: "var(--text)",
            }}
            dangerouslySetInnerHTML={{ __html: highlightLua(code) + "\n" }}
          />

          {/* Actual textarea (transparent text) */}
          <textarea
            ref={textareaRef}
            className="code-area mono"
            value={code}
            spellCheck={false}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{
              position: "relative", marginLeft: 36, width: "calc(100% - 36px)",
              color: "transparent", caretColor: "var(--accent)",
              background: "transparent", resize: "none",
            }}
          />
        </div>

        <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
          Output
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }}>{runs.length} runs</span>
        </div>
        <div className="panel-body log">
          {runs.length === 0 ? (
            <div className="empty-hint">Ctrl+Enter to run.</div>
          ) : (
            runs.map((r, i) => (
              <div key={i} style={{ marginBottom: "var(--pad-sm)" }}>
                <div className="log-row faint">
                  <span>{r.ok ? "✓ ok" : "✗ error"}</span>
                  <span>{r.ms}ms</span>
                </div>
                {r.output !== "" && <div className="log-row">{r.output}</div>}
                {r.error !== undefined && r.error !== "" && (
                  <div className="log-row" style={{ color: "var(--danger)" }}>{r.error}</div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
