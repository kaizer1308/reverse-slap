// app/src/components/panels/ScannerPanel.tsx
// scanner config, results and watchlist, a scan started here is the scan an
// agent sees over mcp

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Eye, Plus, RotateCcw, Search, Snowflake, X } from "lucide-react";
import { hex } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { kFirstKinds, kNextKinds, kWidths, useScanner } from "@/store/scanner";
import { useWatch } from "@/store/watch";

const kRow = 19;

export default function ScannerPanel() {
  const attached = useEngine((s) => s.target.attached);
  const scanner = useScanner();
  const { entries, values, load, add, remove, setFreeze, clear } = useWatch();
  const [editing, setEditing] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void load();
    void scanner.refreshState();
    // Intentionally once on mount: both reads are engine-state seeds, and the
    // watch list keeps itself current from `watch.list` events afterwards
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const virtualizer = useVirtualizer({
    count: scanner.hits.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 15,
  });

  const kinds = scanner.hasState ? kNextKinds : kFirstKinds;
  const needsValue = scanner.kind !== "unknown";

  return (
    <div className="panel">
      <div className="panel-head" style={{ gap: "var(--pad-xs)", flexWrap: "wrap", height: "auto", padding: "var(--pad-sm)" }}>
        <select
          className="select"
          value={scanner.width}
          onChange={(e) => scanner.set({ width: e.target.value })}
        >
          {kWidths.map((w) => (
            <option key={w} value={w}>{w}</option>
          ))}
        </select>
        <select
          className="select"
          value={kinds.includes(scanner.kind as never) ? scanner.kind : kinds[0]}
          onChange={(e) => scanner.set({ kind: e.target.value })}
        >
          {kinds.map((k) => (
            <option key={k} value={k}>{k}</option>
          ))}
        </select>
        {needsValue && (
          <input
            className="addr-input mono"
            style={{ width: 76 }}
            value={scanner.value}
            placeholder="value"
            onChange={(e) => scanner.set({ value: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && void scanner.scan(scanner.hasState)}
          />
        )}
        {scanner.kind === "between" && (
          <input
            className="addr-input mono"
            style={{ width: 76 }}
            value={scanner.value2}
            placeholder="to"
            onChange={(e) => scanner.set({ value2: e.target.value })}
          />
        )}
        <button
          className="row-action"
          disabled={!attached || scanner.busy}
          onClick={() => void scanner.scan(scanner.hasState)}
        >
          <Search size={11} /> {scanner.hasState ? "Next" : "First"}
        </button>
        {scanner.hasState && (
          <button className="icon-button" data-tip="Reset scan" onClick={() => void scanner.reset()}>
            <RotateCcw size={13} />
          </button>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateRows: "auto minmax(0, 1fr) auto minmax(0, 1fr)", minHeight: 0 }}>
        <div className="dbg-head">
          Results
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }}>
            {scanner.busy ? "scanning…" : `${scanner.total}`}
          </span>
        </div>

        <div className="panel-body" ref={scrollRef}>
          {scanner.error !== null && (
            <div className="empty-hint" style={{ padding: "var(--pad-sm) var(--pad-md)", color: "var(--danger)" }}>
              {scanner.error}
            </div>
          )}
          {!attached ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>attach a target first.</div>
          ) : scanner.hits.length === 0 ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              {scanner.busy ? "" : "no results yet, run a scan."}
            </div>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((v) => {
                const h = scanner.hits[v.index];
                return (
                  <div key={h.addr} className="hex-row mono" style={{ top: v.start, height: kRow, fontSize: 11.5 }}>
                    <span className="insn-va">{hex(h.addr, 12)}</span>
                    <span className="insn-text">{h.formatted}</span>
                    <span className="faint">{h.type}</span>
                    <button
                      className="icon-button"
                      data-tip="Add to watchlist"
                      onClick={() => void add(h.addr, h.type)}
                    >
                      <Eye size={11} />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
          Watchlist
          <div className="spacer" />
          <button
            className="icon-button"
            data-tip="Add address"
            disabled={!attached}
            onClick={() => {
              const typed = window.prompt("Address (hex)");
              const parsed = typed === null ? NaN : Number.parseInt(typed.replace(/^0x/i, ""), 16);
              if (Number.isFinite(parsed)) void add(parsed, scanner.width);
            }}
          >
            <Plus size={13} />
          </button>
          {entries.length > 0 && (
            <button className="icon-button" data-tip="Clear all" onClick={() => void clear()}>
              <X size={13} />
            </button>
          )}
        </div>

        <div className="panel-body">
          {entries.length === 0 ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              {attached ? "no watches." : "no target."}
            </div>
          ) : (
            <table className="table">
              <tbody>
                {entries.map((e) => {
                  const v = values.get(e.id);
                  return (
                    <tr key={e.id} data-tip={e.label}>
                      <td className="mono" style={{ width: 96 }}>{hex(e.addr, 12)}</td>
                      <td className="faint" style={{ width: 32 }}>{e.width}</td>
                      <td className="mono" onDoubleClick={() => setEditing(e.id)}>
                        {editing === e.id ? (
                          <input
                            className="addr-input mono"
                            style={{ width: 70 }}
                            autoFocus
                            defaultValue={v?.text ?? ""}
                            onBlur={() => setEditing(null)}
                            onKeyDown={(e2) => {
                              if (e2.key === "Enter") {
                                void useWatch.getState().poke(e.id, e2.currentTarget.value);
                                setEditing(null);
                              }
                              if (e2.key === "Escape") setEditing(null);
                            }}
                          />
                        ) : (
                          <>
                            {v?.ok === true ? v.text : "-"}
                            {e.freeze && <span className="faint"> *</span>}
                          </>
                        )}
                      </td>
                      <td style={{ width: 26 }}>
                        <button
                          className="icon-button"
                          data-tip={e.freeze ? "Unfreeze" : "Freeze"}
                          style={{ color: e.freeze ? "var(--accent)" : undefined }}
                          onClick={() => void setFreeze(e.id, !e.freeze)}
                        >
                          <Snowflake size={11} />
                        </button>
                      </td>
                      <td style={{ width: 24 }}>
                        <button className="icon-button" data-tip="Remove" onClick={() => void remove(e.id)}>
                          <X size={11} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
