// app/src/components/panels/MemoryView.tsx
// Hex editor over live target memory, port of src/ui/view_memory.cpp
// Region list on the left, 16-bytes-per-row grid on the right, edit in place

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowRight, RefreshCw } from "lucide-react";
import { hex } from "@/store/disasm";
import { kPageBytes, protectName, useMemory } from "@/store/memory";

const kRow = 19;
const kCols = 16;

function ascii(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

export default function MemoryView() {
  const { regions, bytes, cursor, loading, error, loadRegions, readAt, writeBytes } = useMemory();
  const [goto, setGoto] = useState("");
  const [edit, setEdit] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void loadRegions();
  }, [loadRegions]);

  // Land on the first readable region so the pane is never blank
  useEffect(() => {
    if (cursor === 0 && regions.length > 0) void readAt(regions[0].base);
  }, [regions, cursor, readAt]);

  const rowCount = Math.ceil(bytes.length / kCols);
  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });

  const jump = () => {
    const parsed = Number.parseInt(goto.replace(/^0x/i, ""), 16);
    if (Number.isFinite(parsed)) void readAt(parsed);
  };

  const commitByte = async (offset: number, text: string) => {
    setEdit(null);
    const value = Number.parseInt(text, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xff) return;
    await writeBytes(cursor + offset, new Uint8Array([value]));
    await readAt(cursor);
  };

  return (
    <div className="mem">
      <div className="mem-regions">
        <div className="view-bar" style={{ padding: "var(--pad-sm)" }}>
          <span className="panel-title">Regions</span>
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }}>
            {regions.length}
          </span>
          <button className="icon-button" data-tip="Refresh" onClick={() => void loadRegions()}>
            <RefreshCw size={13} />
          </button>
        </div>
        <div className="panel-body">
          {regions.map((r) => (
            <button
              key={r.base}
              className="fn-row"
              data-selected={cursor >= r.base && cursor < r.base + r.size}
              style={{ position: "static", height: kRow }}
              onClick={() => void readAt(r.base)}
              data-tip={`${r.size} bytes · ${protectName(r.protect)}`}
            >
              <span className="fn-name">{hex(r.base, 12)}</span>
              <span className="faint" style={{ fontSize: 10 }}>
                {protectName(r.protect)}
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="stack">
        <div className="view-bar">
          <label className="view-label">
            goto
            <input
              className="addr-input mono"
              value={goto}
              placeholder="7FF6..."
              onChange={(e) => setGoto(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && jump()}
            />
          </label>
          <button className="row-action" onClick={jump}>
            <ArrowRight size={11} />
          </button>
          <span className="faint mono" style={{ fontSize: 11 }}>
            {hex(cursor)} · {bytes.length}/{kPageBytes} bytes
          </span>
          <div className="spacer" />
          <button
            className="row-action"
            onClick={() => void readAt(Math.max(0, cursor - kPageBytes))}
          >
            ← prev
          </button>
          <button className="row-action" onClick={() => void readAt(cursor + kPageBytes)}>
            next →
          </button>
        </div>

        <div className="panel-body" ref={scrollRef}>
          {error !== null && (
            <div className="empty-hint" style={{ padding: "var(--pad-md)", color: "var(--danger)" }}>
              {error}
            </div>
          )}
          {loading && bytes.length === 0 && (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>reading…</div>
          )}
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const off = v.index * kCols;
              const row = bytes.subarray(off, off + kCols);
              return (
                <div key={off} className="hex-row mono" style={{ top: v.start, height: kRow }}>
                  <span className="insn-va">{hex(cursor + off, 12)}</span>
                  <span className="hex-cells">
                    {Array.from(row).map((b, i) =>
                      edit === off + i ? (
                        <input
                          key={i}
                          className="hex-edit mono"
                          autoFocus
                          maxLength={2}
                          defaultValue={b.toString(16).padStart(2, "0").toUpperCase()}
                          onBlur={(e) => void commitByte(off + i, e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") void commitByte(off + i, e.currentTarget.value);
                            if (e.key === "Escape") setEdit(null);
                          }}
                        />
                      ) : (
                        <button
                          key={i}
                          className="hex-cell"
                          data-zero={b === 0}
                          onClick={() => setEdit(off + i)}
                          data-tip={`${hex(cursor + off + i, 12)} = ${b}`}
                        >
                          {b.toString(16).padStart(2, "0").toUpperCase()}
                        </button>
                      ),
                    )}
                  </span>
                  <span className="hex-ascii">
                    {Array.from(row)
                      .map((b) => ascii(b))
                      .join("")}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
