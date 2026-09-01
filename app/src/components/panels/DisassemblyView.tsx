// app/src/components/panels/DisassemblyView.tsx
// port of the disasm view, function list and instruction listing, both
// virtualized since a real binary has tens of thousands of each

import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Pencil, Search } from "lucide-react";
import { functionLabel, hex, useDisasm, type FunctionRow } from "@/store/disasm";

const kRow = 20;

function flowColor(flow: string): string | undefined {
  switch (flow) {
    case "call":
      return "var(--accent)";
    case "jump":
    case "cond_jump":
      return "var(--warning)";
    case "ret":
      return "var(--danger)";
    default:
      return undefined;
  }
}

function FunctionList() {
  const { functions, total, selected, filter, setFilter, select, rename } = useDisasm();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const rows = useMemo(() => {
    if (filter === "") return functions;
    const needle = filter.toLowerCase();
    return functions.filter(
      (f) =>
        functionLabel(f).toLowerCase().includes(needle) ||
        hex(f.va).toLowerCase().includes(needle.replace(/^0x/, "")),
    );
  }, [functions, filter]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 15,
  });

  const commit = async (fn: FunctionRow, value: string) => {
    setEditing(null);
    if (value !== functionLabel(fn)) await rename(fn.va, value);
  };

  return (
    <div className="fn-list">
      <div className="search">
        <Search size={13} />
        <input
          value={filter}
          placeholder={`Filter ${total} functions…`}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <div className="panel-body" ref={scrollRef}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((v) => {
            const fn = rows[v.index];
            return (
              <div
                key={fn.va}
                className="fn-row"
                data-selected={fn.va === selected}
                style={{ top: v.start, height: kRow }}
                onClick={() => void select(fn.va)}
                onDoubleClick={() => setEditing(fn.va)}
                data-tip={`${hex(fn.va)} · ${fn.size} bytes${fn.callconv ? ` · ${fn.callconv}` : ""}`}
              >
                {editing === fn.va ? (
                  <input
                    className="fn-rename mono"
                    autoFocus
                    defaultValue={functionLabel(fn)}
                    onBlur={(e) => void commit(fn, e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void commit(fn, e.currentTarget.value);
                      if (e.key === "Escape") setEditing(null);
                    }}
                  />
                ) : (
                  <>
                    <span className="fn-name">{functionLabel(fn)}</span>
                    {fn.noreturn === true && <span className="pill">noret</span>}
                    {fn.blocks !== undefined && <span className="faint">{fn.blocks}bb</span>}
                    <Pencil className="fn-edit" size={11} />
                  </>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Listing() {
  const { insns, selected, functions, gotoAddress, linear } = useDisasm();
  const scrollRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: insns.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 25,
  });

  const fn = functions.find((f) => f.va === selected);

  return (
    <div className="listing">
      <div className="listing-head mono">
        {fn ? (
          <>
            <span style={{ color: "var(--accent)" }}>{functionLabel(fn)}</span>
            <span className="faint">
              {hex(fn.va)} · {fn.size} bytes · {insns.length} insns
              {fn.callconv ? ` · ${fn.callconv}` : ""}
            </span>
            {linear && (
              <span
                className="pill"
                data-tip="the function index under-reported this range, so the listing is a linear sweep past its end"
              >
                linear
              </span>
            )}
          </>
        ) : (
          <span className="faint">no function selected</span>
        )}
      </div>
      {/* Keyed on the selection so picking a new function fades its listing in
          rather than swapping rows underneath the cursor. Remounting also puts
          the scroll back at the top, which the effect below used to do. */}
      <div className="panel-body swap-fade" key={selected ?? "none"} ref={scrollRef}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((v) => {
            const insn = insns[v.index];
            const target = insn.target;
            return (
              <div key={insn.va} className="insn-row mono" style={{ top: v.start, height: kRow }}>
                <span className="insn-va">{hex(insn.va)}</span>
                <span className="insn-text" style={{ color: flowColor(insn.flow) }}>
                  {insn.text}
                </span>
                {target !== undefined && (
                  <button
                    className="insn-target"
                    onClick={() => void gotoAddress(target)}
                    data-tip={`follow ${hex(target)}`}
                  >
                    → {hex(target, 8)}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function DisassemblyView() {
  return (
    <div className="disasm">
      <FunctionList />
      <Listing />
    </div>
  );
}
