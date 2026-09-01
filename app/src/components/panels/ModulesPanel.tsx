// app/src/components/panels/ModulesPanel.tsx
// Module list for the attached target, with the dump / dump+analyze workflow the
// ImGui Targets view carried (src/ui/view_targets.cpp, module table)

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Download, RefreshCw, Search } from "lucide-react";
import { call } from "@/lib/rpc";
import { hex } from "@/store/disasm";
import { useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useTargets } from "@/store/targets";

const kRow = 22;

/** `target.dump_module` result, see mcp_tools.cpp, action "dump_module". */
type DumpResult = {
  dumped: boolean;
  complete: boolean;
  path: string;
  bytes_written: number;
  sections: number;
  loaded: boolean;
  warnings?: string[];
};

export default function ModulesPanel() {
  const target = useEngine((s) => s.target);
  const { modules, refreshModules } = useTargets();
  const refreshLoaded = useDisasm((s) => s.refreshLoaded);
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (target.attached) void refreshModules();
  }, [target.attached, refreshModules]);

  const rows = modules.filter((m) => m.name.toLowerCase().includes(filter.toLowerCase()));

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });

  // dump_module reconstructs a conventional PE from the mapped image; load=true
  // hands it straight to the shared analysis session, which is the fast path
  // from "attached to a packed process" to "looking at real code"
  const dump = async (base: number, name: string, load: boolean) => {
    try {
      const dialog = await import("@tauri-apps/plugin-dialog");
      const picked = await dialog.save({
        title: `Dump ${name}`,
        defaultPath: `${name}_${hex(base, 12)}.dump.${name.endsWith(".dll") ? "dll" : "exe"}`,
      });
      if (picked === null) {
        setStatus(null);
        return;
      }
      setStatus(`dumping ${name}…`);
      // strict=false so a packed image with unreadable spans still produces a
      // file; the engine zero-fills those and reports complete=false
      const res = await call<DumpResult>("target", "dump_module", {
        base,
        path: picked,
        load,
        strict: false,
      });
      const size = `${Math.round(res.bytes_written / 1024)} KiB`;
      const partial = res.complete === false ? " (partial, unreadable spans zero-filled)" : "";
      setStatus(`dumped ${name} · ${size} · ${res.sections} sections${partial}`);
      if (res.warnings !== undefined && res.warnings.length > 0) {
        setStatus(
          `dumped ${name} · ${size}${partial} · ${res.warnings.length} warning(s): ${res.warnings[0]}`,
        );
      }
      if (load) await refreshLoaded();
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  };

  if (!target.attached) {
    return (
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Modules</span>
        </div>
        <div className="empty">
          <div className="empty-hint">Attach to a process to list its modules.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Modules</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: 11 }}>{modules.length}</span>
        <button className="icon-button" data-tip="Refresh" onClick={() => void refreshModules()}>
          <RefreshCw size={14} />
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateRows: "auto 1fr auto", minHeight: 0 }}>
        <div className="search">
          <Search size={13} />
          <input value={filter} placeholder="Filter modules…" onChange={(e) => setFilter(e.target.value)} />
        </div>

        <div className="panel-body" ref={scrollRef}>
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const m = rows[v.index];
              return (
                <div
                  key={m.base}
                  className="fn-row"
                  style={{ top: v.start, height: kRow }}
                  data-tip={m.path ?? m.name}
                >
                  <span className="fn-name">{m.name}</span>
                  <span className="faint" style={{ fontSize: 10 }}>{hex(m.base, 12)}</span>
                  <button
                    className="icon-button"
                    data-tip="Dump + analyze"
                    onClick={() => void dump(m.base, m.name, true)}
                  >
                    <Download size={11} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {status !== null && (
          <div className="empty-hint" style={{ padding: "var(--pad-sm) var(--pad-md)" }}>{status}</div>
        )}
      </div>
    </div>
  );
}
