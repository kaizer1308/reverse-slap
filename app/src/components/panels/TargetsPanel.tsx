// app/src/components/panels/TargetsPanel.tsx
// process list and attach flow, stays on the list after attaching so targets
// can be switched without detaching

import { useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { RefreshCw, Search, Unplug } from "lucide-react";
import ProcessIcon from "@/components/ProcessIcon";
import { matchesFilter, useTargets } from "@/store/targets";
import { useEngine } from "@/store/engine";

const kRowHeight = 22;

export default function TargetsPanel() {
  const { processes, filter, loading, setFilter, refresh, attach, detach } = useTargets();
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rows = useMemo(
    () => processes.filter((p) => matchesFilter(p, filter)),
    [processes, filter],
  );

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRowHeight,
    overscan: 12,
  });

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Backend: {backend.badge}</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          {processes.length} processes
        </span>
        {target.attached && (
          <button className="icon-button" data-tip={`Detach ${target.name}`} onClick={() => void detach()}>
            <Unplug size={14} />
          </button>
        )}
        <button className="icon-button" data-tip="Refresh" onClick={() => void refresh()}>
          <RefreshCw size={14} className={loading ? "spin" : undefined} />
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateRows: "auto 1fr", minHeight: 0 }}>
        <div className="search">
          <Search size={13} />
          <input
            value={filter}
            placeholder="Filter processes…"
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>

        <div className="panel-body" ref={scrollRef}>
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 58 }}>PID</th>
                <th>Name</th>
                <th style={{ width: 44 }}>Arch</th>
                <th style={{ width: 60 }}>Action</th>
              </tr>
            </thead>
            <tbody style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((v) => {
                const p = rows[v.index];
                const isTarget = target.attached && target.pid === p.pid;
                return (
                  <tr
                    key={p.pid}
                    data-selected={isTarget}
                    style={{
                      position: "absolute",
                      top: v.start,
                      left: 0,
                      width: "100%",
                      height: kRowHeight,
                      display: "table",
                      tableLayout: "fixed",
                    }}
                    data-tip={p.path ?? p.name}
                  >
                    <td style={{ width: 58 }} className="mono faint">
                      {p.pid}
                    </td>
                    <td>
                      <span style={{ display: "flex", alignItems: "center", gap: "var(--pad-sm)", minWidth: 0 }}>
                        <ProcessIcon path={p.path} />
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {p.name}
                        </span>
                      </span>
                    </td>
                    <td style={{ width: 44 }}>
                      {p.arch === "unknown" ? (
                        <span className="faint">, </span>
                      ) : (
                        <span className="pill">{p.arch}</span>
                      )}
                    </td>
                    <td style={{ width: 60 }}>
                      {isTarget ? (
                        <button className="row-action" data-active="true" onClick={() => void detach()}>
                          Detach
                        </button>
                      ) : (
                        <button className="row-action" onClick={() => void attach(p.pid)}>
                          Attach
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
