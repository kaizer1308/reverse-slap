// app/src/components/panels/InspectorPanel.tsx
// right hand pane, whatever the engine knows about the target and image

import { Search, SlidersHorizontal, X } from "lucide-react";
import { hex as hexAddr, useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useTargets } from "@/store/targets";

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ display: "flex", gap: "var(--pad-md)", padding: "2px var(--pad-md)" }}>
      <span className="faint" style={{ width: 92, flex: "none", fontSize: "var(--type-small)" }}>
        {k}
      </span>
      {/* Ellipsis rather than break-all: a wrapped path or process name split
          mid-word ("reverse-slo p-engine.ex e") is harder to read than a
          truncated one with the full value on hover. */}
      <span
        className="mono"
        data-tip={v}
        style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
      >
        {v}
      </span>
    </div>
  );
}

export default function InspectorPanel() {
  const { target, backend, hype } = useEngine();
  const modules = useTargets((s) => s.modules);
  // Image facts come from the disasm store, not from `hype.image`: the workspace
  // reads the polled `disasm.loaded` and the event mirror can lag it, which had
  // the Inspector naming one image while the listing showed another
  const image = useDisasm((s) => s.image);

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Inspector</span>
        <div className="spacer" />
        <button className="icon-button" data-tip="Options">
          <SlidersHorizontal size={14} />
        </button>
        <button className="icon-button" data-tip="Close">
          <X size={14} />
        </button>
      </div>

      <div className="panel-body">
        {!target.attached ? (
          <div className="empty">
            <div className="empty-glyph">
              <Search size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">No target selected</div>
            <div className="empty-hint">Select a target to inspect.</div>
          </div>
        ) : (
          <div style={{ padding: "var(--pad-sm) 0" }}>
            <Row k="process" v={target.name ?? "?"} />
            <Row k="pid" v={String(target.pid ?? 0)} />
            <Row k="backend" v={backend.badge} />
            <Row k="modules" v={String(modules.length)} />
            {image.ready && (
              <>
                <div className="menu-sep" />
                <Row k="image" v={image.name ?? "?"} />
                <Row k="base" v={image.base !== undefined ? hexAddr(image.base) : "n/a"} />
                <Row k="functions" v={String(image.functions ?? 0)} />
                <Row
                  k="analysis"
                  v={
                    hype.running
                      ? `${Math.round(hype.progress * 100)}%`
                      : hype.ready
                        ? "ready"
                        : hype.error || "idle"
                  }
                />
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
