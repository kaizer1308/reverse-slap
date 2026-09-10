// app/src/components/panels/WorkspacePanel.tsx
// The tabbed centre area. Disassembly is ported; the remaining tabs keep their
// empty states until each view lands

import { useEffect, useMemo, useState } from "react";
import { FolderOpen, Plus, ScanSearch, X } from "lucide-react";
import DisassemblyView from "@/components/panels/DisassemblyView";
import DebuggerView from "@/components/panels/DebuggerView";
import DotNetView from "@/components/panels/DotNetView";
import MemoryView from "@/components/panels/MemoryView";
import PeView from "@/components/panels/PeView";
import StringsView from "@/components/panels/StringsView";
import { openBinary } from "@/lib/openBinary";
import { useEngine } from "@/store/engine";
import { useDisasm } from "@/store/disasm";
import { useDotnet } from "@/store/dotnet";

type TabId = "disassembly" | "dotnet" | "strings" | "memory" | "debugger" | "pe";

// Which tabs read the static analysis session and which need a live process
// Getting this wrong is what made Memory and Debugger look broken behind a
// "no binary loaded" wall they never needed
const kTabs: readonly { id: TabId; label: string; needs: "image" | "target" }[] = [
  { id: "disassembly", label: "Disassembly", needs: "image" },
  { id: "dotnet", label: ".NET", needs: "image" },
  { id: "strings", label: "Strings", needs: "image" },
  { id: "memory", label: "Memory", needs: "target" },
  { id: "debugger", label: "Debugger", needs: "target" },
  { id: "pe", label: "PE Browser", needs: "image" },
];

export default function WorkspacePanel() {
  const [active, setActive] = useState<TabId>("disassembly");
  const target = useEngine((s) => s.target);
  const hype = useEngine((s) => s.hype);
  const { image, busy, error, refreshLoaded, unload } = useDisasm();
  const dotnetManaged = useDotnet((s) => s.status?.managed ?? false);
  const dotnetRefresh = useDotnet((s) => s.refresh);
  const dotnetReset = useDotnet((s) => s.reset);

  // The session is shared with the ImGui shell and with agents, so the image can
  // change without this window doing anything, re-read when the engine reports
  // analysis movement
  useEffect(() => {
    void refreshLoaded();
  }, [refreshLoaded, hype.has_image, hype.ready]);

  // Probe the managed model once analysis lands: for a .NET image this reveals
  // the tree and turns the ".NET" tab on; for a native image the probe is cheap
  // (status only) and the tab stays hidden. Runs here, not in DotNetView, so the
  // tree + expansion state survive tab switches (the view remounts on switch).
  useEffect(() => {
    if (image.ready && hype.ready) void dotnetRefresh();
    else if (!image.ready) dotnetReset();
  }, [image.ready, image.name, hype.ready, dotnetRefresh, dotnetReset]);

  // The ".NET" tab only exists for managed images; if it vanishes while active,
  // fall back to Disassembly rather than showing a blank pane.
  const tabs = useMemo(
    () => kTabs.filter((t) => t.id !== "dotnet" || dotnetManaged),
    [dotnetManaged],
  );
  useEffect(() => {
    if (!tabs.some((t) => t.id === active)) setActive("disassembly");
  }, [tabs, active]);

  const body = () => {
    const tab = tabs.find((t) => t.id === active);

    if (tab?.needs === "target" && !target.attached) {
      return (
        <div className="empty">
          <div className="empty-glyph">
            <ScanSearch size={28} strokeWidth={1.5} />
          </div>
          <div className="empty-title">No target attached.</div>
          <div className="empty-hint">
            Attach to a process from the Targets panel to use {tab.label}.
          </div>
        </div>
      );
    }

    if (tab?.needs === "image") {
      if (busy && !image.ready) {
        return (
          <div className="empty">
            <div className="empty-title">Loading…</div>
          </div>
        );
      }
      if (!image.ready) {
        return (
          <div className="empty">
            <div className="empty-glyph">
              <ScanSearch size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">No binary loaded.</div>
            <div className="empty-hint">
              {target.attached
                ? "Open a file, or dump a module from the attached target."
                : "Open a binary, or attach to a process."}
            </div>
            <button className="row-action" onClick={() => void openBinary()}>
              <FolderOpen size={12} style={{ marginRight: 6, verticalAlign: -2 }} />
              Open binary…
            </button>
            {error !== null && (
              <div className="empty-hint" style={{ color: "var(--danger)" }}>
                {error}
              </div>
            )}
          </div>
        );
      }
    }

    switch (active) {
      case "disassembly":
        return <DisassemblyView />;
      case "dotnet":
        return <DotNetView />;
      case "strings":
        return <StringsView />;
      case "pe":
        return <PeView />;
      case "memory":
        return <MemoryView />;
      case "debugger":
        return <DebuggerView />;
    }
  };

  return (
    <div className="panel">
      <div className="tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            className="tab"
            data-active={active === t.id}
            onClick={() => setActive(t.id)}
          >
            {t.label}
          </button>
        ))}
        <button className="tab" data-tip="Add view">
          <Plus size={13} />
        </button>
        <div className="spacer" />
        {image.ready && (
          <span
            className="faint"
            style={{ alignSelf: "center", fontSize: "var(--type-small)", marginRight: 8 }}
          >
            {image.name}
            {hype.running ? ` · analyzing ${Math.round(hype.progress * 100)}%` : ""}
          </span>
        )}
        <button
          className="icon-button"
          style={{ alignSelf: "center", marginRight: 6 }}
          data-tip={image.ready ? "Close binary" : "Open binary…"}
          onClick={() => void (image.ready ? unload() : openBinary())}
        >
          {image.ready ? <X size={14} /> : <FolderOpen size={14} />}
        </button>
      </div>
      <div className="panel-body" style={{ overflow: "hidden" }}>
        {/* Keyed on the active tab so the enter animation replays on every
            switch rather than only on first mount. */}
        <div className="view-swap" key={active}>
          {body()}
        </div>
      </div>
    </div>
  );
}
