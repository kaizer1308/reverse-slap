// app/src/App.tsx
// the shell, css grid layout driven by splitter custom properties

import { useEffect, useRef, useState } from "react";
import ActivityRail from "@/components/ActivityRail";
import CommandPalette from "@/components/CommandPalette";
import ExportModal from "@/components/ExportModal";
import SettingsModal from "@/components/SettingsModal";
import ShortcutsModal from "@/components/ShortcutsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import ThemeEditor from "@/components/ThemeEditor";
import TitleBar from "@/components/TitleBar";
import TooltipLayer from "@/components/TooltipLayer";
import FilesPanel from "@/components/panels/FilesPanel";
import FridaPanel from "@/components/panels/FridaPanel";
import GamePanel from "@/components/panels/GamePanel";
import InspectorPanel from "@/components/panels/InspectorPanel";
import KernelPanel from "@/components/panels/KernelPanel";
import ModulesPanel from "@/components/panels/ModulesPanel";
import NetworkPanel from "@/components/panels/NetworkPanel";
import OutputPanel from "@/components/panels/OutputPanel";
import PluginPanel from "@/components/panels/PluginPanel";
import ScannerPanel from "@/components/panels/ScannerPanel";
import ScriptsPanel from "@/components/panels/ScriptsPanel";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WorkspacePanel from "@/components/panels/WorkspacePanel";
import { useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import type { RailView } from "@/components/ActivityRail";

const kRailShortcuts: Record<string, RailView> = {
  "1": "targets", "2": "modules", "3": "game", "4": "network",
  "5": "kernel", "6": "scripts", "7": "frida", "8": "files", "9": "plugins",
};

export default function App() {
  const rail = useUi((s) => s.rail);
  const setRail = useUi((s) => s.setRail);
  const settingsOpen = useUi((s) => s.settingsOpen);
  const openSettings = useUi((s) => s.openSettings);
  const closeSettings = useUi((s) => s.closeSettings);
  const appRef = useRef<HTMLDivElement>(null);
  const boot = useEngine((s) => s.boot);
  const start = useEngine((s) => s.start);
  const attachOutput = useOutput((s) => s.attach);
  const attachWatch = useWatch((s) => s.attach);

  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [themeEditorOpen, setThemeEditorOpen] = useState(false);

  useEffect(() => {
    const detachOutput = attachOutput();
    const detachWatch = attachWatch();
    void start();
    return () => { detachOutput(); detachWatch(); };
  }, [start, attachOutput, attachWatch]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey) {
        const railView = kRailShortcuts[e.key];
        if (railView) { e.preventDefault(); setRail(railView); return; }
        if (e.key === ",") { e.preventDefault(); openSettings(); return; }
        if (e.shiftKey && e.key === "E") { e.preventDefault(); setExportOpen(true); return; }
        if (e.key === "/") { e.preventDefault(); setShortcutsOpen(true); return; }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [setRail, openSettings]);

  const leftPanel = () => {
    switch (rail) {
      case "targets": return <TargetsPanel key="targets" />;
      case "modules": return <ModulesPanel key="modules" />;
      case "scripts": return <ScriptsPanel key="scripts" />;
      case "frida": return <FridaPanel key="frida" />;
      case "game": return <GamePanel key="game" />;
      case "network": return <NetworkPanel key="network" />;
      case "kernel": return <KernelPanel key="kernel" />;
      case "files": return <FilesPanel key="files" />;
      case "plugins": return <PluginPanel key="plugins" />;
    }
  };

  return (
    <div className="app" ref={appRef}>
      <TitleBar />

      {!boot.done ? (
        <Splash />
      ) : (
        <div className="app-body">
          <ActivityRail active={rail} onSelect={setRail} onSettings={openSettings} />

          {leftPanel()}
          <Splitter axis="x" variable="--left-w" target={appRef} min={200} max={620} />

          <div className="center-col">
            <div className="center-top">
              <ScannerPanel />
              <Splitter axis="x" variable="--scan-w" target={appRef} min={220} max={620} />
              <WorkspacePanel />
            </div>
            <Splitter axis="y" variable="--bottom-h" target={appRef} min={100} max={640} invert />
            <OutputPanel />
          </div>

          <Splitter axis="x" variable="--right-w" target={appRef} min={220} max={620} invert />
          <InspectorPanel />
        </div>
      )}

      <StatusBar />
      {settingsOpen && <SettingsModal onClose={closeSettings} />}
      {shortcutsOpen && <ShortcutsModal onClose={() => setShortcutsOpen(false)} />}
      {exportOpen && <ExportModal onClose={() => setExportOpen(false)} />}
      {themeEditorOpen && <ThemeEditor onClose={() => setThemeEditorOpen(false)} />}
      <CommandPalette />
      <TooltipLayer />
    </div>
  );
}
