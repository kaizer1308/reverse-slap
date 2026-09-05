// app/src/App.tsx
// the shell, css grid layout driven by splitter custom properties

import { useEffect, useRef } from "react";
import ActivityRail from "@/components/ActivityRail";
import SettingsModal from "@/components/SettingsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import TitleBar from "@/components/TitleBar";
import TooltipLayer from "@/components/TooltipLayer";
import FridaPanel from "@/components/panels/FridaPanel";
import InspectorPanel from "@/components/panels/InspectorPanel";
import ModulesPanel from "@/components/panels/ModulesPanel";
import OutputPanel from "@/components/panels/OutputPanel";
import ScannerPanel from "@/components/panels/ScannerPanel";
import ScriptsPanel from "@/components/panels/ScriptsPanel";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WorkspacePanel from "@/components/panels/WorkspacePanel";
import { useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";

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

  useEffect(() => {
    // Event handlers must be registered before connect() so the first frames
    // after the stream opens are not dropped
    const detachOutput = attachOutput();
    const detachWatch = attachWatch();
    void start();
    return () => { detachOutput(); detachWatch(); };
  }, [start, attachOutput, attachWatch]);

  const leftPanel = () => {
    // Keyed so switching rails remounts the panel and replays its enter
    // animation (see `.panel` in the motion section of app.css)
    switch (rail) {
      case "targets":
        return <TargetsPanel key="targets" />;
      case "modules":
        return <ModulesPanel key="modules" />;
      case "scripts":
        return <ScriptsPanel key="scripts" />;
      case "frida":
        return <FridaPanel key="frida" />;
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
            <Splitter
              axis="y"
              variable="--bottom-h"
              target={appRef}
              min={100}
              max={640}
              invert
            />
            <OutputPanel />
          </div>

          <Splitter axis="x" variable="--right-w" target={appRef} min={220} max={620} invert />
          <InspectorPanel />
        </div>
      )}

      <StatusBar />
      {settingsOpen && <SettingsModal onClose={closeSettings} />}
      <TooltipLayer />
    </div>
  );
}
