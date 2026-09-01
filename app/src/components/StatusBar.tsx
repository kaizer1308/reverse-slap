// app/src/components/StatusBar.tsx
// indicator row, everything here is pushed by the engine so nothing polls

import { MonitorCog, Settings2, SunMoon } from "lucide-react";
import { useEngine } from "@/store/engine";
import { kThemes, useTheme } from "@/store/theme";
import { useUi } from "@/store/ui";

type DotState = "ok" | "busy" | "bad" | "idle";

function Pill({ label, state }: { label: string; state: DotState }) {
  return (
    <span className="status-pill">
      <span className="dot" data-state={state} />
      {label}
    </span>
  );
}

export default function StatusBar() {
  const { connected, backend, target, hype } = useEngine();
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const openSettings = useUi((s) => s.openSettings);
  const setRail = useUi((s) => s.setRail);

  const cycleTheme = () => {
    const i = kThemes.findIndex((t) => t.id === theme);
    setTheme(kThemes[(i + 1) % kThemes.length].id);
  };

  const analysis: DotState = hype.running
    ? "busy"
    : hype.ready
      ? "ok"
      : hype.error !== ""
        ? "bad"
        : "idle";

  return (
    <div className="statusbar">
      <span>
        {target.attached
          ? `${target.name ?? "target"} (${target.pid ?? 0})`
          : connected
            ? "Ready"
            : "Disconnected"}
      </span>

      <div className="spacer" />

      <Pill label={`Backend: ${backend.badge}`} state={backend.kernel ? "ok" : "busy"} />
      <Pill label={connected ? "Engine: Connected" : "Engine: Offline"} state={connected ? "ok" : "bad"} />
      <Pill label={target.attached ? "Memory: Ready" : "Memory: Idle"} state={target.attached ? "ok" : "idle"} />
      <Pill label={hype.has_image ? `Image: ${hype.image}` : "Image: none"} state={hype.has_image ? "ok" : "idle"} />
      <Pill
        label={
          hype.running
            ? `Analysis: ${Math.round(hype.progress * 100)}%`
            : hype.ready
              ? "Analysis: Ready"
              : "Analysis: Idle"
        }
        state={analysis}
      />

      <div className="status-actions">
        <button className="icon-button" data-tip={`Theme: ${theme}`} onClick={cycleTheme}>
          <SunMoon size={14} />
        </button>
        <button className="icon-button" data-tip="Scripts" onClick={() => setRail("scripts")}>
          <MonitorCog size={14} />
        </button>
        <button className="icon-button" data-tip="Settings" onClick={openSettings}>
          <Settings2 size={14} />
        </button>
      </div>
    </div>
  );
}
