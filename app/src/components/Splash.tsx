// app/src/components/Splash.tsx
// boot checklist fed by boot.stage events so the uac pause doesnt look like a hang

import { useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import logoUrl from "@/assets/reverse-slop-icon.png";

const kStageLabels = [
  "runtime pool & job queue",
  "process / target services",
  "kernel bridge (slopdrvr)",
  "settings & session store",
  "mcp server",
  "interface",
];

export default function Splash() {
  const { boot, connected } = useEngine();
  const lines = useOutput((s) => s.lines);
  const tail = lines.slice(-4);

  return (
    <div className="splash">
      <div className="splash-card">
        <img className="splash-logo" src={logoUrl} alt="reverse-slop" draggable={false} />
        <div className="splash-title">reverse-slop</div>
        <div className="faint" style={{ fontSize: "var(--type-small)" }}>
          windows reverse-engineering workbench, booting
        </div>

        <div className="splash-rows">
          {kStageLabels.map((label, i) => {
            const status = i < boot.stage ? "ok" : i === boot.stage ? "run" : "wait";
            const marker = status === "ok" ? "[ ok ]" : status === "run" ? "[ .. ]" : "[    ]";
            return (
              <div className="splash-row" data-status={status} key={label}>
                {marker} {label}
              </div>
            );
          })}
        </div>

        {tail.length > 0 && (
          <div className="log" style={{ padding: 0, marginBottom: "var(--pad-md)" }}>
            {tail.map((l) => (
              <div className="log-row faint" key={l.seq}>
                {l.text}
              </div>
            ))}
          </div>
        )}

        <div className="progress">
          <div
            className="progress-fill"
            style={{ width: `${Math.round((boot.stage / Math.max(1, boot.total)) * 100)}%` }}
          />
        </div>
        <div className="empty-hint" style={{ marginTop: "var(--pad-sm)" }}>
          {connected
            ? "first launch: windows asks for administrator consent so the kernel bridge can load"
            : "waiting for the engine to accept connections…"}
        </div>
      </div>
    </div>
  );
}
