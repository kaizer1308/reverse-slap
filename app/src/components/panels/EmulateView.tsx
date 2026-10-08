// app/src/components/panels/EmulateView.tsx
// CPU emulation with register/memory state viewer

import { useState } from "react";
import { Play, RefreshCw, StepForward } from "lucide-react";
import { call } from "@/lib/rpc";

type EmulateState = { regs: Record<string, string>; pc: string; sp: string; flags: string; steps: number; status: string; output: string[] };

export default function EmulateView() {
  const [addr, setAddr] = useState("");
  const [steps, setSteps] = useState("100");
  const [state, setState] = useState<EmulateState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    if (!addr.trim()) return;
    setBusy(true); setError(null);
    try {
      const r = await call<EmulateState>("emulate", "run", { addr, max_steps: parseInt(steps) || 100 });
      setState(r);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const step = async () => {
    setBusy(true); setError(null);
    try {
      const r = await call<EmulateState>("emulate", "step", { addr: state?.pc ?? addr });
      setState(r);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="view-label">Emulator</div>
        <input className="addr-input" placeholder="start address" value={addr} onChange={(e) => setAddr(e.target.value)} style={{ width: 140 }} />
        <input className="addr-input" placeholder="max steps" value={steps} onChange={(e) => setSteps(e.target.value)} style={{ width: 70 }} />
        <button className="row-action" disabled={busy} onClick={() => void run()}>
          {busy ? <RefreshCw size={11} className="spin" /> : <><Play size={11} /> Run</>}
        </button>
        <button className="row-action" disabled={busy} onClick={() => void step()}>
          <StepForward size={11} /> Step
        </button>
        <div className="spacer" />
        {state && <span className="faint" style={{ fontSize: 11 }}>{state.steps} steps · {state.status}</span>}
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}
        {state && (
          <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: "var(--pad-lg)", minHeight: 0 }}>
            <div>
              <div className="settings-label">Registers</div>
              <table className="table">
                <tbody>
                  {Object.entries(state.regs).map(([name, value]) => (
                    <tr key={name}>
                      <td style={{ fontWeight: 500 }}>{name}</td>
                      <td className="mono">{value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="settings-rows mono" style={{ marginTop: "var(--pad-md)" }}>
                <div>PC: {state.pc}</div>
                <div>SP: {state.sp}</div>
                <div>FLAGS: {state.flags}</div>
              </div>
            </div>
            <div>
              <div className="settings-label">Execution Log</div>
              <div className="log">
                {state.output.map((l, i) => <div key={i} className="log-row mono">{l}</div>)}
              </div>
            </div>
          </div>
        )}
        {!state && !error && (
          <div className="empty">
            <div className="empty-title">Enter an address and click Run to start emulation.</div>
            <div className="empty-hint">Unicorn-based CPU emulation with full register and memory state tracking.</div>
          </div>
        )}
      </div>
    </div>
  );
}
