// app/src/components/panels/DebuggerView.tsx
// Port of src/ui/view_debugger.cpp: attach state, run control, registers,
// callstack, breakpoints, event log

import { useEffect, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRightToLine,
  ArrowUpFromLine,
  Ban,
  Play,
  Plus,
  Timer,
} from "lucide-react";
import { hex, useDisasm } from "@/store/disasm";
import { isPaused, useDebugger } from "@/store/debugger";
import { useEngine } from "@/store/engine";

const kRegOrder = [
  "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
  "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "flags",
];

export default function DebuggerView() {
  const target = useEngine((s) => s.target);
  const {
    status, regs, frames, events, breakpoints, error, busy,
    refresh, attach, detach, setBreakpoint, clearBreakpoint, step, waitHalt,
  } = useDebugger();
  const { gotoAddress } = useDisasm();
  const [bpAddr, setBpAddr] = useState("");
  const [hw, setHw] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh, target.pid]);

  const attached = status.state !== "detached" && status.pid !== 0;
  const paused = isPaused(status);

  const addBp = () => {
    const parsed = Number.parseInt(bpAddr.replace(/^0x/i, ""), 16);
    if (Number.isFinite(parsed)) {
      void setBreakpoint(parsed, hw);
      setBpAddr("");
    }
  };

  return (
    <div className="stack">
      <div className="view-bar">
        <span className="pill" style={{ color: paused ? "var(--warning)" : undefined }}>
          {status.state}
        </span>
        {attached && <span className="faint mono" style={{ fontSize: 11 }}>pid {status.pid} · {status.mode}</span>}
        {status.kernel_active && <span className="pill">KERNEL</span>}
        {status.hwbp_supported && <span className="pill">hwbp</span>}

        <div className="spacer" />

        {!attached ? (
          <button
            className="row-action"
            disabled={!target.attached || busy}
            onClick={() => target.pid !== undefined && void attach(target.pid)}
          >
            Attach debugger
          </button>
        ) : (
          <>
            <button className="row-action" disabled={busy} onClick={() => void step("continue")} data-tip="continue">
              <Play size={11} />
            </button>
            <button className="row-action" disabled={!paused || busy} onClick={() => void step("step_into")} data-tip="step into">
              <ArrowDownToLine size={11} />
            </button>
            <button className="row-action" disabled={!paused || busy} onClick={() => void step("step_over")} data-tip="step over">
              <ArrowRightToLine size={11} />
            </button>
            <button className="row-action" disabled={!paused || busy} onClick={() => void step("step_out")} data-tip="step out">
              <ArrowUpFromLine size={11} />
            </button>
            <button className="row-action" disabled={busy} onClick={() => void waitHalt(5000)} data-tip="wait for a halt (5s)">
              <Timer size={11} />
            </button>
            <button className="row-action" onClick={() => void detach()}>
              <Ban size={11} /> Detach
            </button>
          </>
        )}
      </div>

      {error !== null && (
        <div className="empty-hint" style={{ padding: "var(--pad-sm) var(--pad-md)", color: "var(--danger)" }}>
          {error}
        </div>
      )}

      <div className="dbg">
        <div className="dbg-col">
          <div className="dbg-head">Registers</div>
          <div className="panel-body">
            {regs === null ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {attached ? "not paused, set a breakpoint or wait for a halt." : "not attached."}
              </div>
            ) : (
              <table className="table">
                <tbody>
                  {kRegOrder.map((name) => (
                    <tr key={name}>
                      <td className="mono faint" style={{ width: 52 }}>{name}</td>
                      <td>
                        <button className="mono link" onClick={() => void gotoAddress(regs[name] ?? 0)}>
                          {hex(regs[name] ?? 0)}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">Call stack</div>
          <div className="panel-body">
            {frames.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>no frames.</div>
            ) : (
              frames.map((f, i) => (
                <button
                  key={i}
                  className="fn-row"
                  style={{ position: "static", height: 20 }}
                  onClick={() => void gotoAddress(f.ret_addr)}
                  data-tip={f.snippet !== undefined && f.snippet !== "" ? f.snippet : undefined}
                >
                  <span className="faint" style={{ width: 20 }}>{i}</span>
                  <span className="fn-name mono">{hex(f.ret_addr)}</span>
                  {f.scanned === true && <span className="faint" style={{ fontSize: 10 }}>scan</span>}
                </button>
              ))
            )}
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">
            Breakpoints
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 110 }}
              value={bpAddr}
              placeholder="address"
              onChange={(e) => setBpAddr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addBp()}
            />
            <label className="view-label" data-tip="hardware breakpoint (debug register)">
              <input type="checkbox" checked={hw} onChange={(e) => setHw(e.target.checked)} />
              hw
            </label>
            <button className="icon-button" onClick={addBp} disabled={!attached}>
              <Plus size={13} />
            </button>
          </div>
          <div className="panel-body">
            {breakpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>none set.</div>
            ) : (
              breakpoints.map((b) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={b.addr}>
                  <span className="fn-name mono">{hex(b.addr)}</span>
                  {b.hw && <span className="pill">hw</span>}
                  <button className="icon-button" onClick={() => void clearBreakpoint(b.addr)}>
                    <Ban size={11} />
                  </button>
                </div>
              ))
            )}
            <div className="dbg-head" style={{ marginTop: "var(--pad-sm)" }}>Events</div>
            {events.slice(-40).reverse().map((e, i) => (
              <div className="log-row mono" key={i} style={{ padding: "1px var(--pad-md)", fontSize: 11 }}>
                <span className="faint">{e.tid}</span>
                <span style={{ color: e.exc_code !== 0 ? "var(--danger)" : undefined }}>{e.kind}</span>
                <span className="faint">{hex(e.address, 12)}</span>
                {e.text !== undefined && e.text !== "" && <span>{e.text}</span>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
