// app/src/components/panels/FridaPanel.tsx
// Frida session + agent script against the attached target. The engine embeds
// frida-core, so the local device needs no frida-server

import { useEffect, useState } from "react";
import { Play, Plug, Square, Trash2 } from "lucide-react";
import { useEngine } from "@/store/engine";
import { useFrida } from "@/store/frida";

const kSample = `// runs inside the target
send({ hello: Process.arch, modules: Process.enumerateModules().length });
`;

export default function FridaPanel() {
  const target = useEngine((s) => s.target);
  const {
    available, devices, session, script, messages, dropped, error, busy,
    refresh, attach, detach, loadScript, unloadScript, drain, clearMessages,
  } = useFrida();
  const [source, setSource] = useState(kSample);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Agent messages have no push channel, send()/console.log land in a ring the
  // engine drains on request, so poll while a script is live
  useEffect(() => {
    if (script === null) return;
    const timer = setInterval(() => void drain(), 700);
    return () => clearInterval(timer);
  }, [script, drain]);

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Frida</span>
        {available ? (
          <span className="pill">{devices.length} devices</span>
        ) : (
          <span className="pill" style={{ color: "var(--danger)" }}>unavailable</span>
        )}
        <div className="spacer" />
        {session === null ? (
          <button
            className="row-action"
            disabled={!available || !target.attached || busy}
            data-tip={target.attached ? `attach to pid ${target.pid}` : "attach a target first"}
            onClick={() => target.pid !== undefined && void attach(target.pid)}
          >
            <Plug size={11} /> Attach
          </button>
        ) : (
          <button className="row-action" onClick={() => void detach()}>
            <Square size={11} /> Detach
          </button>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateRows: "auto 1fr auto 1fr", minHeight: 0 }}>
        <div className="dbg-head">
          {session === null ? (
            <span className="faint">no session</span>
          ) : (
            <span className="mono faint" style={{ fontSize: 11 }}>
              session {session.slice(0, 10)} · pid {target.pid}
            </span>
          )}
          <div className="spacer" />
          {script === null ? (
            <button
              className="icon-button"
              data-tip="Load agent script"
              disabled={session === null || busy}
              onClick={() => void loadScript(source)}
            >
              <Play size={14} />
            </button>
          ) : (
            <button className="icon-button" data-tip="Unload script" onClick={() => void unloadScript()}>
              <Square size={14} />
            </button>
          )}
        </div>

        <textarea
          className="code-area mono"
          value={source}
          spellCheck={false}
          onChange={(e) => setSource(e.target.value)}
        />

        <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
          Agent messages
          <div className="spacer" />
          {dropped > 0 && <span className="pill">{dropped} dropped</span>}
          <button className="icon-button" data-tip="Clear" onClick={clearMessages}>
            <Trash2 size={13} />
          </button>
        </div>

        <div className="panel-body log">
          {error !== null && <div className="log-row" style={{ color: "var(--danger)" }}>{error}</div>}
          {messages.length === 0 && error === null && (
            <div className="empty-hint">
              {script === null ? "load a script to see send() output." : "waiting for messages…"}
            </div>
          )}
          {messages.map((m, i) => (
            <div className="log-row" key={i}>
              <span className="log-time">{new Date(m.at_ms).toLocaleTimeString(undefined, { hour12: false })}</span>
              <span>{typeof m.message === "string" ? m.message : JSON.stringify(m.message)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
