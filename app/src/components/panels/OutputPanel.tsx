// app/src/components/panels/OutputPanel.tsx
// output and log tabs, the app ring and the tagged diag ring side by side

import { useEffect, useRef, useState } from "react";
import { ChevronDown, Eraser, Trash2 } from "lucide-react";
import { call } from "@/lib/rpc";
import { useOutput } from "@/store/output";

type DiagEntry = { ms: number; level: string; tag: string; message: string };

const clock = (ms: number) =>
  new Date(ms).toLocaleTimeString(undefined, { hour12: false });

export default function OutputPanel() {
  const [tab, setTab] = useState<"output" | "log">("output");
  const [diag, setDiag] = useState<DiagEntry[]>([]);
  const [follow, setFollow] = useState(true);
  const { lines, clear } = useOutput();
  const bodyRef = useRef<HTMLDivElement>(null);

  // diag has no push channel: it is a high-volume ring that would swamp the
  // event stream, so the Log tab polls it while it is the visible tab
  useEffect(() => {
    if (tab !== "log") return;
    let alive = true;
    const pull = async () => {
      try {
        const res = await call<{ entries: DiagEntry[] }>("app", "diag", { limit: 1000 });
        if (alive) setDiag(res.entries ?? []);
      } catch {
        /* engine down: keep the last snapshot */
      }
    };
    void pull();
    const timer = setInterval(() => void pull(), 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [tab]);

  useEffect(() => {
    if (!follow) return;
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, diag, follow, tab]);

  return (
    <div className="panel" style={{ borderRight: "none", borderTop: "1px solid var(--border-soft)" }}>
      <div className="tabs">
        <button className="tab" data-active={tab === "output"} onClick={() => setTab("output")}>
          Output
        </button>
        <button className="tab" data-active={tab === "log"} onClick={() => setTab("log")}>
          Log
        </button>
        <div className="spacer" />
        <div style={{ display: "flex", alignSelf: "center", gap: 2, marginRight: 6 }}>
          <button
            className="icon-button"
            data-tip="Clear"
            onClick={() => void (tab === "output" ? clear() : setDiag([]))}
          >
            <Trash2 size={14} />
          </button>
          <button className="icon-button" data-tip="Clear engine ring" onClick={() => void clear()}>
            <Eraser size={14} />
          </button>
          <button
            className="icon-button"
            data-tip={follow ? "Following output" : "Scroll locked"}
            style={{ color: follow ? "var(--accent)" : undefined }}
            onClick={() => setFollow((v) => !v)}
          >
            <ChevronDown size={14} />
          </button>
        </div>
      </div>

      {/* Keyed so switching Output <-> Log replays the enter animation and
          resets the scroll position to the new pane's tail. */}
      <div className="panel-body log swap-fade" key={tab} ref={bodyRef}>
        {tab === "output"
          ? lines.map((l) => (
              <div className="log-row" key={l.seq}>
                <span className="log-time">{clock(l.ms)}</span>
                <span>{l.text}</span>
              </div>
            ))
          : diag.map((e, i) => (
              <div className="log-row" key={`${e.ms}-${i}`}>
                <span className="log-time">{clock(e.ms)}</span>
                <span className="log-level" data-level={e.level}>
                  {e.level}
                </span>
                <span className="log-tag">{e.tag}</span>
                <span>{e.message}</span>
              </div>
            ))}
      </div>
    </div>
  );
}
