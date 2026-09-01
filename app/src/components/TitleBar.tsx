// app/src/components/TitleBar.tsx
// custom titlebar, drag region and buttons through the tauri window api

import { useEffect, useRef, useState } from "react";
import { Minus, Square, X } from "lucide-react";
import { call } from "@/lib/rpc";
import { openBinary } from "@/lib/openBinary";
import { useEngine } from "@/store/engine";
import { useTheme, type ThemeName, kThemes } from "@/store/theme";
import { useUi } from "@/store/ui";
import logoUrl from "@/assets/reverse-slop-icon.png";

type MenuName = "File" | "View" | "Window" | "Theme" | "Help";

async function windowAction(action: "minimize" | "toggleMaximize" | "close") {
  try {
    const mod = await import("@tauri-apps/api/window");
    const win = mod.getCurrentWindow();
    if (action === "minimize") await win.minimize();
    else if (action === "toggleMaximize") await win.toggleMaximize();
    else await win.close();
  } catch {
    // Running in a plain browser (npm run dev): nothing to drive
  }
}

export default function TitleBar() {
  const [open, setOpen] = useState<MenuName | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const quitting = useEngine((s) => s.quitting);
  const rail = useUi((s) => s.rail);
  const setRail = useUi((s) => s.setRail);
  const openSettings = useUi((s) => s.openSettings);

  useEffect(() => {
    if (open === null) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(null);
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const menu = (name: MenuName, body: React.ReactNode) => (
    <div className="menu-root" key={name}>
      <button
        className="menu-button"
        data-open={open === name}
        onClick={() => setOpen(open === name ? null : name)}
        onMouseEnter={() => open !== null && setOpen(name)}
      >
        {name}
      </button>
      {open === name && (
        <div className="menu-pop" onClick={() => setOpen(null)}>
          {body}
        </div>
      )}
    </div>
  );

  return (
    <div className="titlebar" ref={rootRef}>
      <div className="brand">
        <img src={logoUrl} width={16} height={16} alt="" draggable={false} />
      </div>

      {menu(
        "File",
        <>
          <button className="menu-item" onClick={() => void openBinary()}>
            <span>Open binary…</span>
            <span className="faint">Ctrl+O</span>
          </button>
          <button className="menu-item" onClick={() => setRail("targets")}>
            Attach to process…
          </button>
          <div className="menu-sep" />
          <button
            className="menu-item"
            onClick={() => {
              // Ask the engine to run its own teardown (driver unload included)
              // before the window goes away, so a closed UI never orphans state
              void call("app", "shutdown", { reason: "File > Exit" }).finally(() =>
                windowAction("close"),
              );
            }}
          >
            <span>Exit</span>
            <span className="faint">Alt+F4</span>
          </button>
        </>,
      )}

      {menu(
        "View",
        <>
          {(
            [
              ["targets", "Targets"],
              ["modules", "Modules"],
              ["scripts", "Scripts"],
              ["frida", "Frida"],
            ] as const
          ).map(([id, label]) => (
            <button key={id} className="menu-item" onClick={() => setRail(id)}>
              <span>{label}</span>
              {rail === id && <span className="faint">●</span>}
            </button>
          ))}
        </>,
      )}

      {menu(
        "Window",
        <>
          <button className="menu-item" onClick={openSettings}>
            Settings…
          </button>
          <div className="menu-sep" />
          <button className="menu-item" onClick={() => window.location.reload()}>
            Reload interface
          </button>
        </>,
      )}

      {menu(
        "Theme",
        <>
          {kThemes.map((t) => (
            <button
              key={t.id}
              className="menu-item"
              onClick={() => setTheme(t.id as ThemeName)}
            >
              <span>{t.label}</span>
              {theme === t.id && <span className="faint">●</span>}
            </button>
          ))}
        </>,
      )}

      {menu(
        "Help",
        <button className="menu-item" disabled>
          reverse-slop 0.1.0
        </button>,
      )}

      <div className="titlebar-drag" data-tauri-drag-region />

      {quitting !== null && <span className="faint">shutting down…</span>}

      <div className="win-buttons">
        <button className="win-button" onClick={() => void windowAction("minimize")}>
          <Minus size={14} />
        </button>
        <button className="win-button" onClick={() => void windowAction("toggleMaximize")}>
          <Square size={12} />
        </button>
        <button className="win-button close" onClick={() => void windowAction("close")}>
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
