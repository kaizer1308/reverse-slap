// app/src/components/CommandPalette.tsx
// Ctrl+K command palette using cmdk (already a dependency)

import { useCallback, useEffect, useState } from "react";
import { Command } from "cmdk";

import { useUi } from "@/store/ui";
import type { RailView } from "@/components/ActivityRail";

type CmdItem = { id: string; label: string; category: string; action: () => void; shortcut?: string };

export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const setRail = useUi((s) => s.setRail);
  const openSettings = useUi((s) => s.openSettings);

  // Register global Ctrl+K
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setOpen((v) => !v);
        setSearch("");
      }
      if (e.key === "Escape" && open) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open]);

  const run = useCallback((fn: () => void) => {
    fn();
    setOpen(false);
  }, []);

  const items: CmdItem[] = [
    // Navigation
    { id: "nav-targets", label: "Go to Targets", category: "Navigation", action: () => setRail("targets"), shortcut: "" },
    { id: "nav-modules", label: "Go to Modules", category: "Navigation", action: () => setRail("modules") },
    { id: "nav-game", label: "Go to Game Tools", category: "Navigation", action: () => setRail("game") },
    { id: "nav-network", label: "Go to Network", category: "Navigation", action: () => setRail("network") },
    { id: "nav-kernel", label: "Go to Kernel", category: "Navigation", action: () => setRail("kernel") },
    { id: "nav-scripts", label: "Go to Scripts", category: "Navigation", action: () => setRail("scripts") },
    { id: "nav-frida", label: "Go to Frida", category: "Navigation", action: () => setRail("frida") },
    { id: "nav-files", label: "Go to Files", category: "Navigation", action: () => setRail("files" as RailView) },
    { id: "nav-settings", label: "Open Settings", category: "Navigation", action: () => openSettings(), shortcut: "" },
    // Actions
    { id: "act-attach", label: "Attach to Process", category: "Action", action: () => setRail("targets") },
    { id: "act-open-binary", label: "Open Binary...", category: "Action", action: () => { /* handled by workspace */ } },
    // Tools
    { id: "tool-aob", label: "AOB Generator", category: "Game Tools", action: () => setRail("game") },
    { id: "tool-crypto", label: "Crypto Scanner", category: "Game Tools", action: () => setRail("game") },
    { id: "tool-exploit", label: "Exploit Finder", category: "Game Tools", action: () => setRail("game") },
    { id: "tool-overlay", label: "Discord Overlay", category: "Game Tools", action: () => setRail("game") },
    { id: "tool-capture", label: "Start Packet Capture", category: "Network", action: () => setRail("network") },
    { id: "tool-hidden", label: "Scan Hidden Modules", category: "Kernel", action: () => setRail("kernel") },
    { id: "tool-inject", label: "DLL Injection", category: "Kernel", action: () => setRail("kernel") },
    { id: "tool-antidebug", label: "Anti-Debug Spoof", category: "Kernel", action: () => setRail("kernel") },
  ];

  if (!open) return null;

  return (
    <div className="modal-scrim" onClick={() => setOpen(false)}>
      <div style={{ width: "min(560px, 88vw)", marginTop: "-15vh" }} onClick={(e) => e.stopPropagation()}>
        <Command label="Command palette" className="modal" style={{ maxHeight: "50vh" }}>
          <div style={{ padding: "var(--pad-sm) var(--pad-md)", borderBottom: "1px solid var(--border-soft)" }}>
            <Command.Input
              value={search}
              onValueChange={setSearch}
              placeholder="Type a command..."
              style={{
                width: "100%", padding: "var(--pad-sm) 0", fontSize: "var(--type-body)",
                background: "transparent", border: "none", outline: "none", color: "var(--text)",
              }}
              autoFocus
            />
          </div>
          <Command.List style={{ overflow: "auto", padding: "var(--pad-sm) 0", maxHeight: "40vh" }}>
            <Command.Empty style={{ padding: "var(--pad-lg)", textAlign: "center", color: "var(--text-faint)" }}>
              No results found.
            </Command.Empty>
            {["Navigation", "Action", "Game Tools", "Network", "Kernel"].map((cat) => {
              const group = items.filter((i) => i.category === cat);
              if (group.length === 0) return null;
              return (
                <Command.Group key={cat} heading={cat} style={{ padding: "0 var(--pad-sm)" }}>
                  {group.map((item) => (
                    <Command.Item
                      key={item.id}
                      value={item.label}
                      onSelect={() => run(item.action)}
                      style={{
                        display: "flex", alignItems: "center", justifyContent: "space-between",
                        padding: "6px var(--pad-md)", borderRadius: "var(--radius-sm)",
                        cursor: "pointer", fontSize: "var(--type-small)",
                      }}
                    >
                      {item.label}
                      {item.shortcut && <span className="faint" style={{ fontSize: 11 }}>{item.shortcut}</span>}
                    </Command.Item>
                  ))}
                </Command.Group>
              );
            })}
          </Command.List>
        </Command>
      </div>
    </div>
  );
}
