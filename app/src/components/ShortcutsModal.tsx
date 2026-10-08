// app/src/components/ShortcutsModal.tsx
// Global keyboard shortcuts reference

const kShortcuts: readonly { key: string; action: string; category: string }[] = [
  { key: "Ctrl+K", action: "Command Palette", category: "Global" },
  { key: "Ctrl+1", action: "Targets panel", category: "Navigation" },
  { key: "Ctrl+2", action: "Modules panel", category: "Navigation" },
  { key: "Ctrl+3", action: "Game Tools", category: "Navigation" },
  { key: "Ctrl+4", action: "Network", category: "Navigation" },
  { key: "Ctrl+5", action: "Kernel", category: "Navigation" },
  { key: "Ctrl+6", action: "Scripts", category: "Navigation" },
  { key: "Ctrl+7", action: "Frida", category: "Navigation" },
  { key: "Ctrl+8", action: "Files", category: "Navigation" },
  { key: "Ctrl+,", action: "Settings", category: "Global" },
  { key: "Ctrl+Shift+E", action: "Export report", category: "Global" },
  { key: "Ctrl+S", action: "Save session", category: "Session" },
  { key: "F5", action: "Run / Continue", category: "Debug" },
  { key: "F10", action: "Step Over", category: "Debug" },
  { key: "F11", action: "Step Into", category: "Debug" },
  { key: "Shift+F11", action: "Step Out", category: "Debug" },
  { key: "F9", action: "Toggle Breakpoint", category: "Debug" },
  { key: "Ctrl+G", action: "Go to address", category: "Navigation" },
  { key: "Ctrl+F", action: "Find / Filter", category: "Global" },
  { key: "Escape", action: "Close modal / Clear", category: "Global" },
];

type Props = { onClose: () => void };

export default function ShortcutsModal({ onClose }: Props) {
  const categories = [...new Set(kShortcuts.map((s) => s.category))];

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: "min(520px, 88vw)" }}>
        <div className="panel-head">
          <span className="panel-title">Keyboard Shortcuts</span>
          <div className="spacer" />
          <button className="icon-button" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {categories.map((cat) => (
            <div key={cat} className="settings-group">
              <div className="settings-label">{cat}</div>
              <table className="table">
                <tbody>
                  {kShortcuts.filter((s) => s.category === cat).map((s) => (
                    <tr key={s.key}>
                      <td style={{ width: 140 }}>
                        <kbd style={{
                          padding: "2px 6px", background: "var(--bg-2)", border: "1px solid var(--border)",
                          borderRadius: "var(--radius-sm)", fontSize: 11, fontFamily: "var(--font-mono)",
                        }}>{s.key}</kbd>
                      </td>
                      <td>{s.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
