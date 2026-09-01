// app/src/components/panels/PeView.tsx
// PE Browser: headers, sections, imports, exports. Port of src/ui/view_pe.cpp

import { useEffect, useState } from "react";
import { hex, useDisasm } from "@/store/disasm";
import { usePe } from "@/store/pe";

type Sub = "sections" | "imports" | "exports";

export default function PeView() {
  const { pe, loading, error, load } = usePe();
  const { image, gotoAddress } = useDisasm();
  const [sub, setSub] = useState<Sub>("sections");

  useEffect(() => {
    void load();
  }, [load, image.name]);

  const base = pe.image_base ?? image.base ?? 0;

  return (
    <div className="stack">
      <div className="view-bar">
        {(["sections", "imports", "exports"] as Sub[]).map((s) => (
          <button key={s} className="tab" data-active={sub === s} onClick={() => setSub(s)}>
            {s}
            <span className="faint">
              {s === "sections"
                ? pe.sections.length
                : s === "imports"
                  ? pe.imports.length
                  : pe.exports.length}
            </span>
          </button>
        ))}
        <div className="spacer" />
        <span className="faint mono" style={{ fontSize: 11 }}>
          {pe.pe32plus === true ? "PE32+" : "PE32"} · base {hex(base)} · entry{" "}
          {hex(base + (pe.entry_rva ?? 0))}
        </span>
      </div>

      <div className="panel-body swap-fade" key={sub}>
        {error !== null && (
          <div className="empty-hint" style={{ padding: "var(--pad-md)", color: "var(--danger)" }}>
            {error}
          </div>
        )}
        {loading && <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>reading headers…</div>}

        {sub === "sections" && (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 90 }}>Name</th>
                <th style={{ width: 130 }}>VA</th>
                <th style={{ width: 90 }}>RVA</th>
                <th style={{ width: 90 }}>Virtual</th>
                <th style={{ width: 90 }}>Raw</th>
                <th>Flags</th>
              </tr>
            </thead>
            <tbody>
              {pe.sections.map((s) => (
                <tr key={`${s.name}-${s.rva}`}>
                  <td className="mono">{s.name}</td>
                  <td>
                    <button className="mono link" onClick={() => void gotoAddress(base + s.rva)}>
                      {hex(base + s.rva)}
                    </button>
                  </td>
                  <td className="mono faint">0x{s.rva.toString(16).toUpperCase()}</td>
                  <td className="mono faint">0x{s.vsize.toString(16).toUpperCase()}</td>
                  <td className="mono faint">0x{s.raw_size.toString(16).toUpperCase()}</td>
                  <td>
                    {s.exec && <span className="pill">exec</span>}{" "}
                    {s.writable && <span className="pill">write</span>}{" "}
                    <span className="faint mono" style={{ fontSize: 11 }}>
                      0x{s.characteristics.toString(16).toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {sub === "imports" && (
          <div>
            {pe.imports.map((d) => (
              <details key={d.dll} className="tree">
                <summary>
                  <span className="mono">{d.dll}</span>
                  <span className="faint">{d.functions.length}</span>
                </summary>
                {d.functions.map((fn, i) => (
                  <div className="tree-leaf mono" key={`${d.dll}-${i}`}>
                    {fn}
                  </div>
                ))}
              </details>
            ))}
            {pe.imports.length === 0 && !loading && (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                no imports.
              </div>
            )}
          </div>
        )}

        {sub === "exports" && (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 70 }}>Ordinal</th>
                <th style={{ width: 130 }}>VA</th>
                <th>Name</th>
              </tr>
            </thead>
            <tbody>
              {pe.exports.map((e, i) => (
                <tr key={`${e.name}-${i}`}>
                  <td className="mono faint">{e.ordinal}</td>
                  <td>
                    <button className="mono link" onClick={() => void gotoAddress(base + e.rva)}>
                      {hex(base + e.rva)}
                    </button>
                  </td>
                  <td className="mono">{e.name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
