// app/src/components/panels/TypesView.tsx
// Struct and enum editor, C declarations, live field reading

import { useEffect, useState } from "react";
import { Plus, RefreshCw, Trash2 } from "lucide-react";
import { call } from "@/lib/rpc";

type StructInfo = { name: string; size: number; fields: { name: string; type: string; offset: number }[] };
type EnumInfo = { name: string; underlying: string; values: { name: string; value: number }[] };

export default function TypesView() {
  const [tab, setTab] = useState<"structs" | "enums" | "declare">("structs");
  const [structs, setStructs] = useState<StructInfo[]>([]);
  const [enums, setEnums] = useState<EnumInfo[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<StructInfo | EnumInfo | null>(null);
  const [decl, setDecl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshStructs = async () => {
    setBusy(true);
    try {
      const r = await call<{ structs: StructInfo[] }>("types", "list_structs");
      setStructs(r.structs); setError(null);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const refreshEnums = async () => {
    setBusy(true);
    try {
      const r = await call<{ enums: EnumInfo[] }>("types", "list_enums");
      setEnums(r.enums); setError(null);
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const selectStruct = async (name: string) => {
    setSelected(name);
    try {
      const r = await call<StructInfo>("types", "get_struct", { name });
      setDetail(r);
    } catch (e: unknown) { setError((e as Error).message); }
  };

  const selectEnum = async (name: string) => {
    setSelected(name);
    try {
      const r = await call<EnumInfo>("types", "get_enum", { name });
      setDetail(r);
    } catch (e: unknown) { setError((e as Error).message); }
  };

  const submitDecl = async () => {
    if (!decl.trim()) return;
    setBusy(true);
    try {
      await call("types", "declare", { decl });
      setDecl(""); void refreshStructs(); void refreshEnums();
    } catch (e: unknown) { setError((e as Error).message); }
    setBusy(false);
  };

  const removeStruct = async (name: string) => {
    await call("types", "remove_struct", { name });
    setStructs((prev) => prev.filter((s) => s.name !== name));
    if (selected === name) { setSelected(null); setDetail(null); }
  };

  const removeEnum = async (name: string) => {
    await call("types", "remove_enum", { name });
    setEnums((prev) => prev.filter((e) => e.name !== name));
    if (selected === name) { setSelected(null); setDetail(null); }
  };

  useEffect(() => { void refreshStructs(); void refreshEnums(); }, []);

  return (
    <div className="stack">
      <div className="view-bar">
        {(["structs", "enums", "declare"] as const).map((t) => (
          <button key={t} className="row-action" data-active={tab === t} onClick={() => setTab(t)}>{t}</button>
        ))}
        <div className="spacer" />
        <button className="icon-button" onClick={() => { void refreshStructs(); void refreshEnums(); }}>
          <RefreshCw size={12} className={busy ? "spin" : undefined} />
        </button>
      </div>
      <div className="panel-body" style={{ overflow: "auto", padding: "var(--pad-md)" }}>
        {error && <div className="settings-status" style={{ marginBottom: "var(--pad-md)" }}>{error}</div>}

        {tab === "structs" && (
          <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "var(--pad-md)", minHeight: 0 }}>
            <div>
              {structs.map((s) => (
                <div key={s.name} className="fn-row" style={{ position: "relative", cursor: "pointer", padding: "4px 8px" }}
                  data-active={selected === s.name} onClick={() => void selectStruct(s.name)}>
                  <span className="fn-name">{s.name}</span>
                  <span className="faint" style={{ fontSize: 11 }}>{s.size}B</span>
                  <button className="fn-edit" onClick={(e) => { e.stopPropagation(); void removeStruct(s.name); }}>
                    <Trash2 size={10} />
                  </button>
                </div>
              ))}
            </div>
            <div>
              {detail && "fields" in detail && (
                <table className="table">
                  <thead><tr><th>Offset</th><th>Name</th><th>Type</th></tr></thead>
                  <tbody>
                    {(detail as StructInfo).fields.map((f, i) => (
                      <tr key={i}><td className="mono">+0x{f.offset.toString(16)}</td><td>{f.name}</td><td className="mono">{f.type}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {tab === "enums" && (
          <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "var(--pad-md)", minHeight: 0 }}>
            <div>
              {enums.map((e) => (
                <div key={e.name} className="fn-row" style={{ position: "relative", cursor: "pointer", padding: "4px 8px" }}
                  data-active={selected === e.name} onClick={() => void selectEnum(e.name)}>
                  <span className="fn-name">{e.name}</span>
                  <button className="fn-edit" onClick={(ev) => { ev.stopPropagation(); void removeEnum(e.name); }}>
                    <Trash2 size={10} />
                  </button>
                </div>
              ))}
            </div>
            <div>
              {detail && "values" in detail && (
                <table className="table">
                  <thead><tr><th>Name</th><th>Value</th></tr></thead>
                  <tbody>
                    {(detail as EnumInfo).values.map((v, i) => (
                      <tr key={i}><td>{v.name}</td><td className="mono">0x{v.value.toString(16)}</td></tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {tab === "declare" && (
          <div>
            <div className="settings-label" style={{ marginBottom: "var(--pad-sm)" }}>C Declaration</div>
            <textarea className="code-area" style={{ height: 200 }} value={decl} onChange={(e) => setDecl(e.target.value)}
              placeholder={"struct PlayerState {\n    float x, y, z;\n    int health;\n    int ammo;\n};"} />
            <button className="row-action" disabled={busy} onClick={() => void submitDecl()} style={{ marginTop: "var(--pad-sm)" }}>
              <Plus size={11} style={{ marginRight: 4 }} />Declare
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
