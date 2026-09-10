// app/src/components/panels/DotNetView.tsx
// The managed (.NET/CLI) assembly explorer, dnSpy-style: a namespace -> type ->
// member tree on the left, and a code pane on the right that shows a type as C#
// or a method as C# / IL. Backed by the `dotnet` MCP tool, so the UI and an
// agent see the exact same model.

import { useMemo } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { useDisasm } from "@/store/disasm";
import {
  useDotnet,
  type MethodInfo,
  type TreeType,
  type TypeDetail,
} from "@/store/dotnet";

// One-letter badge + color role per type/member kind, echoing dnSpy's icons.
const kindBadge: Record<string, { c: string; cls: string }> = {
  class: { c: "C", cls: "dn-class" },
  struct: { c: "S", cls: "dn-struct" },
  interface: { c: "I", cls: "dn-iface" },
  enum: { c: "E", cls: "dn-enum" },
  delegate: { c: "D", cls: "dn-delegate" },
  method: { c: "M", cls: "dn-method" },
  field: { c: "F", cls: "dn-field" },
  property: { c: "P", cls: "dn-prop" },
  event: { c: "e", cls: "dn-event" },
};

function Badge({ kind }: { kind: string }) {
  const b = kindBadge[kind] ?? { c: "?", cls: "" };
  return <span className={`dn-badge ${b.cls}`}>{b.c}</span>;
}

function MethodRow({ m }: { m: MethodInfo }) {
  const { selection, selectMethod } = useDotnet();
  const active = selection?.kind === "method" && selection.token === m.token;
  return (
    <div
      className="dn-leaf"
      data-selected={active}
      onClick={() => void selectMethod(m.token, m.signature)}
      title={m.signature}
    >
      <Badge kind="method" />
      <span className="dn-leaf-name">
        {m.name}
        <span className="faint">
          (
          {m.pinvoke ? "extern " : ""}
          {m.static ? "static" : "instance"})
        </span>
      </span>
      {m.abstract && <span className="pill">abstract</span>}
      {m.virtual && !m.abstract && <span className="pill">virtual</span>}
      {!m.has_body && !m.abstract && <span className="pill">no body</span>}
    </div>
  );
}

function Members({ detail }: { detail: TypeDetail }) {
  return (
    <>
      {detail.fields.map((f) => (
        <div className="dn-leaf dn-info" key={`f${f.token}`} title={`${f.type} ${f.name}`}>
          <Badge kind="field" />
          <span className="dn-leaf-name">
            {f.name} <span className="faint">: {f.type}</span>
            {f.value !== undefined && <span className="faint"> = {f.value}</span>}
          </span>
          {f.const && <span className="pill">const</span>}
          {f.static && !f.const && <span className="pill">static</span>}
        </div>
      ))}
      {detail.properties.map((p) => (
        <div className="dn-leaf dn-info" key={`p${p.token}`} title={`${p.type} ${p.name}`}>
          <Badge kind="property" />
          <span className="dn-leaf-name">
            {p.name} <span className="faint">: {p.type}</span>
            <span className="faint"> {"{ "}{p.get ? "get; " : ""}{p.set ? "set; " : ""}{"}"}</span>
          </span>
        </div>
      ))}
      {detail.events.map((e) => (
        <div className="dn-leaf dn-info" key={`e${e.token}`} title={`${e.type} ${e.name}`}>
          <Badge kind="event" />
          <span className="dn-leaf-name">
            {e.name} <span className="faint">: {e.type}</span>
          </span>
        </div>
      ))}
      {detail.methods.map((m) => (
        <MethodRow m={m} key={`m${m.token}`} />
      ))}
    </>
  );
}

function TypeNode({ t, depth }: { t: TreeType; depth: number }) {
  const { expandedType, toggleType, selectType, selection, details } = useDotnet();
  const open = expandedType.has(t.token);
  const active = selection?.kind === "type" && selection.token === t.token;
  const detail = details[t.token];
  const memberCount =
    t.counts.fields + t.counts.properties + t.counts.events + t.counts.methods;
  const hasChildren = memberCount > 0 || t.counts.nested > 0;

  return (
    <div className="dn-type">
      <div
        className="dn-row"
        data-selected={active}
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={() => {
          void selectType(t.token, t.full_name);
          void toggleType(t.token);
        }}
      >
        <span className="dn-caret">
          {hasChildren ? (
            open ? <ChevronDown size={12} /> : <ChevronRight size={12} />
          ) : (
            <span style={{ width: 12, display: "inline-block" }} />
          )}
        </span>
        <Badge kind={t.kind} />
        <span className="dn-leaf-name">{t.name}</span>
        <span className="faint">{memberCount || ""}</span>
      </div>

      {open && (
        <div className="dn-children">
          {t.nested?.map((n) => (
            <TypeNode t={n} depth={depth + 1} key={n.token} />
          ))}
          {!detail && hasChildren && (
            <div className="dn-leaf dn-info" style={{ paddingLeft: 8 + (depth + 1) * 14 }}>
              <span className="faint">loading…</span>
            </div>
          )}
          {detail && (
            <div style={{ paddingLeft: (depth + 1) * 14 }}>
              <Members detail={detail} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Tree() {
  const { namespaces, expandedNs, toggleNs, filter, setFilter, status } = useDotnet();

  const filtered = useMemo(() => {
    if (filter.trim() === "") return namespaces;
    const needle = filter.toLowerCase();
    return namespaces
      .map((ns) => ({
        ...ns,
        types: ns.types.filter((t) => t.full_name.toLowerCase().includes(needle)),
      }))
      .filter((ns) => ns.types.length > 0);
  }, [namespaces, filter]);

  const filtering = filter.trim() !== "";

  return (
    <div className="dn-tree">
      <div className="search">
        <Search size={13} />
        <input
          value={filter}
          placeholder={`Filter ${status?.types ?? 0} types…`}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <div className="panel-body">
        {filtered.map((ns) => {
          const open = filtering || expandedNs.has(ns.name);
          return (
            <div className="dn-ns" key={ns.name}>
              <div className="dn-row dn-ns-row" onClick={() => toggleNs(ns.name)}>
                <span className="dn-caret">
                  {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                </span>
                <span className="dn-ns-name">{ns.name}</span>
                <span className="faint">{ns.types.length}</span>
              </div>
              {open && (
                <div>
                  {ns.types.map((t) => (
                    <TypeNode t={t} depth={1} key={t.token} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            no types match “{filter}”.
          </div>
        )}
      </div>
    </div>
  );
}

function CodePane() {
  const { selection, csharp, ilText, view, setView, loadingCode, method } = useDotnet();
  const { gotoAddress } = useDisasm();

  const body = view === "csharp" ? csharp : ilText;
  const canIl = ilText.trim() !== "";

  return (
    <div className="dn-code">
      <div className="listing-head mono">
        {selection ? (
          <>
            <span style={{ color: "var(--accent)" }}>{selection.title}</span>
            <div className="spacer" />
            <div className="dn-toggle">
              <button data-active={view === "csharp"} onClick={() => setView("csharp")}>
                C#
              </button>
              <button
                data-active={view === "il"}
                disabled={!canIl}
                onClick={() => setView("il")}
              >
                IL
              </button>
            </div>
            {method?.entry !== undefined && method.entry !== 0 && (
              <button
                className="link mono"
                style={{ fontSize: 11 }}
                onClick={() => void gotoAddress(method.entry as number)}
                title="show this method in the Disassembly view"
              >
                → disasm
              </button>
            )}
          </>
        ) : (
          <span className="faint">select a type or method</span>
        )}
      </div>
      <div className="panel-body">
        {loadingCode ? (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            decompiling…
          </div>
        ) : (
          <pre className="dn-code-pre mono">{body}</pre>
        )}
      </div>
    </div>
  );
}

export default function DotNetView() {
  // WorkspacePanel drives the metadata probe (so the tree survives tab switches);
  // this view just renders from the shared store.
  const { status, busy } = useDotnet();
  const image = useDisasm((s) => s.image);

  if (busy && status === null) {
    return (
      <div className="empty">
        <div className="empty-title">Reading metadata…</div>
      </div>
    );
  }

  if (!status?.managed) {
    return (
      <div className="empty">
        <div className="empty-title">Not a .NET assembly.</div>
        <div className="empty-hint">
          This view lists managed types, members and IL. The loaded image carries no
          CLI metadata (COM descriptor directory).
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      <div className="view-bar">
        <span className="mono" style={{ color: "var(--accent)" }}>
          {status.assembly || image.name}
        </span>
        <span className="faint mono" style={{ fontSize: 11 }}>
          {status.runtime} · {status.types} types · {status.methods} methods ·{" "}
          {status.fields} fields · {status.properties} props
          {status.il_only ? " · IL-only" : ""}
        </span>
      </div>
      <div className="dn-explorer">
        <Tree />
        <CodePane />
      </div>
    </div>
  );
}
