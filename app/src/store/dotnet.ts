// app/src/store/dotnet.ts
// The managed (.NET/CLI) assembly explorer, dnSpy-style: a namespace -> type ->
// member tree over the shared image, plus per-type C# and per-method C#/IL from
// the `dotnet` MCP tool. Everything the UI shows here an agent can pull too.

import { create } from "zustand";
import { call, ToolError } from "@/lib/rpc";

export type TypeCounts = {
  fields: number;
  properties: number;
  events: number;
  methods: number;
  nested: number;
};

export type TreeType = {
  token: number;
  token_hex: string;
  name: string;
  full_name: string;
  kind: string;
  visibility: string;
  base?: string;
  interfaces?: string[];
  counts: TypeCounts;
  nested?: TreeType[];
};

export type Namespace = { name: string; types: TreeType[] };

export type FieldInfo = {
  token: number;
  name: string;
  type: string;
  visibility: string;
  static: boolean;
  const?: boolean;
  readonly?: boolean;
  value?: string;
};

export type PropertyInfo = {
  token: number;
  name: string;
  type: string;
  get: boolean;
  set: boolean;
};

export type EventInfo = { token: number; name: string; type: string };

export type MethodInfo = {
  token: number;
  token_hex: string;
  name: string;
  signature: string;
  visibility: string;
  ret: string;
  static: boolean;
  abstract?: boolean;
  virtual?: boolean;
  ctor?: boolean;
  pinvoke?: boolean;
  special?: boolean;
  has_body: boolean;
  il_count: number;
  entry?: number;
};

export type TypeDetail = {
  token: number;
  name: string;
  namespace: string;
  full_name: string;
  kind: string;
  visibility: string;
  abstract: boolean;
  sealed: boolean;
  static: boolean;
  base?: string;
  interfaces?: string[];
  attributes?: string[];
  fields: FieldInfo[];
  properties: PropertyInfo[];
  events: EventInfo[];
  methods: MethodInfo[];
  nested?: { token: number; name: string; kind: string }[];
};

export type IlLine = {
  offset: number;
  offset_label: string;
  va: number;
  size: number;
  mnemonic: string;
  operand?: string;
  flow: string;
  target?: number;
};

export type MethodDetail = {
  token: number;
  name: string;
  full_name: string;
  signature: string;
  decl_type: string;
  visibility: string;
  ret: string;
  static: boolean;
  max_stack: number;
  code_size: number;
  entry?: number;
  params: { type: string; name: string }[];
  locals: { index: number; type: string }[];
  handlers: {
    kind: string;
    try_offset: number;
    try_length: number;
    handler_offset: number;
    handler_length: number;
    catch_type: string;
  }[];
  il: IlLine[];
  il_text: string;
  csharp: string;
  csharp_structured: boolean;
};

export type Status = {
  managed: boolean;
  assembly?: string;
  runtime?: string;
  il_only?: boolean;
  types?: number;
  methods?: number;
  fields?: number;
  properties?: number;
  events?: number;
  note?: string;
};

/** What the code pane is currently showing. */
export type Selection =
  | { kind: "type"; token: number; title: string }
  | { kind: "method"; token: number; title: string }
  | null;

type DotNetStore = {
  status: Status | null;
  namespaces: Namespace[];
  /** Type detail cache, keyed by TypeDef token, for lazy member expansion. */
  details: Record<number, TypeDetail>;
  expandedNs: Set<string>;
  expandedType: Set<number>;
  selection: Selection;
  /** Rendered code for the current selection. */
  csharp: string;
  ilText: string;
  method: MethodDetail | null;
  view: "csharp" | "il";
  filter: string;
  busy: boolean;
  loadingCode: boolean;
  error: string | null;

  refresh: () => Promise<void>;
  reset: () => void;
  setFilter: (v: string) => void;
  setView: (v: "csharp" | "il") => void;
  toggleNs: (name: string) => void;
  toggleType: (token: number) => Promise<void>;
  selectType: (token: number, title: string) => Promise<void>;
  selectMethod: (token: number, title: string) => Promise<void>;
};

const kEmpty = {
  status: null,
  namespaces: [] as Namespace[],
  details: {} as Record<number, TypeDetail>,
  expandedNs: new Set<string>(),
  expandedType: new Set<number>(),
  selection: null as Selection,
  csharp: "",
  ilText: "",
  method: null as MethodDetail | null,
  error: null as string | null,
};

export const useDotnet = create<DotNetStore>((set, get) => ({
  ...kEmpty,
  view: "csharp",
  filter: "",
  busy: false,
  loadingCode: false,

  reset: () => set({ ...kEmpty }),

  setFilter: (filter) => set({ filter }),
  setView: (view) => set({ view }),

  refresh: async () => {
    set({ busy: true, error: null });
    try {
      const status = await call<Status>("dotnet", "status");
      if (!status.managed) {
        set({ ...kEmpty, status, busy: false });
        return;
      }
      const tree = await call<{ namespaces: Namespace[] }>("dotnet", "tree", {
        limit: 20000,
      });
      set({
        status,
        namespaces: tree.namespaces ?? [],
        details: {},
        expandedNs: new Set<string>(),
        expandedType: new Set<number>(),
        busy: false,
      });
    } catch (e) {
      // A non-managed image fails the guarded actions; treat as "not managed"
      // rather than a hard error so the tab can show a clean empty state.
      const managed = !(e instanceof ToolError && /not a managed/.test(e.message));
      set({
        ...kEmpty,
        status: { managed: false },
        error: managed ? (e instanceof Error ? e.message : String(e)) : null,
        busy: false,
      });
    }
  },

  toggleNs: (name) =>
    set((s) => {
      const next = new Set(s.expandedNs);
      next.has(name) ? next.delete(name) : next.add(name);
      return { expandedNs: next };
    }),

  toggleType: async (token) => {
    const open = get().expandedType.has(token);
    set((s) => {
      const next = new Set(s.expandedType);
      open ? next.delete(token) : next.add(token);
      return { expandedType: next };
    });
    if (open || get().details[token]) return;
    try {
      const detail = await call<TypeDetail>("dotnet", "type", { token });
      set((s) => ({ details: { ...s.details, [token]: detail } }));
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  selectType: async (token, title) => {
    set({ selection: { kind: "type", token, title }, loadingCode: true, method: null });
    try {
      const res = await call<{ csharp: string }>("dotnet", "source", { token });
      set({ csharp: res.csharp ?? "", ilText: "", view: "csharp", loadingCode: false });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e), loadingCode: false });
    }
  },

  selectMethod: async (token, title) => {
    set({ selection: { kind: "method", token, title }, loadingCode: true });
    try {
      const m = await call<MethodDetail>("dotnet", "method", { token });
      set({
        method: m,
        csharp: m.csharp ?? "",
        ilText: m.il_text ?? "",
        loadingCode: false,
      });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e), loadingCode: false });
    }
  },
}));
