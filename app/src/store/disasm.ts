// app/src/store/disasm.ts
// the shared analysis session, a binary opened here is the binary an agent sees

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type FunctionRow = {
  va: number;
  size: number;
  symbol?: string;
  name?: string;
  blocks?: number;
  callconv?: string;
  loops?: number;
  noreturn?: boolean;
};

export type Insn = {
  va: number;
  len: number;
  text: string;
  flow: string;
  target?: number;
  rip_rel?: number;
};

export type LoadedImage = {
  ready: boolean;
  name?: string;
  path?: string;
  base?: number;
  entry_va?: number;
  functions?: number;
  strings?: number;
  hype?: { available: boolean; ready?: boolean; progress?: number; error?: string };
};

export type StringHit = { va: number; text: string; utf16: boolean };

type DisasmStore = {
  image: LoadedImage;
  functions: FunctionRow[];
  total: number;
  selected: number | null;
  insns: Insn[];
  /** True when the listing ran past the function bounds (unreliable size). */
  linear: boolean;
  filter: string;
  busy: boolean;
  error: string | null;

  setFilter: (v: string) => void;
  refreshLoaded: () => Promise<void>;
  loadFile: (path: string) => Promise<void>;
  unload: () => Promise<void>;
  refreshFunctions: () => Promise<void>;
  select: (va: number) => Promise<void>;
  gotoAddress: (va: number) => Promise<void>;
  rename: (va: number, name: string) => Promise<void>;

  strings: StringHit[];
  stringsTruncated: boolean;
  loadStrings: (minChars: number, includeExec: boolean) => Promise<void>;
};

/** `sub_0000000140001000`, matching the ImGui listing's unnamed-function label. */
export function functionLabel(fn: FunctionRow): string {
  return fn.symbol ?? fn.name ?? `sub_${hex(fn.va)}`;
}

export function hex(va: number, pad = 16): string {
  return va.toString(16).toUpperCase().padStart(pad, "0");
}

export const useDisasm = create<DisasmStore>((set, get) => ({
  image: { ready: false },
  functions: [],
  total: 0,
  selected: null,
  insns: [],
  linear: false,
  filter: "",
  busy: false,
  error: null,

  setFilter: (filter) => set({ filter }),

  refreshLoaded: async () => {
    try {
      const image = await call<LoadedImage>("disasm", "loaded");
      const was = get().image.ready;
      set({ image });
      if (image.ready && !was) await get().refreshFunctions();
      if (!image.ready) set({ functions: [], insns: [], selected: null, total: 0 });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  loadFile: async (path) => {
    set({ busy: true, error: null });
    try {
      await call("disasm", "load", { path });
      await get().refreshLoaded();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  unload: async () => {
    await call("disasm", "unload");
    set({ image: { ready: false }, functions: [], insns: [], selected: null, total: 0 });
  },

  refreshFunctions: async () => {
    set({ busy: true });
    try {
      const res = await call<{ functions: FunctionRow[]; total: number }>(
        "disasm",
        "functions",
        { limit: 10000 },
      );
      const functions = res.functions ?? [];
      set({ functions, total: res.total ?? functions.length });
      // Land on the entry point (or the first function) so the pane is never
      // blank after a load
      const current = get().selected;
      if (current === null && functions.length > 0) {
        const entry = get().image.entry_va;
        const start = functions.find((f) => f.va === entry) ?? functions[0];
        await get().select(start.va);
      }
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  select: async (va) => {
    set({ selected: va });
    const fn = get().functions.find((f) => f.va === va);
    // Ask for more than the function should need, then trim: the engine
    // disassembles linearly and will happily run past the end into the next
    // function, which made the header's byte count disagree with the listing
    const size = fn?.size ?? 0;
    const count = Math.min(4000, Math.max(64, Math.ceil(size / 2)));
    try {
      const res = await call<{ instructions: Insn[] }>("disasm", "disassemble", {
        addr: va,
        count,
      });
      const all = res.instructions ?? [];
      const inRange = size > 0 ? all.filter((i) => i.va < va + size) : all;
      // A function index can under-report size (tail merging, jump tables). If
      // trimming leaves almost nothing, show the linear sweep instead of a
      // misleadingly empty function
      const clamped = inRange.length >= 4;
      set({ insns: clamped ? inRange : all, linear: !clamped });
    } catch (e) {
      set({ insns: [], error: e instanceof Error ? e.message : String(e) });
    }
  },

  gotoAddress: async (va) => {
    // Prefer the enclosing function so the listing keeps its context
    const fn = get().functions.find((f) => va >= f.va && va < f.va + f.size);
    await get().select(fn ? fn.va : va);
  },

  rename: async (va, name) => {
    await call("disasm", "symbol_set", { addr: va, name });
    set((s) => ({
      functions: s.functions.map((f) => (f.va === va ? { ...f, symbol: name || undefined } : f)),
    }));
  },

  strings: [],
  stringsTruncated: false,

  loadStrings: async (minChars, includeExec) => {
    set({ busy: true });
    try {
      const res = await call<{ strings: StringHit[]; truncated: boolean }>(
        "disasm",
        "strings",
        { min_chars: minChars, include_exec: includeExec, limit: 10000 },
      );
      set({ strings: res.strings ?? [], stringsTruncated: res.truncated === true });
    } catch (e) {
      set({ strings: [], error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },
}));
