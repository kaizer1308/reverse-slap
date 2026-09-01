// app/src/store/targets.ts
// process list and attach flow, refresh is explicit and the target mirror
// arrives over events

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type ProcessRow = {
  pid: number;
  name: string;
  arch: string;
  path?: string;
  elevation?: string;
};

export type ModuleRow = {
  name: string;
  base: number;
  size: number;
  path?: string;
};

type TargetsStore = {
  processes: ProcessRow[];
  modules: ModuleRow[];
  filter: string;
  loading: boolean;
  error: string | null;
  setFilter: (v: string) => void;
  refresh: () => Promise<void>;
  refreshModules: () => Promise<void>;
  attach: (pid: number) => Promise<boolean>;
  detach: () => Promise<void>;
};

export const useTargets = create<TargetsStore>((set, get) => ({
  processes: [],
  modules: [],
  filter: "",
  loading: false,
  error: null,

  setFilter: (filter) => set({ filter }),

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const res = await call<{ processes: ProcessRow[] }>("target", "list");
      const processes = [...(res.processes ?? [])].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
      );
      set({ processes, loading: false });
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : String(e) });
    }
  },

  refreshModules: async () => {
    try {
      const res = await call<{ modules: ModuleRow[] }>("target", "modules");
      set({ modules: res.modules ?? [] });
    } catch {
      set({ modules: [] });
    }
  },

  attach: async (pid) => {
    try {
      await call("target", "attach", { pid });
      await get().refreshModules();
      return true;
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
      return false;
    }
  },

  detach: async () => {
    await call("target", "detach");
    set({ modules: [] });
  },
}));

/** Name-or-pid substring match, same rule as NameFilterMatch() in the ImGui view. */
export function matchesFilter(row: ProcessRow, filter: string): boolean {
  if (filter === "") return true;
  const needle = filter.toLowerCase();
  return row.name.toLowerCase().includes(needle) || String(row.pid) === needle;
}
