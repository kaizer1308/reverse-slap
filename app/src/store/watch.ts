// app/src/store/watch.ts
// watchlist mirror, the list lives in core and the app tick services it, a
// watch added over mcp shows up here and vice versa

import { create } from "zustand";
import * as events from "@/lib/events";
import { call } from "@/lib/rpc";
import type { WatchEntry, WatchValue } from "@/lib/events";

type WatchStore = {
  entries: WatchEntry[];
  values: Map<number, WatchValue>;
  attached: boolean;
  attach: () => () => void;
  load: () => Promise<void>;
  add: (addr: number, width: string, label?: string) => Promise<void>;
  remove: (id: number) => Promise<void>;
  setFreeze: (id: number, freeze: boolean) => Promise<void>;
  poke: (id: number, value: string) => Promise<void>;
  clear: () => Promise<void>;
};

export const useWatch = create<WatchStore>((set) => ({
  entries: [],
  values: new Map(),
  attached: false,

  attach: () => {
    const offList = events.on("watch.list", ({ entries }) => set({ entries }));
    const offValues = events.on("watch.values", ({ attached, values }) =>
      set({ attached, values: new Map(values.map((v) => [v.id, v])) }),
    );
    return () => { offList(); offValues(); };
  },

  load: async () => {
    const res = await call<{ entries: WatchEntry[]; values: WatchValue[] }>(
      "memory",
      "watch_list",
    );
    set({
      entries: res.entries ?? [],
      values: new Map((res.values ?? []).map((v) => [v.id, v])),
    });
  },

  add: async (addr, width, label) => {
    await call("memory", "watch_add", { addr, width, ...(label ? { label } : {}) });
  },

  remove: async (id) => {
    await call("memory", "watch_remove", { id });
  },

  setFreeze: async (id, freeze) => {
    await call("memory", "watch_set", { id, freeze });
  },

  // Text form so f32/f64 and signed widths round-trip through the same
  // parse_value_text() the scanner's value box used
  poke: async (id, value) => {
    await call("memory", "watch_set", { id, value });
  },

  clear: async () => {
    await call("memory", "watch_clear");
  },
}));
