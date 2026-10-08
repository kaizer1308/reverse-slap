// app/src/store/persist.ts
import { create } from "zustand";
import { call } from "@/lib/rpc";

export type SessionInfo = { name: string; ts: string; size: number };

type PersistStore = {
  sessions: SessionInfo[];
  busy: boolean;
  error: string | null;

  save: (name: string) => Promise<void>;
  load: (name: string) => Promise<void>;
  remove: (name: string) => Promise<void>;
  refreshList: () => Promise<void>;
  kvSet: (key: string, value: string) => Promise<void>;
  kvGet: (key: string) => Promise<string>;
  hypeSave: (dir?: string) => Promise<void>;
  hypeLoad: (dir?: string) => Promise<void>;
};

export const usePersist = create<PersistStore>((set) => ({
  sessions: [], busy: false, error: null,

  save: async (name) => {
    set({ busy: true, error: null });
    try { await call("persist", "save", { name }); set({ busy: false }); }
    catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  load: async (name) => {
    set({ busy: true, error: null });
    try { await call("persist", "load", { name }); set({ busy: false }); }
    catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  remove: async (name) => {
    try {
      await call("persist", "delete", { name });
      set((s) => ({ sessions: s.sessions.filter((x) => x.name !== name) }));
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  refreshList: async () => {
    try {
      const r = await call<{ sessions: SessionInfo[] }>("persist", "list");
      set({ sessions: r.sessions, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  kvSet: async (key, value) => { await call("persist", "kv_set", { key, value }); },
  kvGet: async (key) => {
    const r = await call<{ value: string }>("persist", "kv_get", { key });
    return r.value;
  },
  hypeSave: async (dir?) => { await call("persist", "hype_save", dir ? { dir } : {}); },
  hypeLoad: async (dir?) => { await call("persist", "hype_load", dir ? { dir } : {}); },
}));
