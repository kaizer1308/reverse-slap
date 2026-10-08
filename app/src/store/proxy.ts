// app/src/store/proxy.ts
import { create } from "zustand";
import { call } from "@/lib/rpc";

export type ProxyEntry = { id: number; method: string; url: string; status: number; content_type: string; size: number; ts: string; request_headers: string; response_headers: string; request_body: string; response_body: string };

type ProxyStore = {
  running: boolean;
  port: number;
  entries: ProxyEntry[];
  selected: ProxyEntry | null;
  busy: boolean;
  error: string | null;

  start: (port?: number) => Promise<void>;
  stop: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  refreshEntries: (limit?: number) => Promise<void>;
  selectEntry: (id: number) => Promise<void>;
  replay: (id: number) => Promise<void>;
};

export const useProxy = create<ProxyStore>((set) => ({
  running: false, port: 8080, entries: [], selected: null, busy: false, error: null,

  start: async (port = 8080) => {
    try {
      await call("proxy", "start", { port });
      set({ running: true, port, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  stop: async () => {
    try {
      await call("proxy", "stop");
      set({ running: false, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  refreshStatus: async () => {
    try {
      const r = await call<{ running: boolean; port: number }>("proxy", "status");
      set({ running: r.running, port: r.port, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  refreshEntries: async (limit = 200) => {
    set({ busy: true });
    try {
      const r = await call<{ entries: ProxyEntry[] }>("proxy", "entries", { limit });
      set({ entries: r.entries, busy: false, error: null });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  selectEntry: async (id) => {
    try {
      const r = await call<ProxyEntry>("proxy", "entry", { id });
      set({ selected: r });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  replay: async (id) => {
    try {
      await call("proxy", "replay", { id });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
}));
