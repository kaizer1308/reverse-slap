// app/src/store/frida.ts
// frida state, device list, one session, one script and the message drain, all
// local since the engine embeds frida

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type FridaDevice = { id: string; name: string; type: string };

export type AgentMessage = { at_ms: number; message: unknown };

type FridaStore = {
  available: boolean;
  devices: FridaDevice[];
  session: string | null;
  script: string | null;
  pid: number | null;
  messages: AgentMessage[];
  dropped: number;
  error: string | null;
  busy: boolean;

  refresh: () => Promise<void>;
  attach: (pid: number) => Promise<void>;
  detach: () => Promise<void>;
  loadScript: (source: string) => Promise<void>;
  unloadScript: () => Promise<void>;
  drain: () => Promise<void>;
  clearMessages: () => void;
};

export const useFrida = create<FridaStore>((set, get) => ({
  available: false,
  devices: [],
  session: null,
  script: null,
  pid: null,
  messages: [],
  dropped: 0,
  error: null,
  busy: false,

  refresh: async () => {
    try {
      const res = await call<{ available: boolean; devices?: FridaDevice[] }>("frida", "status");
      set({ available: res.available === true, error: null });
      if (res.available === true) {
        const dev = await call<{ devices: FridaDevice[] }>("frida", "devices").catch(() => ({
          devices: [] as FridaDevice[],
        }));
        set({ devices: dev.devices ?? [] });
      }
    } catch (e) {
      set({ available: false, error: e instanceof Error ? e.message : String(e) });
    }
  },

  attach: async (pid) => {
    set({ busy: true, error: null });
    try {
      const res = await call<{ session: string }>("frida", "attach", { pid });
      set({ session: res.session, pid });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  detach: async () => {
    const { session } = get();
    if (session !== null) await call("frida", "detach", { session }).catch(() => undefined);
    set({ session: null, script: null, pid: null });
  },

  loadScript: async (source) => {
    const { session } = get();
    if (session === null) {
      set({ error: "attach a frida session first" });
      return;
    }
    set({ busy: true, error: null });
    try {
      // load=true so the agent starts running immediately, matching what
      // `frida -l script.js` does
      const res = await call<{ script: string }>("frida", "script_create", {
        session,
        source,
        load: true,
      });
      set({ script: res.script });
      await get().drain();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  unloadScript: async () => {
    const { script } = get();
    if (script === null) return;
    await call("frida", "script_destroy", { script }).catch(() => undefined);
    set({ script: null });
  },

  drain: async () => {
    const { script } = get();
    if (script === null) return;
    try {
      const res = await call<{ messages: AgentMessage[]; dropped: number }>("frida", "messages", {
        script,
      });
      if ((res.messages ?? []).length === 0 && (res.dropped ?? 0) === 0) return;
      set((s) => ({
        messages: [...s.messages, ...(res.messages ?? [])].slice(-500),
        dropped: s.dropped + (res.dropped ?? 0),
      }));
    } catch {
      // The script may have been destroyed by the target exiting; leave state
    }
  },

  clearMessages: () => set({ messages: [], dropped: 0 }),
}));
