// app/src/store/inject.ts
import { create } from "zustand";
import { call } from "@/lib/rpc";

export type InjectStatus = { injected: boolean; module: string; base: string };

type InjectStore = {
  status: InjectStatus | null;
  busy: boolean;
  error: string | null;

  refreshStatus: () => Promise<void>;
  loadLibrary: (dllPath: string) => Promise<void>;
  manualMap: (dllPath: string) => Promise<void>;
  unload: () => Promise<void>;
};

export const useInject = create<InjectStore>((set) => ({
  status: null, busy: false, error: null,

  refreshStatus: async () => {
    try {
      const r = await call<InjectStatus>("inject", "status");
      set({ status: r, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  loadLibrary: async (dllPath) => {
    set({ busy: true, error: null });
    try {
      await call("inject", "loadlibrary", { dll_path: dllPath });
      set({ busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  manualMap: async (dllPath) => {
    set({ busy: true, error: null });
    try {
      await call("inject", "manual_map", { dll_path: dllPath });
      set({ busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  unload: async () => {
    try {
      await call("inject", "unload");
      set({ status: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
}));
