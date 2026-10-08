// app/src/store/driver.ts
// Kernel driver status, kernel modules, kernel R/W, anti-debug, sandbox

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type DriverStatus = {
  device: string;
  kernel_active: boolean;
  hwbp_supported: boolean;
  preference: string;
};

export type KernelModule = {
  base: string;
  size: number;
  name: string;
  path: string;
};

export type DetectionResult = {
  type: string;
  name: string;
  address: string;
  details: string;
};

type DriverStore = {
  status: DriverStatus | null;
  modules: KernelModule[];
  detections: DetectionResult[];
  busy: boolean;
  error: string | null;

  refreshStatus: () => Promise<void>;
  refreshModules: () => Promise<void>;
  setBackend: (pref: string) => Promise<void>;
  kernelRead: (addr: string, size: number) => Promise<string>;
  kernelSearch: (pattern: string, name?: string) => Promise<unknown[]>;
  antiDebugSpoof: () => Promise<void>;
  sandboxProtect: () => Promise<void>;
  sandboxUnprotect: () => Promise<void>;
  // detection
  hiddenModules: () => Promise<void>;
  minifilters: () => Promise<void>;
  etwSessions: () => Promise<void>;
  kernelCallbacks: () => Promise<void>;
};

export const useDriver = create<DriverStore>((set, get) => ({
  status: null,
  modules: [],
  detections: [],
  busy: false,
  error: null,

  refreshStatus: async () => {
    try {
      const s = await call<DriverStatus>("driver", "status");
      set({ status: s, error: null });
    } catch (e: unknown) {
      set({ error: (e as Error).message });
    }
  },

  refreshModules: async () => {
    set({ busy: true });
    try {
      const r = await call<{ modules: KernelModule[] }>("driver", "kernel_modules", { limit: 500 });
      set({ modules: r.modules, busy: false, error: null });
    } catch (e: unknown) {
      set({ busy: false, error: (e as Error).message });
    }
  },

  setBackend: async (pref) => {
    try {
      await call("driver", "backend", { pref });
      await get().refreshStatus();
    } catch (e: unknown) {
      set({ error: (e as Error).message });
    }
  },

  kernelRead: async (addr, size) => {
    const r = await call<{ hex: string }>("driver", "kernel_read", { addr, size });
    return r.hex;
  },

  kernelSearch: async (pattern, name?) => {
    const r = await call<{ results: unknown[] }>("driver", "kernel_search", { pattern, name, limit: 100 });
    return r.results;
  },

  antiDebugSpoof: async () => {
    await call("driver", "anti_debug_spoof");
  },
  sandboxProtect: async () => {
    await call("driver", "sandbox_protect");
  },
  sandboxUnprotect: async () => {
    await call("driver", "sandbox_unprotect");
  },

  hiddenModules: async () => {
    set({ busy: true });
    try {
      const r = await call<{ results: DetectionResult[] }>("detect", "hidden_modules");
      set((s) => ({ detections: [...s.detections, ...r.results], busy: false }));
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  minifilters: async () => {
    set({ busy: true });
    try {
      const r = await call<{ results: DetectionResult[] }>("detect", "minifilters");
      set((s) => ({ detections: [...s.detections, ...r.results], busy: false }));
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  etwSessions: async () => {
    set({ busy: true });
    try {
      const r = await call<{ results: DetectionResult[] }>("detect", "etw_sessions");
      set((s) => ({ detections: [...s.detections, ...r.results], busy: false }));
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  kernelCallbacks: async () => {
    set({ busy: true });
    try {
      const r = await call<{ results: DetectionResult[] }>("detect", "kernel_callbacks");
      set((s) => ({ detections: [...s.detections, ...r.results], busy: false }));
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
}));
