// app/src/store/xray.ts
// Binary analysis: CFG, entropy, hooks, syscalls, ROP gadgets, crypto, obfuscation

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type CfgNode = { addr: string; size: number; succs: string[]; label: string };
export type HookEntry = { address: string; target: string; module: string; type: string };
export type SyscallEntry = { address: string; number: number; name: string; module: string };
export type GadgetEntry = { address: string; insns: string; type: string };
export type EntropyBlock = { offset: number; size: number; entropy: number; label: string };
export type CryptoRange = { address: string; size: number; algorithm: string; confidence: number };
export type ObfuscationResult = { type: string; count: number; severity: string; details: string };

type XrayStore = {
  cfg: CfgNode[];
  hooks: HookEntry[];
  syscalls: SyscallEntry[];
  gadgets: GadgetEntry[];
  entropy: EntropyBlock[];
  crypto: CryptoRange[];
  obfuscation: ObfuscationResult[];
  complexity: unknown;
  antiAnalysis: unknown;
  busy: boolean;
  error: string | null;
  activeTab: string;

  setTab: (tab: string) => void;
  runCfg: (addr?: string) => Promise<void>;
  runHooks: (maxFns?: number) => Promise<void>;
  runSyscalls: () => Promise<void>;
  runGadgets: (limit?: number) => Promise<void>;
  runEntropy: () => Promise<void>;
  runCrypto: () => Promise<void>;
  runObfuscation: () => Promise<void>;
  runComplexity: () => Promise<void>;
  runAntiAnalysis: () => Promise<void>;
};

export const useXray = create<XrayStore>((set) => ({
  cfg: [], hooks: [], syscalls: [], gadgets: [], entropy: [], crypto: [], obfuscation: [],
  complexity: null, antiAnalysis: null,
  busy: false, error: null, activeTab: "hooks",

  setTab: (tab) => set({ activeTab: tab }),

  runCfg: async (addr?) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ nodes: CfgNode[] }>("xray", "cfg", addr ? { addr } : {});
      set({ cfg: r.nodes, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runHooks: async (maxFns = 1000) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ hooks: HookEntry[] }>("xray", "hooks", { max_functions: maxFns });
      set({ hooks: r.hooks, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runSyscalls: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ entries: SyscallEntry[] }>("xray", "syscalls");
      set({ syscalls: r.entries, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runGadgets: async (limit = 500) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ gadgets: GadgetEntry[] }>("xray", "gadgets", { limit });
      set({ gadgets: r.gadgets, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runEntropy: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ blocks: EntropyBlock[] }>("xray", "entropy");
      set({ entropy: r.blocks, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runCrypto: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ ranges: CryptoRange[] }>("xray", "crypto_range");
      set({ crypto: r.ranges, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runObfuscation: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ results: ObfuscationResult[] }>("xray", "obfuscation");
      set({ obfuscation: r.results, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runComplexity: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<unknown>("xray", "complexity");
      set({ complexity: r, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  runAntiAnalysis: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<unknown>("xray", "anti_analysis");
      set({ antiAnalysis: r, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
}));
