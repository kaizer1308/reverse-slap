// app/src/store/game.ts
// Game analysis tools: AOB generation, crypto scan, exploits, overlay, UE/Il2Cpp dumper

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type AobResult = { label: string; pattern: string; address: string; unique: boolean };
export type CryptoHit = { address: string; type: string; size: number; entropy: number };
export type MapBlock = { base: string; size: number; label: string; type: string; entropy: number };
export type TimerCandidate = { address: string; rate: number; type: string; label: string };
export type ExploitResult = { type: string; address: string; severity: string; description: string };
export type CodeCave = { address: string; size: number; module: string; permissions: string };
export type AuthorityResult = { field: string; authority: string; mutable: boolean; details: string };
export type PositionCandidate = { address: string; x: number; y: number; z: number; confidence: number };
export type SpeedCandidate = { address: string; value: number; type: string; confidence: number };
export type ScreenPoint = { x: number; y: number; visible: boolean };

type GameStore = {
  aobResults: AobResult[];
  cryptoHits: CryptoHit[];
  mapBlocks: MapBlock[];
  timers: TimerCandidate[];
  exploits: ExploitResult[];
  caves: CodeCave[];
  authority: AuthorityResult[];
  positions: PositionCandidate[];
  speeds: SpeedCandidate[];
  overlayConnected: boolean;
  busy: boolean;
  error: string | null;
  activeTab: string;

  setTab: (tab: string) => void;
  aobGenerate: (addr: string, len?: number) => Promise<void>;
  cryptoScan: (blockSize?: number) => Promise<void>;
  binaryMap: () => Promise<void>;
  findTimers: (sampleMs?: number, minRate?: number) => Promise<void>;
  findExploit: (type?: string) => Promise<void>;
  findCodeCaves: (minSize?: number) => Promise<void>;
  testAuthority: () => Promise<void>;
  tickRate: () => Promise<unknown>;
  findPosition: (x?: number, y?: number, z?: number) => Promise<void>;
  findSpeed: () => Promise<void>;
  worldToScreen: (x: number, y: number, z: number, sw: number, sh: number) => Promise<ScreenPoint>;
  overlayConnect: () => Promise<void>;
  overlayDisconnect: () => Promise<void>;
  overlayDraw: (commands: unknown[]) => Promise<void>;
  overlayClear: () => Promise<void>;
  dumpDeobfuscated: (imports?: boolean, oep?: boolean) => Promise<unknown>;
  readTArray: (addr: string, max?: number) => Promise<unknown>;
};

export const useGame = create<GameStore>((set) => ({
  aobResults: [],
  cryptoHits: [],
  mapBlocks: [],
  timers: [],
  exploits: [],
  caves: [],
  authority: [],
  positions: [],
  speeds: [],
  overlayConnected: false,
  busy: false,
  error: null,
  activeTab: "aob",

  setTab: (tab) => set({ activeTab: tab }),

  aobGenerate: async (addr, len = 32) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ results: AobResult[] }>("game", "aob_generate", { addr, len });
      set({ aobResults: r.results, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  cryptoScan: async (blockSize = 256) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ hits: CryptoHit[] }>("game", "crypto_scan", { block_size: blockSize });
      set({ cryptoHits: r.hits, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  binaryMap: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ blocks: MapBlock[] }>("game", "binary_map");
      set({ mapBlocks: r.blocks, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  findTimers: async (sampleMs = 1000, minRate = 10) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ timers: TimerCandidate[] }>("game", "find_timers", { sample_ms: sampleMs, min_rate: minRate });
      set({ timers: r.timers, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  findExploit: async (type?) => {
    set({ busy: true, error: null });
    try {
      const p: Record<string, unknown> = {};
      if (type) p.type = type;
      const r = await call<{ results: ExploitResult[] }>("game", "find_exploit", p);
      set({ exploits: r.results, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  findCodeCaves: async (minSize = 64) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ caves: CodeCave[] }>("game", "find_code_caves", { min_size: minSize });
      set({ caves: r.caves, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  testAuthority: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ results: AuthorityResult[] }>("game", "test_authority");
      set({ authority: r.results, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  tickRate: async () => {
    return call("game", "tick_rate");
  },

  findPosition: async (x?, y?, z?) => {
    set({ busy: true, error: null });
    try {
      const p: Record<string, unknown> = {};
      if (x !== undefined) { p.x = x; p.y = y; p.z = z; }
      const r = await call<{ candidates: PositionCandidate[] }>("game", "find_position", p);
      set({ positions: r.candidates, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  findSpeed: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ candidates: SpeedCandidate[] }>("game", "find_speed");
      set({ speeds: r.candidates, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  worldToScreen: async (x, y, z, sw, sh) => {
    return call<ScreenPoint>("game", "world_to_screen", { x, y, z, screen_w: sw, screen_h: sh });
  },

  overlayConnect: async () => {
    await call("game", "overlay_connect");
    set({ overlayConnected: true });
  },
  overlayDisconnect: async () => {
    await call("game", "overlay_disconnect");
    set({ overlayConnected: false });
  },
  overlayDraw: async (commands) => {
    await call("game", "overlay_draw", { commands });
  },
  overlayClear: async () => {
    await call("game", "overlay_clear");
  },

  dumpDeobfuscated: async (imports?, oep?) => {
    const p: Record<string, unknown> = {};
    if (imports !== undefined) p.imports = imports;
    if (oep !== undefined) p.oep = oep;
    return call("game", "dump_deobfuscated", p);
  },

  readTArray: async (addr, max = 256) => {
    return call("game", "read_tarray", { addr, max });
  },
}));
