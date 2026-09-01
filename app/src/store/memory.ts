// app/src/store/memory.ts
// Live memory browsing for the hex editor, regions plus paged reads and writes
// through the active backend (kernel path when slopdrvr is loaded)

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type Region = {
  base: number;
  size: number;
  protect: number;
  state: number;
  type: number;
};

/** Page size for one read. 4 KiB keeps a scroll responsive over loopback. */
export const kPageBytes = 0x1000;

type MemoryStore = {
  regions: Region[];
  cursor: number;
  bytes: Uint8Array;
  loading: boolean;
  error: string | null;

  loadRegions: () => Promise<void>;
  readAt: (addr: number) => Promise<void>;
  writeBytes: (addr: number, data: Uint8Array) => Promise<void>;
  reset: () => void;
};

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(data: Uint8Array): string {
  let s = "";
  for (const b of data) s += b.toString(16).padStart(2, "0").toUpperCase();
  return s;
}

/** PAGE_* protection constants, rendered the way the region table shows them. */
export function protectName(protect: number): string {
  const base = protect & 0xff;
  const names: Record<number, string> = {
    0x01: "NOACCESS",
    0x02: "R",
    0x04: "RW",
    0x08: "WC",
    0x10: "X",
    0x20: "RX",
    0x40: "RWX",
    0x80: "XWC",
  };
  let out = names[base] ?? `0x${protect.toString(16)}`;
  if ((protect & 0x100) !== 0) out += "+G";
  if ((protect & 0x200) !== 0) out += "+NC";
  return out;
}

export const useMemory = create<MemoryStore>((set) => ({
  regions: [],
  cursor: 0,
  bytes: new Uint8Array(0),
  loading: false,
  error: null,

  loadRegions: async () => {
    try {
      const res = await call<{ regions: Region[] }>("target", "regions");
      // MEM_COMMIT only: reserved and free ranges are not readable, and listing
      // them just gives the user rows that always fail
      const regions = (res.regions ?? []).filter((r) => r.state === 0x1000);
      set({ regions, error: null });
    } catch (e) {
      set({ regions: [], error: e instanceof Error ? e.message : String(e) });
    }
  },

  readAt: async (addr) => {
    set({ loading: true, cursor: addr });
    try {
      const res = await call<{ hex?: string }>("memory", "read", {
        addr,
        len: kPageBytes,
        format: "hex",
      });
      set({ bytes: hexToBytes(res.hex ?? ""), error: null });
    } catch (e) {
      set({ bytes: new Uint8Array(0), error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ loading: false });
    }
  },

  writeBytes: async (addr, data) => {
    await call("memory", "write", { addr, hex: bytesToHex(data) });
  },

  reset: () => set({ regions: [], bytes: new Uint8Array(0), cursor: 0, error: null }),
}));
