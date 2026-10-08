// app/src/store/patch.ts
// Patching: NOP junk, opaque predicates, anti-debug, XOR unpack, string decode

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type PatchEntry = { address: string; original_hex: string; patched_hex: string; description: string };
export type JournalEntry = { id: number; address: string; type: string; original: string; patched: string; ts: string };

type PatchStore = {
  patches: PatchEntry[];
  journal: JournalEntry[];
  busy: boolean;
  error: string | null;
  dryRun: boolean;

  setDryRun: (v: boolean) => void;
  nopJunk: (aggressive?: boolean) => Promise<void>;
  resolveOpaque: () => Promise<void>;
  patchAntidebug: () => Promise<void>;
  unpackXor: (method?: string, keyHex?: string) => Promise<void>;
  decodeStrings: () => Promise<void>;
  writeBytes: (addr: string, hex: string) => Promise<void>;
  revertAll: () => Promise<void>;
  refreshJournal: () => Promise<void>;
  fullPass: () => Promise<void>;
  rebuild: () => Promise<void>;
};

export const usePatch = create<PatchStore>((set, get) => ({
  patches: [], journal: [], busy: false, error: null, dryRun: true,

  setDryRun: (v) => set({ dryRun: v }),

  nopJunk: async (aggressive = false) => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ patches: PatchEntry[] }>("patch", "nop_junk", { aggressive, dry_run: get().dryRun });
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  resolveOpaque: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ patches: PatchEntry[] }>("patch", "resolve_opaque", { dry_run: get().dryRun });
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  patchAntidebug: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ patches: PatchEntry[] }>("patch", "patch_antidebug", { dry_run: get().dryRun });
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  unpackXor: async (method?, keyHex?) => {
    set({ busy: true, error: null });
    try {
      const p: Record<string, unknown> = { dry_run: get().dryRun };
      if (method) p.method = method;
      if (keyHex) p.key_hex = keyHex;
      const r = await call<{ patches: PatchEntry[] }>("patch", "unpack_xor", p);
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  decodeStrings: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ patches: PatchEntry[] }>("patch", "decode_strings", { dry_run: get().dryRun });
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  writeBytes: async (addr, hex) => {
    await call("patch", "write_bytes", { addr, hex });
  },
  revertAll: async () => {
    await call("patch", "revert_all");
    set({ patches: [], journal: [] });
  },
  refreshJournal: async () => {
    try {
      const r = await call<{ entries: JournalEntry[] }>("patch", "journal");
      set({ journal: r.entries, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },
  fullPass: async () => {
    set({ busy: true, error: null });
    try {
      const r = await call<{ patches: PatchEntry[] }>("patch", "full_pass", { dry_run: get().dryRun });
      set({ patches: r.patches, busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
  rebuild: async () => {
    set({ busy: true, error: null });
    try {
      await call("patch", "rebuild");
      set({ busy: false });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },
}));
