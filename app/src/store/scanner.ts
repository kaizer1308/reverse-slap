// app/src/store/scanner.ts
// scanner parameters and the displayed page of hits, the result set itself
// lives in the engine

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type Hit = {
  addr: number;
  bits: number;
  formatted: string;
  type: string;
};

export type ScanState = {
  active: boolean;
  pid: number;
  total: number;
  width: string;
  kind: string;
};

export const kWidths = [
  "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "all",
] as const;

/** First pass can only seed; the comparison kinds need a previous result set. */
export const kFirstKinds = ["exact", "unknown"] as const;
export const kNextKinds = [
  "exact", "between", "bigger", "smaller",
  "increased", "decreased", "changed", "unchanged",
] as const;

type ScannerStore = {
  width: string;
  kind: string;
  value: string;
  value2: string;
  hits: Hit[];
  total: number;
  hasState: boolean;
  busy: boolean;
  error: string | null;

  set: (patch: Partial<Pick<ScannerStore, "width" | "kind" | "value" | "value2">>) => void;
  refreshState: () => Promise<void>;
  scan: (rescan: boolean) => Promise<void>;
  reset: () => Promise<void>;
};

export const useScanner = create<ScannerStore>((set, get) => ({
  width: "u32",
  kind: "exact",
  value: "",
  value2: "",
  hits: [],
  total: 0,
  hasState: false,
  busy: false,
  error: null,

  set: (patch) => set(patch),

  refreshState: async () => {
    try {
      const st = await call<ScanState>("memory", "scan_state");
      set({ hasState: st.active === true, total: st.total ?? 0 });
    } catch {
      set({ hasState: false });
    }
  },

  scan: async (rescan) => {
    const { width, kind, value, value2 } = get();
    set({ busy: true, error: null });
    try {
      // max_results caps the scan itself; limit caps the page handed back, and
      // it defaults to 100, without it the results pane silently shows a
      // hundredth of what was found
      const params: Record<string, unknown> = {
        width,
        kind,
        max_results: 100000,
        limit: 1000,
      };
      // `unknown` seeds a snapshot with no comparand; every other kind needs one
      if (kind !== "unknown") {
        params.value = value.includes(".") ? Number(value) : value;
        if (kind === "between") params.value2 = value2.includes(".") ? Number(value2) : value2;
      }
      const res = await call<{ hits: Hit[]; total: number }>(
        "memory",
        rescan ? "rescan" : "scan",
        params,
      );
      set({ hits: res.hits ?? [], total: res.total ?? 0, hasState: true });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  reset: async () => {
    await call("memory", "scan_reset").catch(() => undefined);
    set({ hits: [], total: 0, hasState: false, error: null });
  },
}));
