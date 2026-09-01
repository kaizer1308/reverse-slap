// app/src/store/pe.ts
// Static PE headers for the loaded image, backs the PE Browser tab
// (src/ui/view_pe.cpp)

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type Section = {
  name: string;
  rva: number;
  vsize: number;
  raw_size: number;
  exec: boolean;
  writable: boolean;
  characteristics: number;
};

export type ImportDll = { dll: string; functions: string[] };
export type ExportEntry = { name: string; rva: number; ordinal: number };

export type PeInfo = {
  image?: string;
  pe32plus?: boolean;
  image_base?: number;
  entry_rva?: number;
  size_of_image?: number;
  sections: Section[];
  imports: ImportDll[];
  exports: ExportEntry[];
};

const kEmpty: PeInfo = { sections: [], imports: [], exports: [] };

type PeStore = {
  pe: PeInfo;
  loading: boolean;
  error: string | null;
  load: () => Promise<void>;
  reset: () => void;
};

export const usePe = create<PeStore>((set) => ({
  pe: kEmpty,
  loading: false,
  error: null,

  load: async () => {
    set({ loading: true, error: null });
    try {
      const pe = await call<PeInfo>("disasm", "pe");
      set({
        pe: {
          ...pe,
          sections: pe.sections ?? [],
          imports: pe.imports ?? [],
          exports: pe.exports ?? [],
        },
      });
    } catch (e) {
      set({ pe: kEmpty, error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ loading: false });
    }
  },

  reset: () => set({ pe: kEmpty, error: null }),
}));
