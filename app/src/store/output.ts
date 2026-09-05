// app/src/store/output.ts
// output pane, lines live in the engine ring so a reconnect replays what was
// missed via the seq cursor

import { create } from "zustand";
import * as events from "@/lib/events";
import { call } from "@/lib/rpc";

export type OutputLine = { seq: number; ms: number; text: string };

const kMaxLines = 4096;

type OutputStore = {
  lines: OutputLine[];
  revision: number;
  clear: () => Promise<void>;
  attach: () => () => void;
  replayFrom: (revision: number) => Promise<void>;
};

export const useOutput = create<OutputStore>((set, get) => ({
  lines: [],
  revision: 0,

  attach: () => {
    const offOutput = events.on("output", (line) =>
      set((s) => {
        // Out-of-order or duplicate frames (reconnect overlap) are dropped by
        // sequence rather than deduplicated by text
        if (line.seq <= s.revision) return s;
        const lines = [...s.lines.slice(-(kMaxLines - 1)), line];
        return {
          lines,
          revision: line.seq,
        };
      }),
    );

    const offClear = events.on("output.cleared", () => set({ lines: [], revision: 0 }));

    // On (re)connect the engine tells us where its ring is; pull the gap
    const offHello = events.on("hello", ({ output_revision }) => {
      if (output_revision < get().revision) set({ lines: [], revision: 0 });
      void get().replayFrom(get().revision > 0 ? get().revision : Math.max(0, output_revision - kMaxLines));
    });
    return () => { offOutput(); offClear(); offHello(); };
  },

  replayFrom: async (revision) => {
    try {
      const res = await call<{ revision: number; lines: OutputLine[] }>(
        "app",
        "output",
        { since: revision },
      );
      if (res.lines.length === 0) return;
      set((s) => {
        const merged = [...s.lines, ...res.lines.filter((l) => l.seq > s.revision)];
        return {
          lines: merged.length > kMaxLines ? merged.slice(-kMaxLines) : merged,
          revision: res.revision,
        };
      });
    } catch {
      // Nothing to show is better than a thrown error in a log pane
    }
  },

  clear: async () => {
    await call("app", "output_clear");
    set({ lines: [], revision: 0 });
  },
}));
