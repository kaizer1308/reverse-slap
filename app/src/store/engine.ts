// app/src/store/engine.ts
// connection, boot progress and the state the status bar mirrors, all fed by
// events, nothing polls

import { create } from "zustand";
import * as events from "@/lib/events";
import { call } from "@/lib/rpc";
import { resolveEndpoint } from "@/lib/endpoint";
import { useDisasm } from "@/store/disasm";

export type BootStage = {
  stage: number;
  total: number;
  label: string;
  done: boolean;
};

export type TargetState = { attached: boolean; pid?: number; name?: string };

export type HypeState = {
  has_image: boolean;
  image: string;
  present: boolean;
  ready: boolean;
  running: boolean;
  progress: number;
  error: string;
};

type EngineStore = {
  connected: boolean;
  boot: BootStage;
  backend: { badge: string; kernel: boolean };
  target: TargetState;
  hype: HypeState;
  quitting: string | null;
  startupError: string | null;
  start: () => Promise<void>;
};

const kInitialBoot: BootStage = { stage: 0, total: 6, label: "connecting", done: false };
const kInitialHype: HypeState = {
  has_image: false,
  image: "",
  present: false,
  ready: false,
  running: false,
  progress: 0,
  error: "",
};
let starting: Promise<void> | undefined;

export const useEngine = create<EngineStore>((set) => ({
  connected: false,
  boot: kInitialBoot,
  backend: { badge: "user", kernel: false },
  target: { attached: false },
  hype: kInitialHype,
  quitting: null,
  startupError: null,

  start: () => starting ??= (async () => {
    set({ startupError: null });
    await resolveEndpoint();

    const refreshStatus = async () => {
      try {
        const status = await call<{ backend: string; target: TargetState }>("app", "status");
        set({
          backend: { badge: status.backend, kernel: status.backend === "kernel" },
          target: status.target,
          boot: { stage: 6, total: 6, label: "ready", done: true },
          startupError: null,
        });
      } catch (error) {
        set({ startupError: error instanceof Error ? error.message : String(error) });
      }
    };
    // Boot/backend events can precede subscription. Snapshot after each stream
    // open, not before the engine accepts connections, and again on reconnect.
    events.onConnectionChange((connected) => {
      set({ connected });
      if (connected) void refreshStatus();
    });
    events.on("boot.stage", (boot) => set({ boot }));
    events.on("backend.changed", (backend) => set({ backend }));
    events.on("target.changed", (target) => set({ target }));
    events.on("hype.progress", (hype) => {
      set({ hype });
      // Let the disassembly store refresh its function list when background
      // analysis completes (the fast native index queried at load time misses
      // hyperion-only functions, e.g. every method of a .NET/IL image).
      useDisasm.getState().onHypeProgress(hype.ready, hype.has_image);
    });
    events.on("app.quitting", ({ reason }) => set({ quitting: reason }));
    events.connect();

  })().catch((error: unknown) => {
    starting = undefined;
    set({ startupError: error instanceof Error ? error.message : String(error) });
  }),
}));
