// app/src/store/engine.ts
// connection, boot progress and the state the status bar mirrors, all fed by
// events, nothing polls

import { create } from "zustand";
import * as events from "@/lib/events";
import { call } from "@/lib/rpc";
import { resolveEndpoint } from "@/lib/endpoint";

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

  start: () => starting ??= (async () => {
    await resolveEndpoint();

    events.onConnectionChange((connected) => set({ connected }));
    events.on("boot.stage", (boot) => set({ boot }));
    events.on("backend.changed", (backend) => set({ backend }));
    events.on("target.changed", (target) => set({ target }));
    events.on("hype.progress", (hype) => set({ hype }));
    events.on("app.quitting", ({ reason }) => set({ quitting: reason }));
    events.connect();

    // The stream only carries changes from here on, so seed from a status read
    // A boot already finished before we connected would otherwise leave the
    // splash up forever waiting for a boot.stage event that never comes
    try {
      const status = await call<{
        backend: string;
        target: { attached: boolean; pid?: number; name?: string };
      }>("app", "status");
      set({
        backend: { badge: status.backend, kernel: status.backend === "kernel" },
        target: status.target,
        boot: { stage: 6, total: 6, label: "ready", done: true },
      });
    } catch {
      // Engine not up yet; the SSE retry loop and boot.stage events cover it
    }
  })().catch((error: unknown) => { starting = undefined; throw error; }),
}));
