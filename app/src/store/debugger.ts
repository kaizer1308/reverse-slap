// app/src/store/debugger.ts
// Debugger control surface, attach/detach, breakpoints, stepping, registers,
// callstack. Port of what src/ui/view_debugger.cpp drove directly

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type DbgStatus = {
  state: string;
  pid: number;
  mode: string;
  backend: string;
  hwbp_supported: boolean;
  kernel_active: boolean;
};

export type Regs = Record<string, number> & { tid: number };

// Field names come straight from mcp_tools.cpp, the callstack unwinder reports
// return addresses, not program counters, and events carry `address`/`text`
// rather than the `addr`/`symbol` an IDE-shaped API would use
export type Frame = {
  ret_addr: number;
  frame_ptr: number;
  snippet?: string;
  scanned?: boolean;
};

export type DbgEvent = {
  kind: string;
  tid: number;
  address: number;
  exc_code: number;
  text?: string;
};

export type Breakpoint = { addr: number; hw: boolean; oneShot: boolean };

const kIdle: DbgStatus = {
  state: "detached",
  pid: 0,
  mode: "-",
  backend: "user",
  hwbp_supported: false,
  kernel_active: false,
};

type DebuggerStore = {
  status: DbgStatus;
  regs: Regs | null;
  frames: Frame[];
  events: DbgEvent[];
  breakpoints: Breakpoint[];
  error: string | null;
  busy: boolean;

  refresh: () => Promise<void>;
  attach: (pid: number) => Promise<void>;
  detach: () => Promise<void>;
  setBreakpoint: (addr: number, hw: boolean) => Promise<void>;
  clearBreakpoint: (addr: number) => Promise<void>;
  step: (kind: "step_into" | "step_over" | "step_out" | "continue") => Promise<void>;
  waitHalt: (timeoutMs: number) => Promise<void>;
  reset: () => void;
};

/** Paused is the only state where registers and a callstack exist. */
export const isPaused = (s: DbgStatus): boolean =>
  s.state === "paused" || s.state === "halted" || s.state === "suspended";

export const useDebugger = create<DebuggerStore>((set, get) => ({
  status: kIdle,
  regs: null,
  frames: [],
  events: [],
  breakpoints: [],
  error: null,
  busy: false,

  refresh: async () => {
    try {
      const status = await call<DbgStatus>("debugger", "status");
      set({ status, error: null });

      // Registers and the callstack only exist while paused; asking otherwise
      // returns a tool error that would show up as a spurious red banner
      if (isPaused(status)) {
        const [regs, stack, events] = await Promise.allSettled([
          call<Regs>("debugger", "regs"),
          call<{ frames?: Frame[] }>("debugger", "callstack", { max_frames: 64 }),
          call<{ events: DbgEvent[] }>("debugger", "events"),
        ]);
        set({
          regs: regs.status === "fulfilled" ? regs.value : null,
          frames: stack.status === "fulfilled" ? (stack.value.frames ?? []) : [],
          events: events.status === "fulfilled" ? (events.value.events ?? []) : get().events,
        });
      } else {
        const events = await call<{ events: DbgEvent[] }>("debugger", "events")
          .catch(() => ({ events: [] as DbgEvent[] }));
        set({ regs: null, frames: [], events: events.events ?? [] });
      }
    } catch (e) {
      set({ status: kIdle, error: e instanceof Error ? e.message : String(e) });
    }
  },

  attach: async (pid) => {
    set({ busy: true, error: null });
    try {
      await call("debugger", "attach", { pid });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  detach: async () => {
    await call("debugger", "detach").catch(() => undefined);
    set({ regs: null, frames: [], breakpoints: [] });
    await get().refresh();
  },

  setBreakpoint: async (addr, hw) => {
    try {
      await call("debugger", "bp_set", { addr, hw });
      set((s) => ({
        breakpoints: [...s.breakpoints.filter((b) => b.addr !== addr), { addr, hw, oneShot: false }],
        error: null,
      }));
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  clearBreakpoint: async (addr) => {
    await call("debugger", "bp_clear", { addr }).catch(() => undefined);
    set((s) => ({ breakpoints: s.breakpoints.filter((b) => b.addr !== addr) }));
  },

  step: async (kind) => {
    set({ busy: true });
    try {
      await call("debugger", kind);
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  waitHalt: async (timeoutMs) => {
    set({ busy: true });
    try {
      await call("debugger", "wait_halt", { timeout_ms: timeoutMs });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  reset: () => set({ status: kIdle, regs: null, frames: [], events: [], breakpoints: [] }),
}));
