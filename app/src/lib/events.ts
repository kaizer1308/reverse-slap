// app/src/lib/events.ts
// eventsource wrapper over the engine stream, the engine pushes state
// changes and this hands them to subscribers

import { baseUrl, getEndpoint } from "./rpc";

export type EngineEvent =
  | { type: "hello"; data: { output_revision: number } }
  | { type: "output"; data: { seq: number; ms: number; text: string } }
  | { type: "output.cleared"; data: Record<string, never> }
  | {
      type: "boot.stage";
      data: { stage: number; total: number; label: string; done: boolean };
    }
  | {
      type: "target.changed";
      data: { attached: boolean; pid?: number; name?: string };
    }
  | { type: "backend.changed"; data: { badge: string; kernel: boolean } }
  | {
      type: "hype.progress";
      data: {
        has_image: boolean;
        image: string;
        present: boolean;
        ready: boolean;
        running: boolean;
        progress: number;
        error: string;
      };
    }
  | { type: "watch.list"; data: { entries: WatchEntry[] } }
  | { type: "watch.values"; data: { attached: boolean; values: WatchValue[] } }
  | { type: "app.quitting"; data: { reason: string } }
  | { type: "server.stopping"; data: Record<string, never> };

export type WatchEntry = {
  id: number;
  addr: number;
  width: string;
  label: string;
  freeze: boolean;
  frozen_bits: number;
  frozen_text: string;
};

export type WatchValue = {
  id: number;
  addr: number;
  ok: boolean;
  held: boolean;
  bits: number;
  text: string;
};

export type EventName = EngineEvent["type"];
type Handler = (data: unknown) => void;

const kEventNames: EventName[] = [
  "hello",
  "output",
  "output.cleared",
  "boot.stage",
  "target.changed",
  "backend.changed",
  "hype.progress",
  "watch.list",
  "watch.values",
  "app.quitting",
  "server.stopping",
];

const handlers = new Map<EventName, Set<Handler>>();
let source: EventSource | null = null;
let retry: ReturnType<typeof setTimeout> | null = null;
const statusHandlers = new Set<(open: boolean) => void>();

function emit(name: EventName, raw: string): void {
  const set = handlers.get(name);
  if (!set || set.size === 0) return;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  for (const fn of set) fn(parsed);
}

/** Subscribe to one event name. Returns an unsubscribe function. */
export function on<K extends EventName>(
  name: K,
  fn: (data: Extract<EngineEvent, { type: K }>["data"]) => void,
): () => void {
  const set = handlers.get(name) ?? new Set<Handler>();
  set.add(fn as Handler);
  handlers.set(name, set);
  return () => {
    set.delete(fn as Handler);
  };
}

/** Notified when the stream opens or drops, for the status-bar indicator. */
export function onConnectionChange(fn: (open: boolean) => void): () => void {
  statusHandlers.add(fn);
  return () => {
    statusHandlers.delete(fn);
  };
}

function setOpen(open: boolean): void {
  for (const fn of statusHandlers) fn(open);
}

export function connect(): void {
  disconnect();
  // EventSource cannot send an Authorization header, so a token-protected
  // engine takes it as a query parameter instead. The listener is loopback-only
  // and the URL never leaves this process
  const { token } = getEndpoint();
  const url = `${baseUrl()}/events${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const es = new EventSource(url);
  source = es;

  es.onopen = () => setOpen(true);
  es.onerror = () => {
    setOpen(false);
    // The engine may still be booting, or was restarted. Reconnect on a fixed
    // delay rather than letting EventSource hammer it
    if (retry === null && source === es) {
      retry = setTimeout(() => {
        retry = null;
        if (source === es) connect();
      }, 1000);
    }
  };
  for (const name of kEventNames) {
    es.addEventListener(name, (ev) => emit(name, (ev as MessageEvent<string>).data));
  }
}

export function disconnect(): void {
  if (retry !== null) {
    clearTimeout(retry);
    retry = null;
  }
  if (source) {
    source.close();
    source = null;
  }
}
