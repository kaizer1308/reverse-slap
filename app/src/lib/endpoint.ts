// app/src/lib/endpoint.ts
// where the engine is, the tauri command first, then the well known port for
// plain browser dev

import { setEndpoint, type Endpoint, health } from "./rpc";

const kDefaultPort = 8765;

type TauriGlobal = {
  core?: { invoke?: (cmd: string) => Promise<unknown> };
};

function tauriInvoke(): ((cmd: string) => Promise<unknown>) | null {
  const t = (window as unknown as { __TAURI__?: TauriGlobal }).__TAURI__;
  return t?.core?.invoke ?? null;
}

export const isTauri = (): boolean => tauriInvoke() !== null;

export async function resolveEndpoint(): Promise<Endpoint> {
  const invoke = tauriInvoke();
  if (invoke) {
    try {
      const ep = (await invoke("engine_endpoint")) as Partial<Endpoint>;
      if (typeof ep?.port === "number" && ep.port > 0) {
        const resolved: Endpoint = { port: ep.port, token: ep.token ?? "" };
        setEndpoint(resolved);
        return resolved;
      }
    } catch {
      // Fall through to the default port: the engine may already be up from a
      // previous run and advertising itself on the well-known port
    }
  }

  const fallback: Endpoint = { port: kDefaultPort, token: "" };
  setEndpoint(fallback);
  return fallback;
}

/** Poll /health until the engine answers or the deadline passes. */
export async function waitForEngine(timeoutMs = 60_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await health()) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}
