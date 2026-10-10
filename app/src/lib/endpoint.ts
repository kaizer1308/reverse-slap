// app/src/lib/endpoint.ts
// where the engine is, the tauri command first, then the well known port for
// plain browser dev

import { setEndpoint, type Endpoint, health } from "./rpc";
import { invoke, isTauri as inTauri } from "@tauri-apps/api/core";

const kDefaultPort = 8765;

export const isTauri = (): boolean => typeof window !== "undefined" && inTauri();

export async function resolveEndpoint(): Promise<Endpoint> {
  if (isTauri()) {
    // SDK IPC is available even when withGlobalTauri is disabled. Native
    // failures must not silently connect to an unrelated default-port engine.
    const ep = await invoke<Partial<Endpoint>>("engine_endpoint");
    const port = ep?.port;
    const token = ep?.token;
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535 ||
        typeof token !== "string") {
      throw new Error("invalid engine endpoint from native bridge");
    }
    const resolved: Endpoint = { port, token };
    setEndpoint(resolved);
    return resolved;
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
