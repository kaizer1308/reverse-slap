// app/src/lib/rpc.ts
// thin transport over the engines /api surface, the ui and an ai agent drive
// exactly the same tool actions

export type Endpoint = { port: number; token: string };

export type ApiEnvelope<T> = { ok: boolean; data: T; id?: number | string };

let endpoint: Endpoint = { port: 8765, token: "" };

export function setEndpoint(next: Endpoint): void {
  endpoint = next;
}

export function getEndpoint(): Endpoint {
  return endpoint;
}

export function baseUrl(): string {
  return `http://127.0.0.1:${endpoint.port}`;
}

function headers(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (endpoint.token) h["Authorization"] = `Bearer ${endpoint.token}`;
  return h;
}

/** Thrown when a tool reports failure; `tool`/`action` aid the error surface. */
export class ToolError extends Error {
  constructor(
    readonly tool: string,
    readonly action: string,
    message: string,
  ) {
    super(`${tool}.${action}: ${message}`);
    this.name = "ToolError";
  }
}

type ToolFailure = { error?: string };

async function post(body: unknown): Promise<unknown> {
  const res = await fetch(`${baseUrl()}/api`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`engine returned HTTP ${res.status}`);
  return res.json();
}

/** Invoke one action. Rejects with ToolError when the tool reports failure. */
export async function call<T>(
  tool: string,
  action: string,
  params?: Record<string, unknown>,
): Promise<T> {
  const env = (await post({ tool, action, params: params ?? {} })) as ApiEnvelope<T>;
  if (!env.ok) {
    const failure = env.data as ToolFailure | undefined;
    throw new ToolError(tool, action, failure?.error ?? "unknown failure");
  }
  return env.data;
}

export type BatchRequest = {
  tool: string;
  action: string;
  params?: Record<string, unknown>;
};

/**
 * One round trip for several unrelated reads, opening a view usually needs
 * status plus a list plus module info, and stacking those latencies is the
 * difference between a snappy first paint and a visibly staged one.
 * Per-request failures are returned rather than thrown; the caller decides.
 */
export async function batch(
  requests: readonly BatchRequest[],
): Promise<ApiEnvelope<unknown>[]> {
  if (requests.length === 0) return [];
  const body = requests.map((r, i) => ({
    tool: r.tool,
    action: r.action,
    params: r.params ?? {},
    id: i,
  }));
  return (await post(body)) as ApiEnvelope<unknown>[];
}

/** Liveness probe used while waiting for a spawned engine to come up. */
export async function health(signal?: AbortSignal): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl()}/health`, { signal });
    return res.ok;
  } catch {
    return false;
  }
}
