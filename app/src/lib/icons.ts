// app/src/lib/icons.ts
// process icon cache, the engine hands back raw bgra and the canvas turns it
// into a data url, requests deduped and batched

import { call } from "./rpc";

type IconBits = { width: number; height: number; bgra_b64?: string };

const cache = new Map<string, string | null>(); // path -> data URL, null = none
const pending = new Set<string>();
const waiters = new Set<() => void>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;

/** Notified when a batch resolves, so components can re-render. */
export function onIconsResolved(fn: () => void): () => void {
  waiters.add(fn);
  return () => {
    waiters.delete(fn);
  };
}

function toDataUrl(bits: IconBits): string | null {
  if (!bits.bgra_b64 || bits.width === 0 || bits.height === 0) return null;

  const binary = atob(bits.bgra_b64);
  const expected = bits.width * bits.height * 4;
  if (binary.length < expected) return null;

  const canvas = document.createElement("canvas");
  canvas.width = bits.width;
  canvas.height = bits.height;
  const ctx = canvas.getContext("2d");
  if (ctx === null) return null;

  const image = ctx.createImageData(bits.width, bits.height);
  // BGRA (Win32 DIB order) -> RGBA (ImageData order)
  for (let i = 0; i < expected; i += 4) {
    image.data[i] = binary.charCodeAt(i + 2);
    image.data[i + 1] = binary.charCodeAt(i + 1);
    image.data[i + 2] = binary.charCodeAt(i);
    image.data[i + 3] = binary.charCodeAt(i + 3);
  }
  ctx.putImageData(image, 0, 0);
  return canvas.toDataURL("image/png");
}

async function flush(): Promise<void> {
  flushTimer = null;
  // The engine caps a single request at 64 paths; drain in chunks so a full
  // process list still resolves
  const batch = [...pending].slice(0, 64);
  if (batch.length === 0) return;
  for (const p of batch) pending.delete(p);

  try {
    const res = await call<{ icons: Record<string, IconBits> }>("target", "icon", {
      paths: batch,
    });
    for (const path of batch) {
      const bits = res.icons[path];
      cache.set(path, bits ? toDataUrl(bits) : null);
    }
  } catch {
    // Mark them resolved-as-missing so a failing path is not retried forever
    for (const path of batch) cache.set(path, null);
  }

  for (const fn of waiters) fn();
  if (pending.size > 0) schedule();
}

function schedule(): void {
  if (flushTimer !== null) return;
  // One frame of coalescing: a virtualized table asks for every visible row in
  // the same tick
  flushTimer = setTimeout(() => void flush(), 16);
}

/**
 * Data URL for a process image, or null when there is no icon. Returns
 * undefined while the lookup is still in flight, render a placeholder and wait
 * for onIconsResolved.
 */
export function iconFor(path: string | undefined): string | null | undefined {
  if (!path) return null;
  const hit = cache.get(path);
  if (hit !== undefined) return hit;
  if (!pending.has(path)) {
    pending.add(path);
    schedule();
  }
  return undefined;
}
