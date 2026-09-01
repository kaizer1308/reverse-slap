// app/src/lib/clipboard.ts
// copy to clipboard with a hidden textarea fallback for stubborn webviews

export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall through to the legacy path rather than failing the copy
    }
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  // Off-screen and inert: present in the layout so it can be selected, but
  // never visible and never part of a tab order
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  ta.style.pointerEvents = "none";
  document.body.appendChild(ta);
  ta.select();
  try {
    if (!document.execCommand("copy")) throw new Error("execCommand copy returned false");
  } finally {
    ta.remove();
  }
}
