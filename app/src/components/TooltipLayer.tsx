// app/src/components/TooltipLayer.tsx
// one global tooltip instead of the native title attribute, any element can
// opt in with data-tip

import { useEffect, useRef, useState } from "react";

type Placed = {
  text: string;
  left: number;
  top: number;
  below: boolean;
};

/** Long enough not to flicker while the cursor crosses a toolbar. */
const kDelayMs = 380;
const kGap = 7;
const kMargin = 6;

export default function TooltipLayer() {
  const [tip, setTip] = useState<Placed | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bubbleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const cancel = () => {
      if (timer.current !== null) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      setTip(null);
    };

    const onOver = (e: PointerEvent) => {
      const host = (e.target as Element | null)?.closest?.("[data-tip]");
      if (!(host instanceof HTMLElement)) {
        cancel();
        return;
      }
      const text = host.dataset.tip ?? "";
      if (text === "") {
        cancel();
        return;
      }
      if (timer.current !== null) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        const r = host.getBoundingClientRect();
        // Prefer below; flip above when the element sits near the bottom edge
        // (the status bar and Output pane are full of tooltip targets)
        const below = r.bottom + 34 < window.innerHeight;
        setTip({
          text,
          left: r.left + r.width / 2,
          top: below ? r.bottom + kGap : r.top - kGap,
          below,
        });
      }, kDelayMs);
    };

    // Any interaction dismisses: a tooltip lingering over a menu that just
    // opened is worse than no tooltip
    document.addEventListener("pointerover", onOver, true);
    document.addEventListener("pointerdown", cancel, true);
    document.addEventListener("wheel", cancel, true);
    document.addEventListener("keydown", cancel, true);
    window.addEventListener("blur", cancel);
    return () => {
      document.removeEventListener("pointerover", onOver, true);
      document.removeEventListener("pointerdown", cancel, true);
      document.removeEventListener("wheel", cancel, true);
      document.removeEventListener("keydown", cancel, true);
      window.removeEventListener("blur", cancel);
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  // Clamp horizontally once the bubble has a measured width
  useEffect(() => {
    const el = bubbleRef.current;
    if (el === null || tip === null) return;
    const half = el.offsetWidth / 2;
    const clamped = Math.min(
      Math.max(tip.left, half + kMargin),
      window.innerWidth - half - kMargin,
    );
    if (Math.abs(clamped - tip.left) > 0.5) setTip({ ...tip, left: clamped });
  }, [tip]);

  if (tip === null) return null;

  return (
    <div
      ref={bubbleRef}
      className="tooltip"
      role="tooltip"
      style={{
        left: tip.left,
        top: tip.top,
        transform: `translate(-50%, ${tip.below ? "0" : "-100%"})`,
      }}
    >
      {tip.text}
    </div>
  );
}
