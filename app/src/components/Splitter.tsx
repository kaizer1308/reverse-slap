// app/src/components/Splitter.tsx
// drag handle that writes a css custom property, keeps the layout in css grid

import { useCallback, useRef } from "react";

type Props = {
  axis: "x" | "y";
  /** CSS variable to drive, e.g. "--left-w". */
  variable: string;
  /** Element the variable is set on. Defaults to the app root. */
  target?: React.RefObject<HTMLElement>;
  min: number;
  max: number;
  /** Drag right/down shrinks instead of grows (handles on a panel's left edge). */
  invert?: boolean;
};

export default function Splitter({ axis, variable, target, min, max, invert }: Props) {
  const dragging = useRef(false);
  const ref = useRef<HTMLDivElement>(null);

  const onPointerDown = useCallback(
    (down: React.PointerEvent<HTMLDivElement>) => {
      const host = target?.current ?? document.documentElement;
      const styles = getComputedStyle(host);
      const start = parseFloat(styles.getPropertyValue(variable)) || min;
      const origin = axis === "x" ? down.clientX : down.clientY;

      dragging.current = true;
      ref.current?.setAttribute("data-dragging", "true");
      down.currentTarget.setPointerCapture(down.pointerId);

      const onMove = (move: PointerEvent) => {
        if (!dragging.current) return;
        const now = axis === "x" ? move.clientX : move.clientY;
        const delta = (now - origin) * (invert === true ? -1 : 1);
        const next = Math.min(max, Math.max(min, start + delta));
        host.style.setProperty(variable, `${Math.round(next)}px`);
      };

      const onUp = () => {
        dragging.current = false;
        ref.current?.removeAttribute("data-dragging");
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
      };

      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    },
    [axis, variable, target, min, max, invert],
  );

  return (
    <div ref={ref} className="splitter" data-axis={axis} onPointerDown={onPointerDown} />
  );
}
