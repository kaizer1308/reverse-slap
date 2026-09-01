// app/src/store/motion.ts
// motion preference, the os reduced motion setting is the default not the law

import { create } from "zustand";

export type MotionPref = "on" | "auto" | "off";

export const kMotionOptions: readonly { id: MotionPref; label: string; hint: string }[] = [
  { id: "on", label: "On", hint: "always animate" },
  { id: "auto", label: "Auto", hint: "follow the Windows animation setting" },
  { id: "off", label: "Off", hint: "no animation" },
];

const kStorageKey = "reverse-slop.motion";

function initial(): MotionPref {
  const saved = localStorage.getItem(kStorageKey);
  return saved === "on" || saved === "auto" || saved === "off" ? saved : "on";
}

/** CSS reads `data-motion` on <html>; see the motion section of app.css. */
function apply(pref: MotionPref): void {
  document.documentElement.setAttribute("data-motion", pref);
}

/** Whether the OS currently asks for reduced motion, for the Settings hint. */
export function osPrefersReduced(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

type MotionStore = {
  motion: MotionPref;
  setMotion: (pref: MotionPref) => void;
};

export const useMotion = create<MotionStore>((set) => {
  const motion = initial();
  apply(motion);
  return {
    motion,
    setMotion: (pref) => {
      apply(pref);
      localStorage.setItem(kStorageKey, pref);
      set({ motion: pref });
    },
  };
});
