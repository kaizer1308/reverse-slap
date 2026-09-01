// app/src/store/theme.ts
// theme pick, palettes are css, this only picks the live block and remembers

import { create } from "zustand";

export type ThemeName = "obsidian" | "nord-slop" | "blood-orange";

export const kThemes: readonly { id: ThemeName; label: string }[] = [
  { id: "obsidian", label: "Obsidian" },
  { id: "nord-slop", label: "Nord-slop" },
  { id: "blood-orange", label: "Blood-orange" },
];

const kStorageKey = "reverse-slop.theme";

function initial(): ThemeName {
  const saved = localStorage.getItem(kStorageKey);
  return kThemes.some((t) => t.id === saved) ? (saved as ThemeName) : "obsidian";
}

function apply(name: ThemeName): void {
  document.documentElement.setAttribute("data-theme", name);
}

type ThemeStore = {
  theme: ThemeName;
  setTheme: (name: ThemeName) => void;
};

export const useTheme = create<ThemeStore>((set) => {
  const theme = initial();
  apply(theme);
  return {
    theme,
    setTheme: (name) => {
      apply(name);
      localStorage.setItem(kStorageKey, name);
      set({ theme: name });
    },
  };
});
