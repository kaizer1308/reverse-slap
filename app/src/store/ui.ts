// app/src/store/ui.ts
// Shell-level UI state that more than one component needs to reach: the settings
// dialog and which left panel the activity rail has selected

import { create } from "zustand";
import type { RailView } from "@/components/ActivityRail";

type UiStore = {
  rail: RailView;
  settingsOpen: boolean;
  setRail: (rail: RailView) => void;
  openSettings: () => void;
  closeSettings: () => void;
};

export const useUi = create<UiStore>((set) => ({
  rail: "targets",
  settingsOpen: false,
  setRail: (rail) => set({ rail }),
  openSettings: () => set({ settingsOpen: true }),
  closeSettings: () => set({ settingsOpen: false }),
}));
