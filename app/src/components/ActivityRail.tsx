// app/src/components/ActivityRail.tsx
// The icon strip on the left of the mockup. Chooses what the left panel shows

import { Boxes, Radio, ScrollText, Settings, Target } from "lucide-react";

export type RailView = "targets" | "modules" | "scripts" | "frida";

const kItems: readonly { id: RailView; label: string; Icon: typeof Target }[] = [
  { id: "targets", label: "Targets", Icon: Target },
  { id: "modules", label: "Modules", Icon: Boxes },
  { id: "scripts", label: "Scripts", Icon: ScrollText },
  { id: "frida", label: "Frida", Icon: Radio },
];

type Props = {
  active: RailView;
  onSelect: (view: RailView) => void;
  onSettings: () => void;
};

export default function ActivityRail({ active, onSelect, onSettings }: Props) {
  return (
    <div className="rail">
      {kItems.map(({ id, label, Icon }) => (
        <button
          key={id}
          className="rail-button"
          data-active={active === id}
          data-tip={label}
          aria-label={label}
          onClick={() => onSelect(id)}
        >
          <Icon size={18} strokeWidth={1.75} />
        </button>
      ))}

      <div className="rail-spacer" />

      <button
        className="rail-button"
        data-tip="Settings"
        aria-label="Settings"
        onClick={onSettings}
      >
        <Settings size={18} strokeWidth={1.75} />
      </button>
    </div>
  );
}
