// app/src/components/ProcessIcon.tsx
// The per-row app icon from the mockup. Falls back to a generic glyph for system
// processes and anything the shell has no icon for

import { useEffect, useState } from "react";
import { AppWindow } from "lucide-react";
import { iconFor, onIconsResolved } from "@/lib/icons";

type Props = { path?: string; size?: number };

export default function ProcessIcon({ path, size = 14 }: Props) {
  const [, bump] = useState(0);

  useEffect(() => onIconsResolved(() => bump((n) => n + 1)), []);

  const url = iconFor(path);

  if (typeof url === "string") {
    return (
      <img
        src={url}
        width={size}
        height={size}
        alt=""
        draggable={false}
        style={{ display: "block", flex: "none" }}
      />
    );
  }

  // undefined = still resolving, null = no icon. Both render the placeholder so
  // the row height never shifts
  return (
    <span
      className="faint"
      style={{
        display: "grid",
        placeItems: "center",
        width: size,
        height: size,
        flex: "none",
        opacity: url === undefined ? 0.25 : 0.5,
      }}
    >
      <AppWindow size={size - 2} strokeWidth={1.75} />
    </span>
  );
}
