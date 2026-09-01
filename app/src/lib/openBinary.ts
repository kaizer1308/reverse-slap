// app/src/lib/openBinary.ts
// file picker, tauri dialog in the shell and a prompt in a plain browser

import { useDisasm } from "@/store/disasm";

export async function openBinary(): Promise<void> {
  let path: string | null = null;

  try {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const picked = await dialog.open({
      multiple: false,
      directory: false,
      title: "Open binary for analysis",
      filters: [
        { name: "Executables", extensions: ["exe", "dll", "sys", "efi", "bin"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    path = typeof picked === "string" ? picked : null;
  } catch {
    const typed = window.prompt("Path to binary");
    path = typed !== null && typed.trim() !== "" ? typed.trim() : null;
  }

  if (path !== null) await useDisasm.getState().loadFile(path);
}
