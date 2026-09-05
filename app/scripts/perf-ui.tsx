import React from "react";
import { createRoot } from "react-dom/client";
import OutputPanel from "../src/components/panels/OutputPanel";
import { useOutput } from "../src/store/output";
import "../src/styles/tokens.css";
import "../src/styles/app.css";
document.documentElement.dataset.theme = "obsidian";
const style = document.createElement("style");
style.textContent = "#root .panel { width: 700px; flex: 1; }";
document.head.appendChild(style);

const lines = Array.from({ length: 4096 }, (_, i) => ({
  seq: i + 1, ms: 1700000000000 + i,
  text: `Line ${i + 1}: ${i % 5 === 0 ? "wrapped message ".repeat(30) : "short message"}`,
}));
useOutput.setState({ lines, revision: 4096, clear: async () => useOutput.setState({ lines: [], revision: 0 }) });
// This fixture never contacts a running engine.
globalThis.fetch = async (_input, init) => new Response(JSON.stringify({ ok: true, data: {
  revision: 1000, entries: JSON.parse(String(init?.body)).params?.since_revision === 1000 ? [] : Array.from({ length: 1000 }, (_, i) => ({
    ms: 1700000000000 + i, level: "info", tag: "fixture", message: `Diagnostic ${i + 1}`,
  })),
} }), { headers: { "Content-Type": "application/json" } });
createRoot(document.getElementById("root")!).render(
  <React.StrictMode><div style={{ height: 400, width: 700, display: "flex" }}><OutputPanel /></div></React.StrictMode>,
);
