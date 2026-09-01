import React from "react";
import ReactDOM from "react-dom/client";
import App from "@/App";
// Bundled rather than system-resolved: the ImGui shell shipped its own faces via
// FreeType, and the layout is tuned to these metrics
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@/styles/tokens.css";
import "@/styles/app.css";
// Imported for its side effect: the store applies `data-motion` to <html> on
// creation, before first paint, so nothing animates against the wrong setting
import "@/store/motion";

const root = document.getElementById("root");
if (root === null) throw new Error("#root missing from index.html");

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
