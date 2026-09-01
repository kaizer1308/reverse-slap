// app/scripts/check-api.mjs
//
// Cross-checks every (tool, action, param) the front end sends against the
// engine's own tools/list schema
//
// This exists because `target.dump_module` was called with `output_path` when the
// schema says `path`: the request was well-formed JSON, the tool rejected it at
// runtime, and nothing before the user clicking Dump could have caught it
// Types cannot help here, the wire contract lives in C++
//
//   node scripts/check-api.mjs [port]
//
// Exits non-zero on any unknown tool, action, or parameter

import { readFileSync } from "node:fs";
import { globSync } from "node:fs";

const port = process.argv[2] ?? "8765";
const base = `http://127.0.0.1:${port}`;

// `app` is reachable over /api only and deliberately absent from tools/list, so
// its surface is declared here instead
const kAppActions = {
  status: [],
  ping: [],
  output: ["since"],
  output_clear: [],
  log: ["text"],
  diag: ["since_revision", "limit"],
  shutdown: ["reason"],
};

async function schemas() {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  if (!res.ok) throw new Error(`tools/list failed: HTTP ${res.status}`);
  const body = await res.json();
  const out = new Map();
  for (const t of body.result.tools) {
    const props = t.inputSchema?.properties ?? {};
    out.set(t.name, {
      actions: new Set(props.action?.enum ?? []),
      params: new Set(Object.keys(props)),
    });
  }
  return out;
}

/** Pull `call("tool", "action", { a, b })` triples out of the sources. */
function callSites() {
  const sites = [];
  const files = globSync("src/**/*.{ts,tsx}");
  const re =
    /call<[^>]*>\(\s*"([a-z]+)"\s*,\s*"([a-z_0-9]+)"\s*(?:,\s*\{([^}]*)\})?|call\(\s*"([a-z]+)"\s*,\s*"([a-z_0-9]+)"\s*(?:,\s*\{([^}]*)\})?/g;
  for (const file of files) {
    const src = readFileSync(file, "utf8");
    for (const m of src.matchAll(re)) {
      const tool = m[1] ?? m[4];
      const action = m[2] ?? m[5];
      const blob = m[3] ?? m[6] ?? "";
      sites.push({ file, tool, action, params: objectKeys(blob) });
    }
  }
  return sites;
}

/**
 * Keys of an inline object literal. Splitting on top-level commas and taking
 * what precedes `:` matters: a naive scan treats the *value* in `addr: va` as a
 * key and reports `va` as an unknown parameter.
 */
function objectKeys(blob) {
  const keys = [];
  let depth = 0;
  let part = "";
  const flush = () => {
    const text = part.trim();
    part = "";
    if (text === "") return;
    // Spread of a conditional, e.g. `...(label ? { label } : {})`, recurse
    if (text.startsWith("...")) {
      for (const inner of text.matchAll(/\{([^}]*)\}/g)) keys.push(...objectKeys(inner[1]));
      return;
    }
    const colon = text.indexOf(":");
    const name = (colon === -1 ? text : text.slice(0, colon)).trim();
    if (/^[A-Za-z_$][\w$]*$/.test(name)) keys.push(name);
  };
  for (const ch of blob) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      flush();
      continue;
    }
    part += ch;
  }
  flush();
  return keys;
}

const known = await schemas();
const sites = callSites();
let bad = 0;

for (const s of sites) {
  const spec =
    s.tool === "app"
      ? { actions: new Set(Object.keys(kAppActions)), params: new Set(Object.values(kAppActions).flat()) }
      : known.get(s.tool);

  if (spec === undefined) {
    console.log(`  UNKNOWN TOOL   ${s.tool}.${s.action}  (${s.file})`);
    bad++;
    continue;
  }
  if (!spec.actions.has(s.action)) {
    console.log(`  UNKNOWN ACTION ${s.tool}.${s.action}  (${s.file})`);
    bad++;
    continue;
  }
  for (const p of s.params) {
    if (p === "action") continue;
    if (!spec.params.has(p)) {
      console.log(`  UNKNOWN PARAM  ${s.tool}.${s.action} -> "${p}"  (${s.file})`);
      bad++;
    }
  }
}

console.log(
  `\nchecked ${sites.length} call sites against ${known.size} tool schemas: ` +
    (bad === 0 ? "all valid" : `${bad} problem(s)`),
);
process.exit(bad === 0 ? 0 : 1);
