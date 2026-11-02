#!/usr/bin/env node
// audit-invariants.mjs — source-level security invariant gate.
//
// Executable form of SECURITY.md §9 "Verification checklist". Hits are found
// on comment/string-masked source and attributed to their enclosing `fn` and
// its cfg(test) status, so legitimate hits are named exemptions rather than a
// raw grep count. Nothing is pinned to line numbers. Complements
// scripts/audit-network.mjs (build-output audit).
//
// Usage:  node scripts/audit-invariants.mjs   Exit: 0 = all hold, 1 = violation
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// repo-root-relative so printed paths match SECURITY.md §9
const REPO_ROOT = resolve(APP_DIR, "..", "..");
const WASM_SRC_DIR = join(APP_DIR, "gpg-wasm", "src");
const WASM_LIB = join(WASM_SRC_DIR, "lib.rs");

const rel = (p) => relative(REPO_ROOT, p).split(sep).join("/");

const SKIP_DIRS = new Set([
  "node_modules",
  ".output",
  ".wxt",
  ".turbo",
  ".cache",
  "dist",
  "coverage",
  "test-results",
  "playwright-report",
  "pkg", // wasm-pack generated bindings
  "target", // cargo build dir
]);

// ── Source masking ──────────────────────────────────────────────────
// Comments and string literals become equal-length spaces, so offsets and
// line numbers are preserved but text in them cannot match.

function maskTs(src) {
  const out = src.split("");
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k++) {
      if (out[k] !== "\n") out[k] = " ";
    }
  };
  let i = 0;
  let prevSignificant = "";
  // `/` starts a regex only after one of these; otherwise a quote inside a
  // regex would desync the scanner.
  const REGEX_PRECEDERS = new Set([
    "",
    "(",
    ",",
    "=",
    ":",
    "[",
    "!",
    "&",
    "|",
    "?",
    "{",
    "}",
    ";",
    "+",
    "-",
    "*",
    "%",
    "<",
    ">",
    "~",
    "^",
    "\n",
  ]);

  while (i < src.length) {
    const c = src[i];
    const c2 = src[i + 1];

    if (c === "/" && c2 === "/") {
      const end = src.indexOf("\n", i);
      blank(i, end === -1 ? src.length : end);
      i = end === -1 ? src.length : end;
      continue;
    }
    if (c === "/" && c2 === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") {
        if (src[j] === "\\") j++;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      prevSignificant = c;
      continue;
    }
    if (c === "`") {
      // Blank template text but keep `${…}` visible, so code in it is caught.
      let j = i + 1;
      let textStart = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") {
          blank(textStart, j);
          let depth = 1;
          let k = j + 2;
          while (k < src.length && depth > 0) {
            if (src[k] === "{") depth++;
            else if (src[k] === "}") depth--;
            k++;
          }
          j = k;
          textStart = j;
          continue;
        }
        j++;
      }
      blank(textStart, j);
      i = j + 1;
      prevSignificant = "`";
      continue;
    }
    if (c === "/" && REGEX_PRECEDERS.has(prevSignificant)) {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < src.length && src[j] !== "\n") {
        const d = src[j];
        if (d === "\\") {
          j += 2;
          continue;
        }
        if (d === "[") inClass = true;
        else if (d === "]") inClass = false;
        else if (d === "/" && !inClass) {
          closed = true;
          break;
        }
        j++;
      }
      if (closed) {
        blank(i + 1, j);
        i = j + 1;
        prevSignificant = "/";
        continue;
      }
    }
    if (!/\s/.test(c)) prevSignificant = c;
    else if (c === "\n") prevSignificant = "\n";
    i++;
  }
  return out.join("");
}

function maskRust(src) {
  const out = src.split("");
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k++) {
      if (out[k] !== "\n") out[k] = " ";
    }
  };
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const c2 = src[i + 1];

    if (c === "/" && c2 === "/") {
      const end = src.indexOf("\n", i);
      blank(i, end === -1 ? src.length : end);
      i = end === -1 ? src.length : end;
      continue;
    }
    if (c === "/" && c2 === "*") {
      // Rust block comments nest.
      let depth = 1;
      let j = i + 2;
      while (j < src.length && depth > 0) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      blank(i, j);
      i = j;
      continue;
    }
    // Raw strings: r"…", r#"…"#, br##"…"##
    const raw = /^(?:b?r)(#*)"/.exec(src.slice(i, i + 12));
    if (raw && (i === 0 || !/[A-Za-z0-9_]/.test(src[i - 1]))) {
      const hashes = raw[1];
      const open = i + raw[0].length;
      const terminator = `"${hashes}`;
      const end = src.indexOf(terminator, open);
      const stop = end === -1 ? src.length : end + terminator.length;
      blank(open, stop);
      i = stop;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") j++;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    // Char literal — only when it really closes, so lifetimes ('a) survive.
    if (c === "'") {
      const m = /^'(?:\\.|[^'\\])'/.exec(src.slice(i, i + 6));
      if (m) {
        blank(i + 1, i + m[0].length - 1);
        i += m[0].length;
        continue;
      }
    }
    i++;
  }
  return out.join("");
}

// ── Rust structural index ───────────────────────────────────────────
// Per line: innermost enclosing `fn` and whether it sits in a #[cfg(test)] item.
function indexRust(maskedSource) {
  const lines = maskedSource.split("\n");
  const fnName = new Array(lines.length).fill(null);
  const testGated = new Array(lines.length).fill(false);

  let depth = 0;
  let pendingFn = null;
  let pendingCfgTest = false;
  const fnStack = [];
  const gatedStack = [];

  const CFG_TEST = /^\s*#\s*\[\s*cfg\s*\(.*\btest\b.*\)\s*\]\s*$/;
  const ATTR_OR_BLANK = /^\s*(#\s*\[|$)/;

  for (let i = 0; i < lines.length; i++) {
    const code = lines[i];

    if (CFG_TEST.test(code)) {
      pendingCfgTest = true;
      testGated[i] = true;
      continue;
    }
    // Attributes between the cfg and its item must not cancel the gate.
    if (pendingCfgTest && ATTR_OR_BLANK.test(code)) {
      testGated[i] = true;
      continue;
    }

    const fnMatch = /(?:^|[^A-Za-z0-9_])fn\s+([A-Za-z_]\w*)/.exec(code);
    if (fnMatch && pendingFn === null) pendingFn = fnMatch[1];

    const before = depth;
    let opened = false;
    for (const ch of code) {
      if (ch === "{") {
        depth++;
        opened = true;
      } else if (ch === "}") depth--;
    }

    if (depth > before) {
      if (pendingCfgTest) {
        gatedStack.push({ closeDepth: before });
        pendingCfgTest = false;
      }
      if (pendingFn !== null) {
        fnStack.push({ name: pendingFn, closeDepth: before });
        pendingFn = null;
      }
    } else if (pendingCfgTest) {
      // single-line item: `#[cfg(test)] use x;` or `#[cfg(test)] fn f() { … }`
      if (opened || /;\s*$/.test(code)) {
        testGated[i] = true;
        pendingCfgTest = false;
        pendingFn = null;
      }
    }

    fnName[i] = fnStack.length ? fnStack[fnStack.length - 1].name : null;
    if (!testGated[i]) testGated[i] = gatedStack.length > 0;

    while (fnStack.length && depth <= fnStack[fnStack.length - 1].closeDepth) {
      fnStack.pop();
    }
    while (
      gatedStack.length &&
      depth <= gatedStack[gatedStack.length - 1].closeDepth
    ) {
      gatedStack.pop();
    }
  }

  return { lines, fnName, testGated };
}

// ── Rust source collection ──────────────────────────────────────────
// Globs gpg-wasm/src/*.rs (not just lib.rs) so a new module is covered the
// moment it lands. Unreadable (mid-write) files are skipped and named in the
// header, never silently assumed clean.

/// Modules lib.rs declares as `#[cfg(test)] mod x;` — the gate lives at the
/// declaration site, so per-line `testGated` cannot see it.
function cfgTestModules(libMasked) {
  const found = new Set();
  const lines = libMasked.split("\n");
  const CFG_TEST = /^\s*#\s*\[\s*cfg\s*\(.*\btest\b.*\)\s*\]\s*$/;
  for (let i = 0; i < lines.length; i++) {
    if (!CFG_TEST.test(lines[i])) continue;
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*(#\s*\[|$)/.test(lines[j])) continue;
      const m = /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;/.exec(
        lines[j],
      );
      if (m) found.add(m[1]);
      break;
    }
  }
  return found;
}

let RUST_CACHE = null;
function rustSources() {
  if (RUST_CACHE) return RUST_CACHE;
  const libMasked = maskRust(readFileSync(WASM_LIB, "utf-8"));
  const testOnlyMods = cfgTestModules(libMasked);

  let entries = [];
  try {
    entries = readdirSync(WASM_SRC_DIR);
  } catch {
    entries = [];
  }

  const files = [];
  const unreadable = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith(".rs")) continue;
    const full = join(WASM_SRC_DIR, entry);
    let src;
    try {
      src = readFileSync(full, "utf-8");
    } catch {
      unreadable.push(entry);
      continue;
    }
    const idx = indexRust(maskRust(src));
    // EXEMPTION: a `#[cfg(test)] mod x;` is not compiled into the shipped wasm.
    if (testOnlyMods.has(entry.slice(0, -3))) {
      idx.testGated = idx.testGated.map(() => true);
    }
    files.push({ path: full, rel: rel(full), raw: src.split("\n"), ...idx });
  }
  RUST_CACHE = { files, unreadable };
  return RUST_CACHE;
}

/// Every (file, line) pair across the scanned Rust sources.
function* rustLines() {
  for (const f of rustSources().files) {
    for (let i = 0; i < f.lines.length; i++) yield { f, i, code: f.lines[i] };
  }
}

/// True when the fn on `lines[fnLine]` has a `#[wasm_bindgen]` attribute.
/// Stops at the first real code line so a previous item's attribute can't count.
function isWasmExport(lines, fnLine) {
  for (let k = fnLine - 1; k >= 0; k--) {
    const t = lines[k].trim();
    if (t === "") continue;
    if (t.startsWith("#")) {
      if (/#\s*\[\s*wasm_bindgen/.test(t)) return true;
      continue;
    }
    return false;
  }
  return false;
}

/// Signature and body text of the fn on `lines[i]` (masked); null if unclosed.
function fnSpan(lines, i, searchFrom) {
  let depth = 0;
  let sigEnd = -1;
  let ci = lines[i].indexOf("(", searchFrom);
  if (ci === -1) return null;
  for (let li = i; li < lines.length && sigEnd === -1; li++, ci = 0) {
    const line = lines[li];
    for (; ci < line.length; ci++) {
      if (line[ci] === "(") depth++;
      else if (line[ci] === ")") {
        depth--;
        if (depth === 0) {
          sigEnd = li;
          break;
        }
      }
    }
  }
  if (sigEnd === -1) return null;

  let bodyStart = -1;
  let bodyEnd = -1;
  let bDepth = 0;
  for (let k = sigEnd; k < lines.length && bodyEnd === -1; k++) {
    for (const ch of lines[k]) {
      if (ch === "{") {
        if (bodyStart === -1) bodyStart = k;
        bDepth++;
      } else if (ch === "}") {
        bDepth--;
        if (bodyStart !== -1 && bDepth === 0) bodyEnd = k;
      }
    }
  }
  if (bodyStart === -1) return null;
  return {
    signature: lines.slice(i, sigEnd + 1).join("\n"),
    body: lines
      .slice(bodyStart, (bodyEnd === -1 ? lines.length - 1 : bodyEnd) + 1)
      .join("\n"),
  };
}

function collectSources(dir, exts) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith(".") && entry !== ".") continue;
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) files.push(...collectSources(full, exts));
    else if (exts.some((e) => entry.endsWith(e))) files.push(full);
  }
  return files;
}

let TS_CACHE = null;
function tsSources() {
  if (!TS_CACHE) {
    TS_CACHE = collectSources(APP_DIR, [".ts", ".tsx"]).map((file) => ({
      file,
      rel: rel(file),
      masked: maskTs(readFileSync(file, "utf-8")),
      raw: readFileSync(file, "utf-8").split("\n"),
    }));
  }
  return TS_CACHE;
}

function scanTs(regex, predicate) {
  const hits = [];
  for (const { rel: relPath, masked, raw } of tsSources()) {
    const lines = masked.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const re = new RegExp(regex.source, regex.flags.replace("g", "") + "g");
      let m;
      while ((m = re.exec(lines[i])) !== null) {
        const hit = {
          file: relPath,
          line: i + 1,
          match: m[0],
          text: (raw[i] ?? "").trim(),
        };
        if (!predicate || predicate(hit)) hits.push(hit);
      }
    }
  }
  return hits;
}

// ── Invariant 1 — KEY_STORE has exactly one live insert site ─────────
// SECURITY.md §9 check 1.
const invariantKeyStoreInsert = {
  id: "key-store-single-insert",
  name: "KEY_STORE has exactly one live insert_key() call site",
  expectation:
    "1 definition + exactly 1 non-test call site, inside parse_and_store_private_key()",
  why: "Every extra insert_key() call is another way a cert can reach KEY_STORE without going through an unlock, which is what makes 'keys only enter the store via unlock' true.",
  run() {
    const definitions = [];
    const liveCalls = [];
    const exempt = [];

    // All gpg-wasm modules, so a sibling module can't reach KEY_STORE unseen.
    for (const { f, i, code } of rustLines()) {
      if (!/\binsert_key\s*\(/.test(code)) continue;
      const hit = {
        file: f.rel,
        line: i + 1,
        text: (f.raw[i] ?? "").trim(),
        fn: f.fnName[i],
      };
      if (/\bfn\s+insert_key\s*\(/.test(code)) {
        definitions.push(hit);
        continue;
      }
      // EXEMPTION: #[cfg(test)]-gated call sites (the test-only `store_key`
      // shim). cfg(test) code never ships; detected structurally, not by line.
      if (f.testGated[i]) {
        exempt.push({ ...hit, reason: "#[cfg(test)]-gated" });
        continue;
      }
      liveCalls.push(hit);
    }

    const violations = [];
    if (definitions.length !== 1) {
      violations.push({
        summary: `expected 1 definition of insert_key, found ${definitions.length}`,
        hits: definitions,
      });
    }
    if (liveCalls.length !== 1) {
      violations.push({
        summary: `expected exactly 1 non-test insert_key() call site, found ${liveCalls.length}`,
        hits: liveCalls,
      });
    }
    const stray = liveCalls.filter(
      (h) => h.fn !== "parse_and_store_private_key",
    );
    if (stray.length) {
      violations.push({
        summary:
          "insert_key() called from outside parse_and_store_private_key()",
        hits: stray,
      });
    }

    return {
      violations,
      exempt,
      detail: `1 definition, ${liveCalls.length} live call site in ${liveCalls.map((h) => h.fn).join(", ") || "-"}, ${exempt.length} test-only exemption(s)`,
    };
  },
};

// ── Invariant 2 — that insert site is reachable only from unlock ─────
// SECURITY.md §9 check 2.
const UNLOCK_ENTRYPOINTS = ["unlock_with_password", "unlock_with_prf"];
const invariantUnlockOnly = {
  id: "insert-only-from-unlock",
  name: "parse_and_store_private_key() is called only from the unlock paths",
  expectation: `1 definition + exactly ${UNLOCK_ENTRYPOINTS.length} non-test call sites, from ${UNLOCK_ENTRYPOINTS.join(" / ")}`,
  why: "This is the sole path into KEY_STORE (invariant 1); if anything but an unlock can call it, a caller could load a private key without proving possession of the password/passkey.",
  run() {
    const definitions = [];
    const callers = [];
    const exempt = [];

    for (const { f, i, code } of rustLines()) {
      if (!/\bparse_and_store_private_key\s*\(/.test(code)) continue;
      const hit = {
        file: f.rel,
        line: i + 1,
        text: (f.raw[i] ?? "").trim(),
        fn: f.fnName[i],
      };
      if (/\bfn\s+parse_and_store_private_key\s*\(/.test(code)) {
        definitions.push(hit);
        continue;
      }
      // EXEMPTION: cfg(test) code ships nowhere.
      if (f.testGated[i]) {
        exempt.push({ ...hit, reason: "#[cfg(test)]-gated" });
        continue;
      }
      callers.push(hit);
    }

    const violations = [];
    if (definitions.length !== 1) {
      violations.push({
        summary: `expected 1 definition of parse_and_store_private_key, found ${definitions.length}`,
        hits: definitions,
      });
    }
    const stray = callers.filter((h) => !UNLOCK_ENTRYPOINTS.includes(h.fn));
    if (stray.length) {
      violations.push({
        summary: `called from ${stray.length} fn(s) that are not unlock entrypoints`,
        hits: stray,
      });
    }
    const missing = UNLOCK_ENTRYPOINTS.filter(
      (name) => !callers.some((h) => h.fn === name),
    );
    if (missing.length) {
      violations.push({
        summary: `expected unlock entrypoint(s) to call it but they don't: ${missing.join(", ")} - if an unlock path was renamed, update UNLOCK_ENTRYPOINTS`,
        hits: [],
      });
    }

    return {
      violations,
      exempt,
      detail: `1 definition, ${callers.length} call site(s): ${callers.map((h) => h.fn).join(", ") || "-"}`,
    };
  },
};

// ── Invariant 3 — no JS bypass of the wasm-secrets boundary ─────────
// SECURITY.md §9 check 3.
// Secret-bearing wasm exports must be reached only via src/lib/pgp/wasm-secrets.ts,
// which owns zeroization and the handle lifecycle.
const SECRET_WASM_EXPORTS = [
  "generateProtectedWith",
  "protectImportedWith",
  "unlockWith",
  "reprotectKeyWithPrf",
  "encryptKeyForExportWithHandle",
  "getKeyArmored",
  "argon2Derive",
  "initContactsSessionWithPrf",
  "encryptCanaryAndInitSession",
  "verifyCanaryAndInitSession",
  "encryptDraft",
  "decryptDraft",
  "initDraftSessionIfUnset",
  "dropDraftSession",
  // CRX signing keys (prefixes cover ...WithPassword and ...WithPrf).
  "generateCrxKeyWith",
  "importCrxKeyWith",
  "reprotectCrxKeyWithPassword",
  "unlockCrxWith",
  "exportCrxPrivateKeyPem",
  // age / SSH identities (prefixes). decryptAgeWithHandle takes a KEY_STORE
  // handle; dropSshIdentity's lifecycle belongs to the boundary module.
  "protectSshIdentityWith",
  "unlockSshIdentityWith",
  "reprotectSshIdentityWithPrf",
  "decryptAgeWithHandle",
  "dropSshIdentity",
  // Listed for its PASSWORD param; the plaintext it returns is user data and
  // crosses by design (as decryptWithHandle's does, which is not listed).
  "decryptWithPassword",
];
// EXEMPTION: the boundary module itself is *supposed* to make these calls.
const SECRETS_BOUNDARY = "apps/pgp/src/lib/pgp/wasm-secrets.ts";
// EXEMPTION: test/spec files, where `wasm` is a vi.hoisted mock — no key
// material exists. (`isTestFile` is defined with the console invariant.)
const invariantWasmBoundary = {
  id: "wasm-secrets-boundary",
  name: "secret-bearing wasm calls happen only in src/lib/pgp/wasm-secrets.ts",
  expectation: "must be empty outside the boundary module",
  why: "The boundary module is the only place that zeroizes inputs and tracks key handles; a direct wasm.* call elsewhere can leak plaintext key material into the JS heap or leave a handle unlocked.",
  run() {
    const re = new RegExp(`wasm\\.(?:${SECRET_WASM_EXPORTS.join("|")})`, "g");
    const all = scanTs(re);
    const exempt = [
      ...all
        .filter((h) => h.file === SECRETS_BOUNDARY)
        .map((h) => ({ ...h, reason: "boundary module" })),
      ...all
        .filter((h) => h.file !== SECRETS_BOUNDARY && isTestFile(h.file))
        .map((h) => ({ ...h, reason: "test/spec file - mocked wasm module" })),
    ];
    const bad = all.filter(
      (h) => h.file !== SECRETS_BOUNDARY && !isTestFile(h.file),
    );
    return {
      violations: bad.length
        ? [
            {
              summary: `${bad.length} direct wasm secret call(s) outside ${SECRETS_BOUNDARY}`,
              hits: bad,
            },
          ]
        : [],
      exempt,
      detail: `${all.length} secret wasm call(s), ${bad.length === 0 ? "all inside the boundary module or test mocks" : `${bad.length} OUTSIDE the boundary module`}`,
    };
  },
};

// ── Invariant 4 — owned secret params are wrapped in Zeroizing ───────
// SECURITY.md §9 check 4.
//
// Not "every *_with_password fn takes Vec<u8>" (unlock_* legitimately borrow
// and zeroize the derived key): whenever such a fn takes an owned secret by
// value, it must immediately move it into `Zeroizing`.
const SECRET_PARAM_NAMES = [
  "password",
  "passphrase",
  "source_passphrase",
  "prf_output",
  "stored_secret",
  // User content, not a credential, but as secret (store plaintext).
  "plaintext",
  // The age/SSH private key FILE — the secret itself, not a means to it.
  "key_file",
];
// Credential fns by the `_with_password` / `_with_prf` SUFFIX (any prefix, so
// new key types are covered), plus the store-sealing fns that own plaintext
// (SECURITY.md §11.2).
const SECRET_FN_RE =
  /\bfn\s+(\w*_with_(?:password|prf)|encrypt_store|encrypt_contacts)\s*\(/;
// Also ANY #[wasm_bindgen] export: a fn that merely RECEIVES a secret (e.g.
// `key_file`) matches no naming convention. Exports with no secret param
// contribute nothing; internal helpers stay out (the boundary is the ABI).
const ANY_FN_RE = /(?:^|[^A-Za-z0-9_])fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(/;
/// The fn declared on `code`, and why it is in scope — or null if it isn't.
function secretFnMatch(f, i, code) {
  const byName = SECRET_FN_RE.exec(code);
  if (byName) return { m: byName, via: "naming convention" };
  const anyFn = ANY_FN_RE.exec(code);
  if (anyFn && isWasmExport(f.lines, i))
    return { m: anyFn, via: "wasm export" };
  return null;
}
/** `name: Vec<u8>` or `name: Option<Vec<u8>>` — owned, so the callee can scrub it. */
const OWNED_SECRET_RE = (p) =>
  new RegExp(`\\b${p}\\s*:\\s*(?:Option\\s*<\\s*)?Vec\\s*<\\s*u8\\s*>`);

/** Ownership under `Zeroizing`, directly or via `.map(Zeroizing::new)` on an Option. */
const ZEROIZED_RE = (p) =>
  new RegExp(
    `let\\s+(?:mut\\s+)?${p}\\s*=\\s*(?:Zeroizing::new\\(|${p}\\s*\\.map\\(\\s*Zeroizing::new\\s*\\))`,
  );

const invariantZeroizedParams = {
  id: "owned-secret-params-zeroized",
  name: "owned secret params (credentials + store plaintext) are Zeroizing-wrapped",
  expectation: "must be empty (zero un-zeroized owned secret params)",
  why: "An owned Vec<u8> of key material that is never moved into Zeroizing stays in wasm linear memory after the call returns, defeating the 'no plaintext secret survives the call' guarantee.",
  run() {
    const violations = [];
    const exempt = [];
    const checked = [];

    for (const { f, i, code } of rustLines()) {
      const lines = f.lines;
      const raw = f.raw;
      const found = secretFnMatch(f, i, code);
      if (!found) continue;
      const { m, via } = found;
      if (f.testGated[i]) {
        // EXEMPTION: cfg(test) helpers never ship.
        exempt.push({
          file: f.rel,
          line: i + 1,
          text: m[1],
          reason: "#[cfg(test)]-gated",
        });
        continue;
      }
      const fnNameHere = m[1];

      const span = fnSpan(lines, i, m.index);
      if (!span) continue;
      const { signature, body } = span;

      // Owned = `Vec<u8>` or `Option<Vec<u8>>` (no `&`). The Option arm
      // matters: without it an optional secret matched neither the owned nor
      // the borrowed pattern and was invisible to both invariants.
      const owned = [];
      const borrowed = [];
      for (const p of SECRET_PARAM_NAMES) {
        const owns = OWNED_SECRET_RE(p).test(signature);
        const borrows = new RegExp(`\\b${p}\\s*:\\s*&`).test(signature);
        if (owns) owned.push(p);
        else if (borrows) borrowed.push(p);
      }

      // A structurally-included export with no secret param is out of scope,
      // not "checked" (else the convention guard below can't fail).
      if (via === "wasm export" && !owned.length && !borrowed.length) continue;

      const unwrapped = owned.filter((p) => !ZEROIZED_RE(p).test(body));
      checked.push({ fn: fnNameHere, file: f.rel, owned, borrowed, via });
      if (unwrapped.length) {
        violations.push({
          summary: `${fnNameHere}() takes owned Vec<u8> secret(s) never moved into Zeroizing: ${unwrapped.join(", ")}`,
          hits: [{ file: f.rel, line: i + 1, text: (raw[i] ?? "").trim() }],
        });
      }
    }

    const byConvention = checked.filter((c) => c.via === "naming convention");
    if (byConvention.length === 0) {
      violations.push({
        summary:
          "found no *_with_password / *_with_prf fns at all - the naming convention changed and this invariant is no longer checking anything",
        hits: [],
      });
    }

    const ownedCount = checked.reduce((n, c) => n + c.owned.length, 0);
    const borrowedCount = checked.reduce((n, c) => n + c.borrowed.length, 0);
    const fileCount = new Set(checked.map((c) => c.file)).size;
    const unwrappedCount = violations.length;
    // Print matched param names: a secret named outside the list passes
    // vacuously, and naming the matched set makes that visible.
    const matchedParams = [
      ...new Set(checked.flatMap((c) => [...c.owned, ...c.borrowed])),
    ].sort();
    const unmatched = SECRET_PARAM_NAMES.filter(
      (p) => !matchedParams.includes(p),
    );
    return {
      violations,
      exempt,
      detail:
        `${checked.length} fn(s) across ${fileCount} file(s) ` +
        `(${byConvention.length} by naming convention, ${checked.length - byConvention.length} other wasm export(s)); ` +
        `${ownedCount} owned secret param(s) ` +
        (unwrappedCount === 0
          ? "all Zeroizing-wrapped"
          : `- ${unwrappedCount} fn(s) with an UNWRAPPED param`) +
        `, ${borrowedCount} borrowed (&[u8], caller-owned)` +
        `; matched on: ${matchedParams.join(", ") || "-"}` +
        (unmatched.length ? ` (never seen: ${unmatched.join(", ")})` : ""),
    };
  },
};

// ── Invariant 5 — wasm exports take credential material BY VALUE ─────
// Invariant 4 passes vacuously for a fn that BORROWS its password. At a
// #[wasm_bindgen] boundary a `&[u8]` is wasm-bindgen's copy, freed WITHOUT
// scrubbing, so the plaintext outlives the call (SECURITY.md §8.4,
// T-UNLOCK-PARAM-NOT-OWNED). Keyed on PARAM NAME, not fn naming.
const CREDENTIAL_PARAM_NAMES = [
  "password",
  "passphrase",
  "source_passphrase",
  "prf_output",
  "stored_secret",
  // The private key file itself (age/SSH): a borrowed one would leave a full
  // unencrypted key in freed memory.
  "key_file",
];
// `plaintext` deliberately NOT listed: encrypt* borrow message bytes only to
// pass them through; owned store plaintext is covered by invariant 4. Adding
// it would cry wolf.

// EXEMPTION (KNOWN GAP, not an approval): exports still borrowing a
// credential, by fn name → reason. Shrink, never grow. CURRENTLY EMPTY, the
// goal state: any borrowed credential param on an export fails outright.
// (argon2_derive's export is argon2_derive_owned; the borrowing helper is
// in-crate and out of scope.)
const BORROWED_CREDENTIAL_EXPORT_EXEMPTIONS = new Map();

const invariantExportsOwnCredentials = {
  id: "wasm-exports-own-credential-params",
  name: "#[wasm_bindgen] exports take password/PRF material owned, not borrowed",
  expectation:
    BORROWED_CREDENTIAL_EXPORT_EXEMPTIONS.size === 0
      ? "no borrowed credential params on wasm exports (no known-gap exemptions outstanding)"
      : `no borrowed credential params on wasm exports, outside the ${BORROWED_CREDENTIAL_EXPORT_EXEMPTIONS.size} named known-gap exemption(s)`,
  why: "A borrowed &[u8] credential param at the wasm-bindgen boundary is a buffer we do not own: wasm-bindgen frees its marshalled copy of the password / PRF output without scrubbing it, so there is nothing to wrap in Zeroizing and the plaintext outlives the call in linear memory.",
  run() {
    const violations = [];
    const exempt = [];
    const checked = [];

    for (const { f, i, code } of rustLines()) {
      const m =
        /(?:^|[^A-Za-z0-9_])fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(/.exec(code);
      if (!m) continue;
      // EXEMPTION: cfg(test) code is not compiled into the shipped wasm.
      if (f.testGated[i]) continue;
      // EXEMPTION: internal (non-export) helpers receive a reference to a
      // `Zeroizing` their exported caller owns; by-value there would add an
      // un-scrubbed copy. Ownership is required at the ABI.
      if (!isWasmExport(f.lines, i)) continue;

      const span = fnSpan(f.lines, i, m.index);
      if (!span) continue;
      const fnHere = m[1];
      const borrowed = CREDENTIAL_PARAM_NAMES.filter((param) =>
        new RegExp(`\\b${param}\\s*:\\s*&`).test(span.signature),
      );
      const owned = CREDENTIAL_PARAM_NAMES.filter((param) =>
        OWNED_SECRET_RE(param).test(span.signature),
      );
      if (!borrowed.length && !owned.length) continue;
      checked.push({ fn: fnHere, file: f.rel, owned, borrowed });
      if (!borrowed.length) continue;

      const hit = {
        file: f.rel,
        line: i + 1,
        text: (f.raw[i] ?? "").trim(),
        fn: fnHere,
      };
      const excuse = BORROWED_CREDENTIAL_EXPORT_EXEMPTIONS.get(fnHere);
      if (excuse) {
        exempt.push({ ...hit, reason: `${excuse} (${borrowed.join(", ")})` });
        continue;
      }
      violations.push({
        summary: `${fnHere}() is a wasm export that borrows credential material: ${borrowed.map((b) => `${b}: &[u8]`).join(", ")} - take it as Vec<u8> and wrap in Zeroizing`,
        hits: [hit],
      });
    }

    if (checked.length === 0) {
      violations.push({
        summary:
          "found no wasm export taking password/PRF material at all - the param naming convention changed and this invariant is no longer checking anything",
        hits: [],
      });
    }

    const fileCount = new Set(checked.map((c) => c.file)).size;
    const ownedCount = checked.reduce((n, c) => n + c.owned.length, 0);
    // As in invariant 4: print matched/never-seen names so a silent zero
    // from an unlisted param name is legible.
    const matchedParams = [
      ...new Set(checked.flatMap((c) => [...c.owned, ...c.borrowed])),
    ].sort();
    const unmatched = CREDENTIAL_PARAM_NAMES.filter(
      (p) => !matchedParams.includes(p),
    );
    return {
      violations,
      exempt,
      detail:
        `${checked.length} credential-taking export(s) across ${fileCount} file(s); ${ownedCount} owned param(s), ${violations.length} borrowed unexempted, ${exempt.length} known-gap exemption(s)` +
        `; matched on: ${matchedParams.join(", ") || "-"}` +
        (unmatched.length ? ` (never seen: ${unmatched.join(", ")})` : ""),
    };
  },
};

// ── Invariant 6 — no console.* outside the network lockdown ──────────
// SECURITY.md §9 check 5.
//
// EXEMPTION: src/lib/network-lockdown.ts logs a blocked request's URL so the user
// can see an exfiltration attempt.
const CONSOLE_EXEMPT_FILES = new Set(["apps/pgp/src/lib/network-lockdown.ts"]);

// EXEMPTION: test/spec files are never bundled. Not free: a test printing a
// secret still lands in CI logs — treat that as a defect in review.
const TEST_FILE_RE = /\.(test|spec)\.tsx?$/;
const isTestFile = (file) => TEST_FILE_RE.test(file);

const invariantNoConsole = {
  id: "no-console-logging",
  name: "no console.* outside src/lib/network-lockdown.ts (tests exempt)",
  expectation: "must be empty outside the exempt file(s) and test/spec files",
  why: "Console output in this codebase runs in the same context as unlocked key material, and devtools logs persist and are trivially scraped - any accidental log of a passphrase, handle or plaintext is an exfiltration channel.",
  run() {
    // Masked source, so comments/strings mentioning console.* don't count.
    const re = /\bconsole\s*\.\s*[A-Za-z_$][\w$]*\s*\(/g;
    const all = scanTs(re);
    const exempt = [
      ...all
        .filter((h) => CONSOLE_EXEMPT_FILES.has(h.file))
        .map((h) => ({ ...h, reason: "blocked-request logging" })),
      ...all
        .filter((h) => !CONSOLE_EXEMPT_FILES.has(h.file) && isTestFile(h.file))
        .map((h) => ({ ...h, reason: "test/spec file - never bundled" })),
    ];
    const bad = all.filter(
      (h) => !CONSOLE_EXEMPT_FILES.has(h.file) && !isTestFile(h.file),
    );
    return {
      violations: bad.length
        ? [
            {
              summary: `${bad.length} console.* call(s) outside the exempt file(s)`,
              hits: bad,
            },
          ]
        : [],
      exempt,
      detail: (() => {
        const inLockdown = exempt.filter((h) =>
          CONSOLE_EXEMPT_FILES.has(h.file),
        ).length;
        const inTests = exempt.filter((h) => isTestFile(h.file)).length;
        const breakdown = `${inLockdown} in network-lockdown, ${inTests} in test/spec files`;
        return bad.length === 0
          ? `${all.length} console.* call(s), all exempt (${breakdown})`
          : `${all.length} console.* call(s), ${bad.length} in shipping code (${breakdown} exempt)`;
      })(),
    };
  },
};

// ── Invariant 7 — contacts are bound to a person only by the user ───
// A contact may only be written after the user saw it on the import Review
// (`applyReview` brands it `ReviewedContact`) or on undo of their own delete.
// The store's add takes only the brand; this holds the rest.
const REVIEWED_CALLERS = new Map([
  [
    "apps/pgp/src/lib/import/review.ts",
    "applyReview: the user's Review decisions",
  ],
  [
    "apps/pgp/src/components/keys/DeletePages.tsx",
    "undo of the user's own delete: restores the record they had",
  ],
]);
// Every write path into the contact store (updateContact can write anything
// saveContact can; upsertContacts is the merge saveContact writes).
const CONTACT_WRITE_FNS = [
  "saveContact",
  "upsertContacts",
  "updateContact",
  "setContactRecipientDisabled",
  "setContactVerified",
  "updateContactAlias",
  "removeContact",
];
const CONTACT_WRITERS = new Map([
  ["apps/pgp/src/lib/storage/contacts.ts", "the store itself"],
  [
    "apps/pgp/src/hooks/useContacts.ts",
    "the store's add (typed ReviewedContact), remove, rename and verify",
  ],
  [
    "apps/pgp/src/lib/storage/contact-backfill.ts",
    "the legacy backfills: derived fields of a record already in the store",
  ],
  [
    "apps/pgp/src/lib/import-public-keys.ts",
    "mergeIntoContact: a newer copy of the SAME key merged into an existing record (only what its owner signed)",
  ],
  [
    "apps/pgp/src/components/keys/KeyDetailsPage.tsx",
    "the user's own toggle of one key / Mark as verified, on a record already in the store",
  ],
]);

/** Argument text of every `name(` call in masked source, parens matched. */
function callArguments(masked, nameRe) {
  const out = [];
  const re = new RegExp(`\\b(?:${nameRe})\\s*\\(`, "g");
  let m;
  while ((m = re.exec(masked)) !== null) {
    let depth = 1;
    let j = m.index + m[0].length;
    while (j < masked.length && depth > 0) {
      if (masked[j] === "(") depth++;
      else if (masked[j] === ")") depth--;
      j++;
    }
    out.push({
      line: masked.slice(0, m.index).split("\n").length,
      call: m[0],
      args: masked.slice(m.index + m[0].length, j - 1),
    });
  }
  return out;
}

// A cast to never/any mints the brand without naming it.
const ESCAPE_CAST_RE =
  /\bas\s+(?:never|any)\b|\bas\s+unknown\s+as\b|<\s*(?:never|any)\s*>/;
// Contact-adding calls. `add(` is broad on purpose; no such cast exists in
// shipping code today.
const CONTACT_ADD_CALL = "onAddContact|addContact|add";

const invariantReviewedContacts = {
  id: "contacts-only-after-review",
  name: "contacts are written only from the import Review (or an undo)",
  expectation:
    "the identifier reviewed only in REVIEWED_CALLERS (import, alias or call); no as never/any/unknown-as in a contact add; contact-store writers and CONTACTS_STORE only in CONTACT_WRITERS (tests exempt)",
  why: "A contact binds a key to a person. A write that skips the Review is how a bundle slipped in a second key with someone's name and address: the user never saw it, and it then sat in the encrypt picker as that person.",
  run() {
    const notTest = (h) => !isTestFile(h.file);
    // ANY use of the name (import, alias, call), not just `reviewed(`.
    const brand = [
      ...scanTs(/\breviewed\b/, notTest),
      ...scanTs(/\bas\s+ReviewedContact\b|<ReviewedContact>\s*[\w({]/, notTest),
    ];
    // Namespace/dynamic imports of the review module (`ns["reviewed"]`) are
    // hidden by the mask, so read them off the raw line.
    const REVIEW_MODULE_IMPORT =
      /\*\s*as\s+[\w$]+\s+from\s+["'][^"']*\/review["']|\bimport\s*\(\s*["'][^"']*\/review["']/;
    for (const { rel: relPath, raw } of tsSources()) {
      if (isTestFile(relPath) || REVIEWED_CALLERS.has(relPath)) continue;
      raw.forEach((text, i) => {
        const m = REVIEW_MODULE_IMPORT.exec(text);
        if (m)
          brand.push({
            file: relPath,
            line: i + 1,
            match: m[0],
            text: text.trim(),
            noExempt: true,
          });
      });
    }
    // Escape casts into an add also mint the brand.
    for (const { rel: relPath, masked, raw } of tsSources()) {
      if (isTestFile(relPath)) continue;
      for (const c of callArguments(masked, CONTACT_ADD_CALL)) {
        const cast = ESCAPE_CAST_RE.exec(c.args);
        if (!cast) continue;
        brand.push({
          file: relPath,
          line: c.line,
          match: `${c.call}... ${cast[0]}`,
          text: (raw[c.line - 1] ?? "").trim(),
          noExempt: true,
        });
      }
    }
    // `noExempt` hits fail everywhere. The definition exemption is exactly
    // `function reviewed(` in review.ts.
    const isDefinition = (h) =>
      h.file === "apps/pgp/src/lib/import/review.ts" &&
      /\bfunction\s+reviewed\s*\(/.test(h.text);
    const writes = [
      ...scanTs(
        new RegExp(`\\b(?:${CONTACT_WRITE_FNS.join("|")})\\b`),
        notTest,
      ),
      ...scanTs(/\bCONTACTS_STORE\b/, notTest),
    ];
    const badBrand = brand.filter(
      (h) => h.noExempt || (!REVIEWED_CALLERS.has(h.file) && !isDefinition(h)),
    );
    const badWrites = writes.filter((h) => !CONTACT_WRITERS.has(h.file));
    const violations = [];
    if (badBrand.length)
      violations.push({
        summary: `${badBrand.length} use(s) of reviewed / the brand outside the Review`,
        hits: badBrand,
      });
    if (badWrites.length)
      violations.push({
        summary: `${badWrites.length} contact-store write(s) outside the allowed writers`,
        hits: badWrites,
      });
    return {
      violations,
      exempt: [
        ...brand
          .filter((h) => !h.noExempt && isDefinition(h))
          .map((h) => ({ ...h, reason: "the definition" })),
        ...brand
          .filter(
            (h) =>
              !h.noExempt && !isDefinition(h) && REVIEWED_CALLERS.has(h.file),
          )
          .map((h) => ({ ...h, reason: REVIEWED_CALLERS.get(h.file) })),
        ...writes
          .filter((h) => CONTACT_WRITERS.has(h.file))
          .map((h) => ({ ...h, reason: CONTACT_WRITERS.get(h.file) })),
      ],
      detail: `${brand.length} use(s) of reviewed / the brand, ${writes.length} contact-store writer reference(s)`,
    };
  },
};

const INVARIANTS = [
  invariantKeyStoreInsert,
  invariantUnlockOnly,
  invariantWasmBoundary,
  invariantZeroizedParams,
  invariantExportsOwnCredentials,
  invariantNoConsole,
  invariantReviewedContacts,
];

try {
  statSync(WASM_LIB);
} catch {
  console.error(`ERROR: ${rel(WASM_LIB)} not found - cannot audit invariants.`);
  process.exit(1);
}

console.log("");
console.log("── SECURITY.md §9 invariants ────────────────");
{
  const { files, unreadable } = rustSources();
  console.log(
    `   rust sources scanned: ${files.map((f) => f.rel.split("/").pop()).join(", ")}`,
  );
  if (unreadable.length) {
    console.log(`   ⚠️  unreadable (skipped): ${unreadable.join(", ")}`);
  }
}

const results = [];
for (const inv of INVARIANTS) {
  let result;
  try {
    result = inv.run();
  } catch (e) {
    result = {
      violations: [{ summary: `check threw: ${e.message}`, hits: [] }],
      exempt: [],
      detail: "check errored",
    };
  }
  results.push({ inv, result });
  const ok = result.violations.length === 0;
  console.log(`   ${ok ? "✅" : "❌"} ${inv.id} - ${inv.name}`);
  console.log(`      expect: ${inv.expectation}`);
  console.log(`      actual: ${result.detail}`);
}

const failed = results.filter((r) => r.result.violations.length > 0);

if (failed.length > 0) {
  console.log("");
  console.log("❌ SECURITY INVARIANT VIOLATION");
  for (const { inv, result } of failed) {
    console.log("");
    console.log(`   ${inv.id} - ${inv.name}`);
    console.log(`   why it matters: ${inv.why}`);
    for (const v of result.violations) {
      console.log(`   • ${v.summary}`);
      for (const h of v.hits) {
        console.log(
          `       ${h.file}:${h.line}${h.fn ? `  (in fn ${h.fn})` : ""}`,
        );
        if (h.text) console.log(`       │ ${h.text.slice(0, 120)}`);
      }
    }
  }
}

const exemptTotal = results.reduce((n, r) => n + r.result.exempt.length, 0);

console.log("");
console.log("── Summary ──────────────────────────────────");
console.log(`   Invariants checked: ${INVARIANTS.length}`);
console.log(`   Passed:             ${INVARIANTS.length - failed.length}`);
console.log(`   Failed:             ${failed.length}`);
console.log(`   Exemptions applied: ${exemptTotal}`);
console.log("");

if (failed.length > 0) {
  console.log("⚠️  Fix the code, or - if the new usage is genuinely safe -");
  console.log(
    "   add a commented exemption in scripts/audit-invariants.mjs and",
  );
  console.log("   update SECURITY.md §9 to match. Do not loosen it silently.");
  process.exit(1);
}

console.log(`✅ All ${INVARIANTS.length} source invariants hold.`);
