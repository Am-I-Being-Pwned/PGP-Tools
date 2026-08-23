#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// audit-invariants.mjs — source-level security invariant gate
//
// Executable form of SECURITY.md §9 "Verification checklist". That section
// is five shell greps a human is supposed to run by hand and then eyeball;
// this script encodes each one as a named invariant with an explicit,
// machine-checkable expectation, so a regression fails the build instead of
// waiting for someone to notice.
//
// Why not just run the greps in CI: a raw grep can't tell a real violation
// from a legitimate one. `insert_key(` matches its own definition and a
// `#[cfg(test)]`-only shim as well as the single live call site — a count
// check on the raw grep is a permanent false alarm that trains people to
// ignore it. So instead of counting lines we mask out comments/strings,
// resolve each hit's enclosing `fn`, and know whether that `fn` is
// cfg(test)-gated. Exemptions are explicit, named and commented below;
// nothing is pinned to a line number, which would rot on the next edit.
//
// This is a *source* audit and complements scripts/audit-network.mjs, which
// is a *build output* audit:
//   - audit-invariants: our own source keeps the key-isolation contract
//   - audit-network:    the shipped bundle gained no network primitives
//
// Usage:  node scripts/audit-invariants.mjs
// Exit:   0 = all invariants hold, 1 = at least one violated
// ──────────────────────────────────────────────────────────────────────
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

// apps/pgp — resolved from this file so cwd doesn't matter
const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// repo root, so printed paths match the ones written in SECURITY.md §9
const REPO_ROOT = resolve(APP_DIR, "..", "..");
const WASM_SRC_DIR = join(APP_DIR, "gpg-wasm", "src");
const WASM_LIB = join(WASM_SRC_DIR, "lib.rs");

const rel = (p) => relative(REPO_ROOT, p).split(sep).join("/");

// Directories that are never source we own.
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
// Both scanners below match on a *masked* copy of the file: comments and
// string literals are replaced by spaces of equal length, so offsets and
// line numbers stay identical to the original while `// no console.* here`
// and `"…console.log(…)"` can no longer trigger a match. This is what lets
// the checks be strict without hand-maintained per-line suppressions.

function maskTs(src) {
  const out = src.split("");
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k++) {
      if (out[k] !== "\n") out[k] = " ";
    }
  };
  let i = 0;
  let prevSignificant = "";
  // A `/` starts a regex literal (rather than a division) only after one of
  // these. Without this, a regex containing a quote would desync the scanner.
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
      // Template literal: blank the literal text but keep `${…}` code visible,
      // so a console call inside an interpolation is still caught.
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
          // skip to the matching close brace
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
// For every line of lib.rs, records:
//   fnName    — the innermost enclosing `fn`, or null at item level
//   testGated — whether the line sits inside a `#[cfg(test)]` item
//               (fn, mod, impl, or single-line `use`)
// Both are derived from brace depth on the masked source, so no line
// numbers are baked into the invariants.
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
    // Other attributes / doc comments between the cfg and its item must not
    // cancel the pending gate.
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
// This used to read lib.rs and nothing else, and that was the hole the
// borrowed-secret bug walked through: crx.rs is a whole file of
// credential-handling `#[wasm_bindgen]` exports that no invariant could
// see, so `unlock_crx_with_password(password: &[u8])` passed the gate the
// gate exists to catch. The scan is now a glob over gpg-wasm/src/*.rs, so a
// new key type's module is covered the moment it lands rather than when
// someone remembers to add it to a list here.
//
// Read defensively: a module may be mid-write (a concurrent build, an editor
// swap) and a *source* audit must not turn a transient read failure into a
// security verdict either way. Unreadable files are skipped and named in the
// header line, so a silently-unscanned file is visible rather than assumed.

/// Modules lib.rs declares as `#[cfg(test)] mod x;`. Nothing inside such a
/// file marks itself test-only, so per-line `testGated` cannot see it -- the
/// gate lives at the declaration site. Resolved from source rather than
/// hard-coded so renaming or un-gating the module changes the answer.
function cfgTestModules(libMasked) {
  const found = new Set();
  const lines = libMasked.split("\n");
  const CFG_TEST = /^\s*#\s*\[\s*cfg\s*\(.*\btest\b.*\)\s*\]\s*$/;
  for (let i = 0; i < lines.length; i++) {
    if (!CFG_TEST.test(lines[i])) continue;
    for (let j = i + 1; j < lines.length; j++) {
      // attributes / doc comments (masked to blanks) between cfg and item
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
    // EXEMPTION: a `#[cfg(test)] mod x;` module is test-only in its entirety.
    // cfg(test) code is not compiled into the shipped wasm, so it cannot
    // weaken a runtime invariant -- same rationale as the per-fn exemptions.
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

/// True when the `fn` on `lines[fnLine]` carries a `#[wasm_bindgen]`
/// attribute, i.e. it is a real export across the JS/wasm ABI rather than an
/// internal helper. Walks up over attributes and blank lines (doc comments
/// are already masked to blanks) and stops at the first line of real code,
/// so an attribute belonging to a previous item cannot be borrowed.
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

/// The `(...)` signature text and `{...}` body text of the fn whose `fn`
/// keyword is on `lines[i]`, scanning forward on masked source. Returns null
/// if either fails to close (a mid-write file).
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

// ── TS/TSX file collection ──────────────────────────────────────────
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

    // Scanned across every gpg-wasm module, not just lib.rs: a sibling
    // module reaching into KEY_STORE would bypass this check entirely if it
    // were only ever pointed at one file.
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
      // EXEMPTION: call sites inside a `#[cfg(test)]`-gated item. The unit
      // tests predate the unlock-only rule and use a test-only `store_key`
      // shim to mint a handle. cfg(test) code is not compiled into the
      // shipped wasm, so it cannot weaken the runtime invariant. Detected
      // structurally (enclosing fn/mod is cfg(test)-gated), never by line.
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
      // EXEMPTION: same rationale as invariant 1 — cfg(test) code ships
      // nowhere.
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
//
// Every wasm export that touches key material must be reached only through
// lib/pgp/wasm-secrets.ts, which owns the zeroization / handle lifecycle.
const SECRET_WASM_EXPORTS = [
  "generateProtectedWith",
  "protectImportedWith",
  "unlockWith",
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
  // CRX signing keys. Absent until now for the same reason crx.rs went
  // unscanned on the Rust side: the list was written when only PGP keys
  // existed and nobody widened it. Prefixes, so both the ...WithPassword and
  // ...WithPrf variant of each is covered.
  "generateCrxKeyWith",
  "importCrxKeyWith",
  "reprotectCrxKeyWithPassword",
  "unlockCrxWith",
  "exportCrxPrivateKeyPem",
  // age / SSH identities. Added with the engine itself rather than after
  // the fact -- the CRX entries above record what it costs to widen this
  // list late. Prefixes, so both the ...WithPassword and ...WithPrf
  // variant of each is covered. `decryptAgeWithHandle` is listed because
  // age.rs files it on its secret side (it takes a KEY_STORE handle and
  // returns plaintext); `dropSshIdentity` is listed for the same reason
  // `dropCrxKey`'s lifecycle is owned by the boundary module.
  "protectSshIdentityWith",
  "unlockSshIdentityWith",
  "decryptAgeWithHandle",
  "dropSshIdentity",
];
// EXEMPTION: the boundary module itself is *supposed* to make these calls.
const SECRETS_BOUNDARY = "apps/pgp/lib/pgp/wasm-secrets.ts";
// EXEMPTION: test/spec files. In a vitest spec `wasm` is a locally-declared
// `vi.hoisted({...})` object of `vi.fn()` stubs — `wasm.unlockWithPassword`
// there is a mock assertion, not a call into the wasm module, and no key
// material exists to leak. Narrowed the same way, and for the same reason,
// as the console invariant below: without this the check was permanently red
// on protect-runner.test.ts, and a permanently-red gate reports nothing.
// (`isTestFile` is defined with that invariant.)
const invariantWasmBoundary = {
  id: "wasm-secrets-boundary",
  name: "secret-bearing wasm calls happen only in lib/pgp/wasm-secrets.ts",
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
// §9 phrases this as "every `_with_password` / `_with_prf` wasm fn takes
// owned Vec<u8> so we can wrap in Zeroizing" and then just *lists* the fns
// for a human to eyeball. Counting the list would rot the moment a helper is
// added, and the literal claim is not what the code does: the `unlock_*` and
// `init_contacts_session_with_prf` exports take `&[u8]` (a borrowed view that
// wasm-bindgen owns) because they derive a key immediately and zeroize the
// *derived* bytes. What is actually checkable, and is the property that
// matters, is: whenever such a fn does take an owned secret by value, the
// very next thing it does is take ownership under `Zeroizing`.
const SECRET_PARAM_NAMES = [
  "password",
  "passphrase",
  "source_passphrase",
  "prf_output",
  "stored_secret",
  // User content, not a credential, but just as secret: `encrypt_store` /
  // `encrypt_contacts` carry up to 64 KB of message plaintext per call.
  "plaintext",
  // The age/SSH engine's private key FILE. Strictly more sensitive than a
  // password: a password is a means to a secret, `key_file` IS the secret
  // -- an unencrypted OpenSSH or PKCS#8 private key, in full. It was
  // invisible to both invariants until now (see the note on
  // SECRET_FN_RE below for why the naming convention could not see
  // it), so `ssh_private_key_format_rejection(key_file: Vec<u8>)` was
  // covered by nothing and dropping its `Zeroizing` wrapper passed green.
  "key_file",
];
// Two families: the credential-taking `*_with_password` / `*_with_prf` fns,
// and the store-sealing fns that take user plaintext by value. The latter
// were NOT covered until an agent pointed out this check passed either way
// on `encrypt_contacts` -- i.e. SECURITY.md §11.2's claim was unenforced.
// A gate that cannot fail is not a gate.
// This was a prefix allowlist (`encrypt|protect|generate|unlock|...`) and
// the allowlist was itself a hole: `reprotect_crx_key_with_password` starts
// with "re", matched nothing, and was silently unchecked — and so were
// protected.rs's `seal_with_password` / `open_with_password`, the shared
// envelope every key type's credential bytes actually pass through. Any fn
// name is accepted now; the `_with_password` / `_with_prf` SUFFIX is the
// convention that is actually load-bearing, and a new key type's module gets
// covered without editing this regex.
const SECRET_FN_RE =
  /\bfn\s+(\w*_with_(?:password|prf)|encrypt_store|encrypt_contacts)\s*\(/;
// ...and the convention was STILL not enough. It describes how a fn USES a
// secret (seal it under a credential, seal the store), which says nothing
// about fns that merely *receive* one:
// `ssh_private_key_format_rejection(key_file: Vec<u8>)` takes a whole
// private key file, matches no suffix and no name above, and so was checked
// by no invariant at all — its `Zeroizing` wrapper could have been deleted
// without turning a single gate red. Rather than bolt its name onto the
// regex (a fourth allowlist entry, rotting the same way the prefix list
// did), the scope is widened structurally: ANY `#[wasm_bindgen]` export is
// checked too. Exports without a param in SECRET_PARAM_NAMES contribute
// nothing, so this costs no false positives; what it buys is that a new
// export taking `key_file` / `password` / `plaintext` by value is covered
// on the day it lands, whatever it is called. Internal helpers stay out for
// the reason invariant 5 spells out: the boundary is the ABI.
const ANY_FN_RE = /(?:^|[^A-Za-z0-9_])fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(/;
/// The fn declared on `code`, and why it is in scope — or null if it isn't.
function secretFnMatch(f, i, code) {
  const byName = SECRET_FN_RE.exec(code);
  if (byName) return { m: byName, via: "naming convention" };
  const anyFn = ANY_FN_RE.exec(code);
  if (anyFn && isWasmExport(f.lines, i)) return { m: anyFn, via: "wasm export" };
  return null;
}
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

      // Signature runs from the `(` to the matching `)`; body from the next
      // `{` to its matching `}`. Scan forward on the masked source.
      const span = fnSpan(lines, i, m.index);
      if (!span) continue;
      const { signature, body } = span;

      // Owned secret params: `name: Vec<u8>` (no leading `&`).
      const owned = [];
      const borrowed = [];
      for (const p of SECRET_PARAM_NAMES) {
        const owns = new RegExp(`\\b${p}\\s*:\\s*Vec\\s*<\\s*u8\\s*>`).test(
          signature,
        );
        const borrows = new RegExp(`\\b${p}\\s*:\\s*&`).test(signature);
        if (owns) owned.push(p);
        else if (borrows) borrowed.push(p);
      }

      // An export pulled in by the structural widening that carries no
      // secret param is not "checked", it is simply out of scope: counting
      // it would inflate the detail line and, worse, make the
      // "convention changed" guard below unfalsifiable.
      if (via === "wasm export" && !owned.length && !borrowed.length) continue;

      const unwrapped = owned.filter(
        (p) =>
          !new RegExp(`let\\s+(?:mut\\s+)?${p}\\s*=\\s*Zeroizing::new\\(`).test(
            body,
          ),
      );
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
    // Which param names actually matched is printed, not just how many: the
    // list is finite and a secret named something it does not contain
    // (`secret`, `pin`, `recovery_code`) passes vacuously and silently.
    // Naming the matched set makes an unmatched name visible to a reader
    // comparing it against SECRET_PARAM_NAMES.
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
//
// The gap invariant 4 could not see. Invariant 4 asks "if an owned secret
// param exists, is it Zeroizing-wrapped?" — a fn that borrows its password
// has no owned param, so it passes vacuously. That is exactly how
// `unlock_crx_with_password(password: &[u8], ...)` shipped: it was correct
// by invariant 4's question and wrong by the one that matters.
//
// Why borrowing is the bug, not a style preference (SECURITY.md §8.4,
// T-UNLOCK-PARAM-NOT-OWNED): at a `#[wasm_bindgen]` boundary a `&[u8]` param
// is a view onto a buffer wasm-bindgen allocated, copied the JS bytes into,
// and frees WITHOUT scrubbing once the call returns. There is no owned value
// to move into `Zeroizing`, so the plaintext password / PRF output is left
// in freed linear memory and its lifetime becomes whatever the allocator
// decides. Taking `Vec<u8>` hands us that same allocation to own — and to
// wipe. Internal helpers are a different case and are exempt below.
//
// Deliberately keyed on PARAM NAME, not on the fn naming convention that
// invariant 4 uses: a new key type can call its unlock fn anything, but a
// param carrying a password is going to be called `password`.
const CREDENTIAL_PARAM_NAMES = [
  "password",
  "passphrase",
  "source_passphrase",
  "prf_output",
  "stored_secret",
  // The private key file itself (age/SSH engine). Belongs here even more
  // clearly than a password does: a borrowed `key_file: &[u8]` would leave
  // a full unencrypted private key in the wasm-bindgen allocation that is
  // freed WITHOUT scrubbing -- the same defect as
  // T-UNLOCK-PARAM-NOT-OWNED, with the actual key rather than the
  // credential that guards it. Unlike `plaintext` below there is no
  // pass-through case to false-positive on: every export that names a
  // `key_file` is consuming it.
  "key_file",
];
// NOTE: `plaintext` is deliberately NOT in that list even though invariant 4
// treats it as secret. `encrypt` / `encryptWithSigningHandle` borrow message
// bytes they only ever pass through to the recipients' session key, and the
// store-sealing fns that DO own their plaintext are already covered by
// invariant 4. Adding it here would flag the pass-through fns, and an
// invariant that cries wolf gets ignored — which is how this class of bug
// survives.

// EXEMPTION (KNOWN GAP, not an approval): `#[wasm_bindgen]` exports that
// still borrow a credential today. Each such entry is the same defect as
// T-UNLOCK-PARAM-NOT-OWNED and should be converted to `Vec<u8>` +
// `Zeroizing`; listing one rather than silently tolerating it keeps (a) the
// gap enumerable and (b) NEW borrowed-credential exports failing the gate.
// Shrink this list; never grow it. Removing an entry after fixing the fn
// requires no other change here.
//
// CURRENTLY EMPTY, and that is the goal state, not a dormant mechanism:
// every wasm export taking credential material now takes it owned. The map
// stays because it is the only pressure valve — without it, the next
// borrowed-credential export would be argued into the invariant itself
// rather than into a named, commented line here. An empty map means the
// gate is at full strength: any borrowed credential param on an export is
// an outright failure.
//
// The last three entries were `argon2_derive` (exported as `argon2Derive`),
// `encrypt_canary_and_init_session` and `verify_canary_and_init_session` —
// the onboarding and master-unlock paths, i.e. the master password itself.
// All three now take `password: Vec<u8>` and wrap it in `Zeroizing` on
// entry. `argon2_derive` was split: the export is `argon2_derive_owned`,
// and the borrowing `argon2_derive` it delegates to is an in-crate helper,
// which this invariant deliberately does not check (see the note above on
// why internal helpers are a different case).
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
      // EXEMPTION: internal (non-`#[wasm_bindgen]`) helpers such as
      // protected::open_with_password and crx::encrypt_der_with_password.
      // They never see a wasm-bindgen allocation — the reference they get is
      // to a `Zeroizing` their exported caller already owns, and taking it by
      // value there would mean an extra un-scrubbed copy, not one fewer.
      // The boundary is the ABI, so that is where ownership is required.
      if (!isWasmExport(f.lines, i)) continue;

      const span = fnSpan(f.lines, i, m.index);
      if (!span) continue;
      const fnHere = m[1];
      const borrowed = CREDENTIAL_PARAM_NAMES.filter((param) =>
        new RegExp(`\\b${param}\\s*:\\s*&`).test(span.signature),
      );
      const owned = CREDENTIAL_PARAM_NAMES.filter((param) =>
        new RegExp(`\\b${param}\\s*:\\s*Vec\\s*<\\s*u8\\s*>`).test(
          span.signature,
        ),
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
    // Same reasoning as invariant 4's detail line: CREDENTIAL_PARAM_NAMES is
    // a fixed list, so an export whose secret param is called `secret`,
    // `pin` or `recovery_code` is not caught -- it is simply never seen, and
    // a silent zero is indistinguishable from a clean bill of health.
    // Printing the names that DID match, and the listed names that never
    // appeared, is the cheap version of making that gap legible; it does not
    // close it.
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
// EXEMPTION: lib/network-lockdown.ts logs the URL of a blocked request. That
// is the one place a log is load-bearing (the user must be able to see an
// exfiltration attempt) and it only ever prints a URL we refused to fetch.
const CONSOLE_EXEMPT_FILES = new Set(["apps/pgp/lib/network-lockdown.ts"]);

// EXEMPTION: test and spec files. They are never bundled into the extension,
// so a log in one cannot reach a user's devtools alongside unlocked key
// material - the threat this invariant exists to stop. Canary probes in
// e2e/*.spec.ts legitimately print heap/memory diagnostics while being
// written.
//
// This is a deliberate narrowing, and it is not free: a canary printed by a
// test still lands in CI logs, which is a real (if lesser) disclosure route.
// Reviewers should treat a secret-printing test as a defect even though this
// gate no longer catches it. Revisit if CI logs become shared more widely.
const TEST_FILE_RE = /\.(test|spec)\.tsx?$/;
const isTestFile = (file) => TEST_FILE_RE.test(file);

const invariantNoConsole = {
  id: "no-console-logging",
  name: "no console.* outside lib/network-lockdown.ts (tests exempt)",
  expectation: "must be empty outside the exempt file(s) and test/spec files",
  why: "Console output in this codebase runs in the same context as unlocked key material, and devtools logs persist and are trivially scraped - any accidental log of a passphrase, handle or plaintext is an exfiltration channel.",
  run() {
    // Real calls only; matched on masked source so comments mentioning
    // `console.*` and strings containing it don't count.
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

const INVARIANTS = [
  invariantKeyStoreInsert,
  invariantUnlockOnly,
  invariantWasmBoundary,
  invariantZeroizedParams,
  invariantExportsOwnCredentials,
  invariantNoConsole,
];

// ── Run ─────────────────────────────────────────────────────────────
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
    // Named, never swallowed: a file skipped because it was mid-write is a
    // file no invariant covered on this run.
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
