#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// i18n-check.mjs — translation gate
//
// Fails the build when:
//   1. the generated bundles / TS drift from i18n/<locale>/*.json
//      (run `pnpm i18n:build`);
//   2. a locale has a key `en` does not, or its placeholders differ from
//      en's (Chrome substitutes positionally, so a mismatch shows `$2`
//      or drops a value);
//   3. a locale translates a plural base but not every category en has
//      (Chrome falls back PER KEY, so a missing `_one` would render in
//      English next to a translated `_other`);
//   4. source calls `t()` / `tn()` with a key `en` lacks;
//   5. JSX in components/ or entrypoints/ still carries literal English:
//      JSXText with words, or a text-like string attribute.
//
// Missing keys in a locale are NOT an error -- Chrome shows `en` for
// them -- but coverage is printed so nobody mistakes 40% for done.
//
// Opting a literal out (brand names, key IDs, code samples):
//   {/* i18n-ignore */}      before a JSX text node or element
//   // i18n-ignore           on the line above an attribute
//   /* i18n-ignore-file */   anywhere in the file
//
// Usage:  node scripts/i18n-check.mjs [--strict]   (--strict: unused
//         en keys are errors instead of warnings)
// ──────────────────────────────────────────────────────────────────────
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { parse } from "@babel/parser";
import traverseModule from "@babel/traverse";

import {
  buildAll,
  GENERATED_TS,
  LOCALES_DIR,
  placeholderNames,
  pluralBase,
  readLocale,
  renderGeneratedTs,
} from "./i18n-build.mjs";

const traverse = traverseModule.default ?? traverseModule;
const APP_DIR = join(import.meta.dirname, "..");
const STRICT = process.argv.includes("--strict");

const errors = [];
const warnings = [];
const fail = (msg) => errors.push(msg);
const warn = (msg) => warnings.push(msg);

// ── 1. generated outputs in sync ────────────────────────────────────
const { locales, en, orders, bundles } = buildAll();
for (const locale of locales) {
  const path = join(LOCALES_DIR, locale, "messages.json");
  const want = JSON.stringify(bundles[locale], null, 2) + "\n";
  const have = existsSync(path) ? readFileSync(path, "utf8") : "";
  if (have !== want)
    fail(
      `public/_locales/${locale}/messages.json is stale: run pnpm i18n:build`,
    );
}
if (readFileSync(GENERATED_TS, "utf8") !== renderGeneratedTs(en, orders))
  fail("lib/i18n/messages.generated.ts is stale: run pnpm i18n:build");

// ── 2 + 3. per-locale consistency ───────────────────────────────────
const enKeys = new Set(Object.keys(en));
const enPluralBases = new Map(); // base -> categories en has
for (const k of enKeys) {
  const base = pluralBase(k);
  if (base && enKeys.has(`${base}_other`)) {
    if (!enPluralBases.has(base)) enPluralBases.set(base, new Set());
    enPluralBases.get(base).add(k.slice(base.length + 1));
  }
}
for (const k of enKeys) {
  const e = en[k];
  if (!e.description && !k.startsWith("ext"))
    warn(`en: "${k}" has no description (translators and models need context)`);
  if (/[–—]/.test(e.message))
    fail(`en: "${k}" contains an em/en dash; use a hyphen (repo rule)`);
}

const coverage = [];
for (const locale of locales) {
  if (locale === "en") continue;
  const { messages } = readLocale(locale);
  let translated = 0;
  for (const [k, entry] of Object.entries(messages)) {
    if (!enKeys.has(k)) {
      // Allowed: a plural category en lacks (ru `_few`), if the base exists.
      const base = pluralBase(k);
      if (base && enPluralBases.has(base)) {
        const want = orders[`${base}_other`];
        const have = placeholderNames(entry.message);
        if (!sameSet(want, have))
          fail(
            `${locale}: "${k}" placeholders [${have}] differ from en [${want}]`,
          );
        continue;
      }
      fail(`${locale}: "${k}" is not an en key`);
      continue;
    }
    translated++;
    if (!entry.message.trim()) fail(`${locale}: "${k}" is empty`);
    const have = placeholderNames(entry.message);
    if (!sameSet(orders[k], have))
      fail(
        `${locale}: "${k}" placeholders [${have}] differ from en [${orders[k]}]`,
      );
  }
  for (const [base, cats] of enPluralBases) {
    const hasAny = [...cats].some((c) => `${base}_${c}` in messages);
    if (!hasAny) continue;
    for (const c of cats)
      if (!(`${base}_${c}` in messages))
        fail(`${locale}: plural "${base}" is missing "_${c}" (en has it)`);
  }
  coverage.push([locale, translated, enKeys.size]);
}

function sameSet(a, b) {
  return a.length === b.length && a.every((x) => b.includes(x));
}

// ── 4 + 5. source scan ──────────────────────────────────────────────
const SCAN_DIRS = ["components", "entrypoints", "hooks", "lib"];
const SKIP = [
  /\.test\.tsx?$/,
  /\.d\.ts$/,
  /fake-.*\.ts$/,
  /messages\.generated\.ts$/,
];
const usedKeys = new Set();

const TEXT_ATTR_DENY = new Set([
  "className",
  "class",
  "id",
  "key",
  "href",
  "src",
  "to",
  "type",
  "role",
  "name",
  "value",
  "defaultValue",
  "variant",
  "size",
  "mode",
  "kind",
  "tone",
  "action",
  "htmlFor",
  "autoComplete",
  "autoCapitalize",
  "autoCorrect",
  "spellCheck",
  "inputMode",
  "target",
  "rel",
  "method",
  "lang",
  "dir",
  "encType",
  "accept",
  "pattern",
  "style",
  "as",
  "form",
  "tabIndex",
  "align",
  "side",
  "sideOffset",
  "orientation",
  "position",
  "wrap",
  "loading",
  "decoding",
  "referrerPolicy",
  "download",
  "fill",
  "stroke",
  "viewBox",
  "d",
  "xmlns",
  "path",
  "icon",
  "testId",
  "testid",
  "data-testid",
  "data-slot",
  "data-state",
  "data-mode",
  "data-kind",
  "data-action",
  "data-variant",
  "shortcut",
  "keys",
  "layout",
  "family",
  "algorithm",
  "curve",
  "format",
  "encoding",
  "code",
  "status",
  "step",
  "page",
  "tab",
  "route",
  "view",
  "field",
  "storageKey",
  "prefKey",
  "preference",
]);

function looksLikeProse(s) {
  const v = s.trim();
  if (!v) return false;
  if (!/[A-Za-z]{2,}/.test(v)) return false; // digits, punctuation, symbols
  if (/^[A-Z0-9_]+$/.test(v)) return false; // CONSTANT-looking
  if (/^[a-z0-9-]+$/.test(v)) return false; // enum / token
  if (/^(0x)?[0-9A-Fa-f]{8,}$/.test(v)) return false; // fingerprints / ids
  if (/^-----(BEGIN|END) PGP/.test(v)) return false; // armor markers
  return true;
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === "node_modules") continue;
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.tsx?$/.test(name) && !SKIP.some((re) => re.test(name)))
      out.push(p);
  }
  return out;
}

const files = SCAN_DIRS.flatMap((d) => walk(join(APP_DIR, d)));
let literalHits = 0;
for (const file of files) {
  const src = readFileSync(file, "utf8");
  if (src.includes("i18n-ignore-file")) continue;
  const rel = relative(APP_DIR, file);
  let ast;
  try {
    ast = parse(src, { sourceType: "module", plugins: ["jsx", "typescript"] });
  } catch (e) {
    fail(`${rel}: parse error: ${e.message}`);
    continue;
  }
  const lineOf = (node) => node.loc?.start.line ?? 0;
  const ignoredLines = new Set();
  for (const c of ast.comments ?? [])
    if (c.value.includes("i18n-ignore")) {
      // The comment covers the line it ends on and the next one, so both
      // `{/* i18n-ignore */}text` and `// i18n-ignore\n title="..."` work.
      ignoredLines.add(c.loc.end.line);
      ignoredLines.add(c.loc.end.line + 1);
    }

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      const name = callee.type === "Identifier" ? callee.name : null;
      if (name !== "t" && name !== "tn") return;
      const arg = path.node.arguments[0];
      if (!arg) return;
      if (arg.type !== "StringLiteral") {
        // Dynamic keys are allowed only via `satisfies MessageKey`-style
        // maps; report so a reviewer looks.
        if (
          arg.type !== "Identifier" &&
          arg.type !== "MemberExpression" &&
          arg.type !== "TemplateLiteral"
        )
          warn(`${rel}:${lineOf(arg)}: ${name}() with a non-literal key`);
        return;
      }
      const key = arg.value;
      if (name === "t") {
        if (!enKeys.has(key))
          fail(`${rel}:${lineOf(arg)}: t("${key}") is not an en key`);
        usedKeys.add(key);
      } else {
        if (!enPluralBases.has(key))
          fail(
            `${rel}:${lineOf(arg)}: tn("${key}") has no "${key}_other" en key`,
          );
        for (const c of enPluralBases.get(key) ?? [])
          usedKeys.add(`${key}_${c}`);
      }
    },
    StringLiteral(path) {
      // A lookup table of keys (`Record<Mode, MessageKey>`) references
      // them without a literal `t("...")`; credit any literal that IS a key.
      const v = path.node.value;
      if (enKeys.has(v)) usedKeys.add(v);
      else if (enPluralBases.has(v))
        for (const c of enPluralBases.get(v)) usedKeys.add(`${v}_${c}`);
    },
    JSXText(path) {
      if (!file.endsWith(".tsx")) return;
      const v = path.node.value;
      if (!looksLikeProse(v)) return;
      const line = lineOf(path.node) + (v.match(/^\s*\n/) ? 1 : 0);
      if (ignoredLines.has(line) || ignoredLines.has(lineOf(path.node))) return;
      literalHits++;
      fail(
        `${rel}:${line}: untranslated JSX text ${JSON.stringify(v.trim().slice(0, 60))}`,
      );
    },
    JSXAttribute(path) {
      const attr = path.node;
      const name =
        attr.name.type === "JSXIdentifier"
          ? attr.name.name
          : `${attr.name.namespace.name}:${attr.name.name.name}`;
      if (
        /ClassName$/.test(name) ||
        TEXT_ATTR_DENY.has(name) ||
        name.startsWith("data-") ||
        name.startsWith("on")
      )
        return;
      if (
        name === "aria-hidden" ||
        name === "aria-live" ||
        name === "aria-expanded"
      )
        return;
      let value = null;
      if (attr.value?.type === "StringLiteral") value = attr.value.value;
      else if (
        attr.value?.type === "JSXExpressionContainer" &&
        attr.value.expression.type === "StringLiteral"
      )
        value = attr.value.expression.value;
      if (value === null || !looksLikeProse(value)) return;
      // Single capitalised word in an unknown prop is probably an enum
      // ("Default", "Primary"); demand two words or terminal punctuation
      // unless it's a known text attribute.
      const knownText =
        /^(title|placeholder|alt|label|description|hint|heading|subtitle|tooltip|message|aria-label|aria-description|aria-roledescription|aria-placeholder|aria-valuetext|emptyText|helperText|confirmLabel|cancelLabel|okLabel|actionLabel|buttonLabel|caption|summary|detail|body|text|children|explainer|warning|note|question|prompt)$/;
      if (
        !knownText.test(name) &&
        !/\s/.test(value.trim()) &&
        !/[.!?:]$/.test(value.trim())
      )
        return;
      const line = lineOf(attr);
      if (ignoredLines.has(line)) return;
      literalHits++;
      fail(
        `${rel}:${line}: untranslated ${name}=${JSON.stringify(value.slice(0, 60))}`,
      );
    },
  });
}

// The manifest references keys as `__MSG_key__` (name, description,
// command descriptions); Chrome resolves them from _locales directly.
const wxtConfig = readFileSync(join(APP_DIR, "wxt.config.ts"), "utf8");
for (const m of wxtConfig.matchAll(/__MSG_([A-Za-z0-9_]+)__/g)) {
  if (!enKeys.has(m[1]))
    fail(`wxt.config.ts: __MSG_${m[1]}__ is not an en key`);
  usedKeys.add(m[1]);
}

for (const k of enKeys) {
  if (usedKeys.has(k)) continue;
  // A plural base counts as used when tn() referenced it.
  (STRICT ? fail : warn)(
    `en: "${k}" is defined but never referenced from source`,
  );
}

// ── report ──────────────────────────────────────────────────────────
if (coverage.length) {
  console.log("Translation coverage (keys translated / en keys):");
  const full = coverage.filter(([, n, total]) => n === total).map(([l]) => l);
  const partial = coverage.filter(([, n, total]) => n !== total);
  for (const [l, n, total] of partial.sort((a, b) => b[1] - a[1]))
    console.log(
      `  ${l.padEnd(6)} ${String(n).padStart(4)} / ${total}  ${Math.round((100 * n) / total)}%`,
    );
  if (full.length) console.log(`  complete: ${full.join(", ")}`);
}
if (warnings.length) {
  console.log(`\n${warnings.length} warning(s):`);
  for (const w of warnings.slice(0, 50)) console.log("  " + w);
  if (warnings.length > 50) console.log(`  ... ${warnings.length - 50} more`);
}
if (errors.length) {
  console.error(`\n${errors.length} error(s):`);
  for (const e of errors) console.error("  " + e);
  process.exit(1);
}
console.log(
  `\ni18n-check: OK (${enKeys.size} en keys, ${files.length} source files scanned)`,
);
