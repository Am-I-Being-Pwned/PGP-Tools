#!/usr/bin/env node
// ──────────────────────────────────────────────────────────────────────
// i18n-build.mjs — merge translation fragments into chrome.i18n bundles
//
// SOURCE OF TRUTH:  i18n/<locale>/<area>.json   (hand-edited, committed)
// GENERATED:        public/_locales/<locale>/messages.json
//                   lib/i18n/messages.generated.ts
//
// Both generated outputs are committed so `wxt`, `tsc` and vitest work
// from a fresh checkout without a pre-step; `scripts/i18n-check.mjs`
// fails CI if they drift from the fragments.
//
// Fragment format is chrome.i18n's, minus the ceremony: every key is
//   { "message": "Hello $name$", "description": "why / where" }
// with placeholders written INLINE as `$name$` (lowercase). This script
// emits the `placeholders` map Chrome wants (`$1`, `$2`, ... assigned in
// order of first appearance in the `en` message) and records that order
// in the generated TS so `t()` can take a named-object argument.
//
// Keys are area-prefixed snake_case (`settings_title`). Plural forms
// are `key_one` / `key_other` (and `_zero` `_two` `_few` `_many` where a
// language needs them); `tn()` picks by Intl.PluralRules and always
// substitutes `$count$`.
//
// Usage:  node scripts/i18n-build.mjs
// ──────────────────────────────────────────────────────────────────────
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const FRAGMENT_DIR = join(APP_DIR, "i18n");
export const LOCALES_DIR = join(APP_DIR, "public", "_locales");
export const GENERATED_TS = join(
  APP_DIR,
  "lib",
  "i18n",
  "messages.generated.ts",
);

export const PLURAL_SUFFIXES = ["zero", "one", "two", "few", "many", "other"];
const PLACEHOLDER_RE = /\$([a-z][a-z0-9_]*)\$/g;
const KEY_RE = /^[a-zA-Z][a-zA-Z0-9_]*$/;

/** Read every fragment for a locale, merged, with the fragment file each
 *  key came from (for error messages). Throws on duplicate keys. */
export function readLocale(locale) {
  const dir = join(FRAGMENT_DIR, locale);
  const messages = {};
  const origin = {};
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(dir, file), "utf8"));
    for (const [key, entry] of Object.entries(parsed)) {
      if (key in messages)
        throw new Error(
          `${locale}: key "${key}" defined in both ${origin[key]} and ${file}`,
        );
      if (!KEY_RE.test(key))
        throw new Error(`${locale}/${file}: invalid key "${key}"`);
      if (typeof entry?.message !== "string")
        throw new Error(`${locale}/${file}: "${key}" has no string message`);
      messages[key] = entry;
      origin[key] = file;
    }
  }
  return { messages, origin };
}

export function listLocales() {
  return readdirSync(FRAGMENT_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
}

/** Placeholder names in order of first appearance. */
export function placeholderNames(message) {
  const names = [];
  for (const m of message.matchAll(PLACEHOLDER_RE))
    if (!names.includes(m[1])) names.push(m[1]);
  return names;
}

/** Convert one fragment entry into chrome.i18n's on-disk shape, using
 *  `order` (from the en message) to number the placeholders. */
function toChromeEntry(entry, order) {
  const out = { message: entry.message };
  if (entry.description) out.description = entry.description;
  if (order.length) {
    out.placeholders = {};
    order.forEach((name, i) => {
      out.placeholders[name] = { content: `$${i + 1}` };
    });
  }
  return out;
}

export function buildAll() {
  const locales = listLocales();
  const en = readLocale("en").messages;
  const orders = Object.fromEntries(
    Object.entries(en).map(([k, e]) => [k, placeholderNames(e.message)]),
  );

  const bundles = {};
  for (const locale of locales) {
    const { messages } = readLocale(locale);
    const bundle = {};
    for (const key of Object.keys(messages).sort()) {
      // A locale-only plural variant (e.g. ru `_few`) shares its base
      // key's placeholders with en's `_other`.
      const order =
        orders[key] ??
        orders[`${pluralBase(key)}_other`] ??
        placeholderNames(messages[key].message);
      bundle[key] = toChromeEntry(messages[key], order);
    }
    bundles[locale] = bundle;
  }
  return { locales, en, orders, bundles };
}

export function pluralBase(key) {
  const m = /^(.*)_(zero|one|two|few|many|other)$/.exec(key);
  return m ? m[1] : null;
}

export function renderGeneratedTs(en, orders) {
  const keys = Object.keys(en).sort();
  const pluralBases = new Set();
  const plainKeys = [];
  for (const k of keys) {
    const base = pluralBase(k);
    if (base && `${base}_other` in en) pluralBases.add(base);
    else plainKeys.push(k);
  }
  const argType = (names) =>
    names.length
      ? `{ ${names.map((n) => `${n}: string | number`).join("; ")} }`
      : "undefined";

  const lines = [];
  lines.push("// GENERATED by scripts/i18n-build.mjs from i18n/en/*.json.");
  lines.push("// Do not edit; run `pnpm i18n:build`.");
  lines.push("");
  lines.push(
    "/** Every non-plural message key, mapped to its named substitutions. */",
  );
  lines.push("export interface MessageArgs {");
  for (const k of plainKeys)
    lines.push(`  ${JSON.stringify(k)}: ${argType(orders[k])};`);
  lines.push("}");
  lines.push("");
  lines.push(
    "/** Plural base keys (the `_one` / `_other` suffix is chosen at runtime). */",
  );
  lines.push("export interface PluralArgs {");
  for (const b of [...pluralBases].sort()) {
    const names = orders[`${b}_other`].filter((n) => n !== "count");
    lines.push(`  ${JSON.stringify(b)}: ${argType(names)};`);
  }
  lines.push("}");
  lines.push("");
  lines.push(
    "/** Substitution order for keys that have placeholders ($1, $2, ...). */",
  );
  lines.push(
    "export const PLACEHOLDER_ORDER: Readonly<Partial<Record<string, readonly string[]>>> = {",
  );
  for (const k of keys)
    if (orders[k].length)
      lines.push(`  ${JSON.stringify(k)}: ${JSON.stringify(orders[k])},`);
  lines.push("};");
  lines.push("");
  return lines.join("\n");
}

function main() {
  const { locales, en, orders, bundles } = buildAll();
  for (const locale of locales) {
    mkdirSync(join(LOCALES_DIR, locale), { recursive: true });
    writeFileSync(
      join(LOCALES_DIR, locale, "messages.json"),
      JSON.stringify(bundles[locale], null, 2) + "\n",
    );
  }
  writeFileSync(GENERATED_TS, renderGeneratedTs(en, orders));
  const total = Object.keys(en).length;
  console.log(
    `i18n: ${total} en keys, ${locales.length} locales written to public/_locales`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main();
