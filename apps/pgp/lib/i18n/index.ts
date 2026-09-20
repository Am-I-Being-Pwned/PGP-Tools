import type { MessageArgs, PluralArgs } from "./messages.generated";
import { PLACEHOLDER_ORDER } from "./messages.generated";

/**
 * Typed front for `chrome.i18n`.
 *
 * Why chrome.i18n and not a JS library: the bundles live in
 * `public/_locales`, so no locale data is fetched or code-split, nothing
 * touches the network census in `scripts/audit-network.mjs`, and the
 * same `t()` works in the side panel and the service worker. The cost
 * is that the language follows Chrome's UI language and cannot be
 * switched inside the app; a key missing from a locale falls back to
 * `en` (the manifest's `default_locale`) at the browser level, so a
 * partly translated locale never shows a blank.
 *
 * Source of truth is `i18n/<locale>/*.json`; `pnpm i18n:build` turns
 * those into the Chrome bundles and `messages.generated.ts`, which is
 * where the key and argument types below come from. See `i18n/README.md`.
 *
 * Unit tests run in node with no `chrome`; `lib/i18n/fake-chrome-i18n.ts`
 * (a vitest setup file) installs an `en`-backed stand-in.
 */

export type MessageKey = keyof MessageArgs;
export type PluralKey = keyof PluralArgs;

type Subs = Readonly<Record<string, string | number>>;

/** `[]` when the key takes no substitutions, `[subs]` otherwise. */
type ArgsOf<A> = A extends undefined ? [] : [subs: A];

/** The minimal slice of `chrome.i18n` this module uses; nullable so the
 *  same code runs in node (tests) where `chrome` is not defined. */
interface I18nApi {
  getMessage(key: string, substitutions?: string[]): string;
  getUILanguage(): string;
}

function api(): I18nApi | undefined {
  const g = globalThis as { chrome?: { i18n?: I18nApi } };
  return g.chrome?.i18n;
}

/** Chrome's UI language as a BCP 47 tag ("en-GB", "pt-BR"). */
export function uiLanguage(): string {
  const tag = api()?.getUILanguage();
  return tag === undefined || tag === "" ? "en" : tag;
}

/** Order substitutions the way the built bundle numbered them. */
function values(key: string, subs: Subs | undefined): string[] {
  const order = PLACEHOLDER_ORDER[key];
  if (order === undefined || subs === undefined) return [];
  return order.map((name) => String(subs[name] ?? ""));
}

function lookup(key: string, subs: Subs | undefined): string {
  const i18n = api();
  if (!i18n) return key;
  const msg = i18n.getMessage(key, values(key, subs));
  // Chrome returns "" for an unknown key. Surfacing the key beats a blank
  // control, and `scripts/i18n-check.mjs` catches it before it ships.
  return msg === "" ? key : msg;
}

/** Look up one message, with named substitutions typed per key. */
export function t<K extends MessageKey>(
  key: K,
  ...args: ArgsOf<MessageArgs[K]>
): string {
  return lookup(key, (args as [Subs?])[0]);
}

let pluralRules: { tag: string; rules: Intl.PluralRules } | null = null;

function categoryFor(count: number): Intl.LDMLPluralRule {
  const tag = uiLanguage();
  if (pluralRules?.tag !== tag) {
    let rules: Intl.PluralRules;
    try {
      rules = new Intl.PluralRules(tag);
    } catch {
      rules = new Intl.PluralRules("en");
    }
    pluralRules = { tag, rules };
  }
  return pluralRules.rules.select(count);
}

/**
 * Plural-aware lookup: picks `<key>_<category>` by Intl.PluralRules for
 * the UI language, falling back to `<key>_other`, and always supplies
 * `$count$`. A locale only needs the categories its grammar uses.
 */
export function tn<K extends PluralKey>(
  key: K,
  count: number,
  ...args: ArgsOf<PluralArgs[K]>
): string {
  const base: string = key;
  const subs: Subs = { ...(args as [Subs?])[0], count };
  const category = categoryFor(count);
  const i18n = api();
  if (i18n && category !== "other") {
    // A locale-only category (ru `_few`) has no PLACEHOLDER_ORDER entry
    // of its own; the build gave it `_other`'s numbering.
    const specific = `${base}_${category}`;
    const order =
      PLACEHOLDER_ORDER[specific] ?? PLACEHOLDER_ORDER[`${base}_other`];
    const msg = i18n.getMessage(
      specific,
      order === undefined ? [] : order.map((name) => String(subs[name] ?? "")),
    );
    if (msg !== "") return msg;
  }
  return lookup(`${base}_other`, subs);
}
