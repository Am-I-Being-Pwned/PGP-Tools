import {
  PLACEHOLDER_ORDER,
  type MessageArgs,
  type PluralArgs,
} from "./messages.generated";

/**
 * Typed front for `chrome.i18n`: bundled locales mean no fetches (nothing
 * for the network audit) and one `t()` for panel and worker. Language
 * follows Chrome's UI; missing keys fall back to `en`. Source of truth is
 * `i18n/<locale>/*.json`, see `i18n/README.md`.
 */

export type MessageKey = keyof MessageArgs;
export type PluralKey = keyof PluralArgs;

type Subs = Readonly<Record<string, string | number>>;

type ArgsOf<A> = A extends undefined ? [] : [subs: A];

/** Nullable: tests run in node without `chrome`. */
interface I18nApi {
  getMessage(key: string, substitutions?: string[]): string;
  getUILanguage(): string;
}

function api(): I18nApi | undefined {
  const g = globalThis as { chrome?: { i18n?: I18nApi } };
  return g.chrome?.i18n;
}

/** BCP 47 tag ("en-GB"). */
export function uiLanguage(): string {
  const tag = api()?.getUILanguage();
  return tag === undefined || tag === "" ? "en" : tag;
}

function values(key: string, subs: Subs | undefined): string[] {
  const order = PLACEHOLDER_ORDER[key];
  if (order === undefined || subs === undefined) return [];
  return order.map((name) => String(subs[name] ?? ""));
}

function lookup(key: string, subs: Subs | undefined): string {
  const i18n = api();
  if (!i18n) return key;
  const msg = i18n.getMessage(key, values(key, subs));
  // Unknown key returns "": show the key rather than a blank control.
  return msg === "" ? key : msg;
}

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

/** `<key>_<category>` by Intl.PluralRules, falling back to `<key>_other`;
 *  always supplies `$count$`. */
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
    // Locale-only categories (ru `_few`) use `_other`'s numbering.
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
