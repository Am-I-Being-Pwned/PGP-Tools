/**
 * The languages this app offers for translation, and how to name them.
 *
 * Chrome's Translator supports more pairs than this list; we curate
 * rather than enumerate because every entry is a row in a settings
 * picker and an implied promise that the pair works. Adding a language
 * is a one-line change, so the list can grow on demand rather than
 * speculatively.
 *
 * Codes are BCP 47, which is what both built-in APIs speak. Chrome may
 * hand back a REGIONAL code from the detector ("pt-BR") where the
 * translator wants the base tag ("pt"); `baseLanguage` is the one place
 * that narrowing happens.
 */

import { uiLanguage } from "../i18n";

export interface LanguageOption {
  /** BCP 47 base tag. */
  code: string;
  /** Display name in the UI language (see `languageLabel`). */
  readonly label: string;
}

/**
 * English names, the curated fallback for `languageLabel`. Kept as
 * written here for an English UI (the wording is asserted on by tests
 * and "Chinese (Simplified)" beats Intl's "Chinese"); every other UI
 * language gets Intl's own name for the code.
 */
const ENGLISH_NAMES: readonly [code: string, label: string][] = [
  ["ar", "Arabic"],
  ["bn", "Bengali"],
  ["zh", "Chinese (Simplified)"],
  ["zh-Hant", "Chinese (Traditional)"],
  ["cs", "Czech"],
  ["nl", "Dutch"],
  ["en", "English"],
  ["fr", "French"],
  ["de", "German"],
  ["el", "Greek"],
  ["he", "Hebrew"],
  ["hi", "Hindi"],
  ["id", "Indonesian"],
  ["it", "Italian"],
  ["ja", "Japanese"],
  ["ko", "Korean"],
  ["pl", "Polish"],
  ["pt", "Portuguese"],
  ["ru", "Russian"],
  ["es", "Spanish"],
  ["th", "Thai"],
  ["tr", "Turkish"],
  ["uk", "Ukrainian"],
  ["vi", "Vietnamese"],
];

const ENGLISH_BY_CODE = new Map(ENGLISH_NAMES);

let displayNames: { tag: string; names: Intl.DisplayNames | null } | null =
  null;

/** Localised name of a supported code, or null when Intl has none. */
function localisedName(code: string): string | null {
  const tag = uiLanguage();
  // An English UI keeps the curated table verbatim.
  if (tag === "en" || tag.startsWith("en-")) return null;
  if (displayNames?.tag !== tag) {
    let names: Intl.DisplayNames | null = null;
    try {
      names = new Intl.DisplayNames(tag, { type: "language" });
    } catch {
      names = null;
    }
    displayNames = { tag, names };
  }
  try {
    return displayNames.names?.of(code) ?? null;
  } catch {
    return null;
  }
}

/**
 * Sorted by English label; `translationLanguages()` re-sorts for the
 * UI language. `label` is a getter so every consumer reads the name in
 * the current UI language at render time, not at module load.
 *
 * Every entry must be a direction Chrome actually offers, in BOTH
 * directions, because the list feeds the source and target sides alike.
 * A language Chrome does not translate renders as a dead "Not offered"
 * row that the user can neither use nor dismiss.
 *
 * Persian ("fa") was here and is deliberately NOT: Chrome reports
 * `unavailable` for both `fa->en` and `en->fa`. Do not re-add it without
 * checking `Translator.availability()` first -- the whole list was probed
 * against a real browser and `fa` was the only one that failed.
 */
export const TRANSLATION_LANGUAGES: LanguageOption[] = ENGLISH_NAMES.map(
  ([code]) => ({
    code,
    get label() {
      return languageLabel(code);
    },
  }),
);

const CODES = new Set(ENGLISH_NAMES.map(([code]) => code));

/**
 * The offered languages sorted by their name in the UI language, for
 * pickers. Cheap enough to call per render.
 */
export function translationLanguages(): LanguageOption[] {
  let collator: Intl.Collator;
  try {
    collator = new Intl.Collator(uiLanguage());
  } catch {
    collator = new Intl.Collator("en");
  }
  return [...TRANSLATION_LANGUAGES].sort((a, b) =>
    collator.compare(a.label, b.label),
  );
}

/**
 * Narrow a detector result to a tag the translator will accept.
 *
 * The detector reports regional and script variants; the translator is
 * keyed on the tags in `TRANSLATION_LANGUAGES`. "pt-BR" and "pt-PT" are
 * both `pt`, but "zh-Hant" is NOT `zh` -- Traditional and Simplified are
 * separate models, so the script subtag is load-bearing and kept.
 */
export function baseLanguage(code: string): string {
  if (CODES.has(code)) return code;
  const dash = code.indexOf("-");
  return dash === -1 ? code : code.slice(0, dash);
}

/** Display name for a code in the UI language (Intl.DisplayNames, with
 *  the English table as the fallback), falling back to the code itself
 *  so an unexpected tag renders as something rather than nothing. */
export function languageLabel(code: string): string {
  const base = baseLanguage(code);
  const english = ENGLISH_BY_CODE.get(base);
  if (english === undefined) return code;
  return localisedName(base) ?? english;
}

/** Whether we offer this language at all (post-narrowing). */
export function isSupportedLanguage(code: string): boolean {
  return CODES.has(baseLanguage(code));
}
