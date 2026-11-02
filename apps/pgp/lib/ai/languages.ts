/**
 * The curated languages offered for translation (each is a picker row and an
 * implied promise), as BCP 47 codes. `baseLanguage` is the one place a
 * detector's regional code is narrowed for the translator.
 */

import { uiLanguage } from "../i18n";

export interface LanguageOption {
  /** BCP 47 base tag. */
  code: string;
  /** Display name in the UI language (see `languageLabel`). */
  readonly label: string;
}

/** English names: the fallback for `languageLabel` and verbatim for an
 *  English UI (tests assert on the wording). */
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
  if (tag === "en" || tag.startsWith("en-")) return null;
  if (displayNames?.tag !== tag) {
    let names: Intl.DisplayNames | null;
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
 * Sorted by English label; `label` is a getter so it reads the current UI
 * language at render time.
 *
 * Every entry must translate in BOTH directions or it renders a dead row.
 * Persian ("fa") is deliberately absent: Chrome reports `unavailable` both
 * ways. Probe `Translator.availability()` before re-adding anything.
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

/** Offered languages sorted by UI-language name, for pickers. */
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

/** Narrow a detector result to a translator tag. "pt-BR" → `pt`, but
 *  "zh-Hant" is kept: Traditional and Simplified are separate models. */
export function baseLanguage(code: string): string {
  if (CODES.has(code)) return code;
  const dash = code.indexOf("-");
  return dash === -1 ? code : code.slice(0, dash);
}

/** Display name in the UI language, falling back to English, then the code. */
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
