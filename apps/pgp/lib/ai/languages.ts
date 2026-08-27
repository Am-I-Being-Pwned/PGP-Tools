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

export interface LanguageOption {
  /** BCP 47 base tag. */
  code: string;
  /** English name, shown in the picker. */
  label: string;
}

/**
 * Sorted by label so the settings picker needs no sort of its own.
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
export const TRANSLATION_LANGUAGES: LanguageOption[] = [
  { code: "ar", label: "Arabic" },
  { code: "bn", label: "Bengali" },
  { code: "zh", label: "Chinese (Simplified)" },
  { code: "zh-Hant", label: "Chinese (Traditional)" },
  { code: "cs", label: "Czech" },
  { code: "nl", label: "Dutch" },
  { code: "en", label: "English" },
  { code: "fr", label: "French" },
  { code: "de", label: "German" },
  { code: "el", label: "Greek" },
  { code: "he", label: "Hebrew" },
  { code: "hi", label: "Hindi" },
  { code: "id", label: "Indonesian" },
  { code: "it", label: "Italian" },
  { code: "ja", label: "Japanese" },
  { code: "ko", label: "Korean" },
  { code: "pl", label: "Polish" },
  { code: "pt", label: "Portuguese" },
  { code: "ru", label: "Russian" },
  { code: "es", label: "Spanish" },
  { code: "th", label: "Thai" },
  { code: "tr", label: "Turkish" },
  { code: "uk", label: "Ukrainian" },
  { code: "vi", label: "Vietnamese" },
];

const BY_CODE = new Map(TRANSLATION_LANGUAGES.map((l) => [l.code, l]));

/**
 * Narrow a detector result to a tag the translator will accept.
 *
 * The detector reports regional and script variants; the translator is
 * keyed on the tags in `TRANSLATION_LANGUAGES`. "pt-BR" and "pt-PT" are
 * both `pt`, but "zh-Hant" is NOT `zh` -- Traditional and Simplified are
 * separate models, so the script subtag is load-bearing and kept.
 */
export function baseLanguage(code: string): string {
  if (BY_CODE.has(code)) return code;
  const dash = code.indexOf("-");
  return dash === -1 ? code : code.slice(0, dash);
}

/** Display name for a code, falling back to the code itself so an
 *  unexpected tag renders as something rather than nothing. */
export function languageLabel(code: string): string {
  return BY_CODE.get(baseLanguage(code))?.label ?? code;
}

/** Whether we offer this language at all (post-narrowing). */
export function isSupportedLanguage(code: string): boolean {
  return BY_CODE.has(baseLanguage(code));
}
