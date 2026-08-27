/**
 * Presence and readiness checks for the built-in AI APIs.
 *
 * Every caller in this app goes through here rather than touching the
 * globals, for three reasons:
 *
 *  1. REALM. Neither `Translator` nor `LanguageDetector` exists in a Web
 *     Worker, and therefore not in the MV3 service worker. A bare
 *     `Translator.availability()` in the wrong realm is a ReferenceError,
 *     not a `false`. The `typeof` guards below are what make "the API is
 *     absent" a first-class answer instead of a crash.
 *
 *  2. HARDWARE. The models need ~22 GB free disk and either >4 GB VRAM or
 *     16 GB RAM, and are desktop-only. We do not probe for any of that:
 *     `availability()` already accounts for it and returns "unavailable",
 *     so asking the browser is both simpler and correct as the floor
 *     moves. The whole feature degrades to INVISIBLE, never broken --
 *     which is also the CI case, since headless Chrome ships no model.
 *
 *  3. NO IMPLICIT DOWNLOADS. `create()` starts a model download when the
 *     pack is absent; `availability()` never does. Keeping the two apart
 *     behind named functions is what lets the decrypt path be provably
 *     download-free (see `translate.ts` and T-AI-TRANSLATE-METADATA).
 */

/**
 * What a pack download would cost the user, for the settings copy. Not
 * read from the browser -- Chrome exposes no size before the download
 * starts -- so it is deliberately vague rather than precise and wrong.
 */
export const LANGUAGE_PACK_SIZE_HINT = "usually a few tens of MB";

/** True when the Translator API exists in this realm at all. */
export function translatorSupported(): boolean {
  return typeof Translator !== "undefined";
}

/** True when the Language Detector API exists in this realm at all. */
export function detectorSupported(): boolean {
  return typeof LanguageDetector !== "undefined";
}

/**
 * Readiness of one translation direction. Never downloads.
 *
 * CAVEAT worth knowing before trusting a "downloadable": Chrome reports
 * every pair as `downloadable` until THIS origin has created a translator
 * for it, deliberately, so that a page cannot enumerate which language
 * packs a user already has. So "downloadable" means "we have not used
 * this pair yet", NOT "the bytes are absent" -- the pack may well be on
 * disk already, in which case the create() in `downloadLanguagePack`
 * returns near-instantly. Never present a "downloadable" pair to the user
 * as a definite download.
 */
export async function translationAvailability(
  pair: TranslatorPair,
): Promise<AiAvailabilityState> {
  if (!translatorSupported()) return "unavailable";
  try {
    return await Translator.availability(pair);
  } catch {
    // An unsupported pair can reject rather than resolve "unavailable".
    // Same outcome for us either way: nothing to offer.
    return "unavailable";
  }
}

/** Readiness of the language detector. Never downloads. */
export async function detectorAvailability(): Promise<AiAvailabilityState> {
  if (!detectorSupported()) return "unavailable";
  try {
    return await LanguageDetector.availability();
  } catch {
    return "unavailable";
  }
}

/**
 * Whether the translate feature can do anything at all on this machine.
 *
 * Used to decide if the settings section renders. Detector readiness is
 * NOT part of this: a missing detector costs us auto-detection, not
 * translation, and `translate.ts` falls back to an explicit source
 * language. Requiring both would hide a working feature.
 */
export async function translationSupportedHere(): Promise<boolean> {
  if (!translatorSupported()) return false;
  // "en" to "es" stands in for "does this device do translation".
  // A device with the feature reports something other than "unavailable"
  // for it; a device without reports "unavailable" for every pair.
  const state = await translationAvailability({
    sourceLanguage: "en",
    targetLanguage: "es",
  });
  return state !== "unavailable";
}
