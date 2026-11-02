/**
 * Presence and readiness checks for the built-in AI APIs; callers never touch
 * the globals directly:
 *  - The APIs don't exist in workers (incl. the MV3 service worker); the
 *    `typeof` guards turn that ReferenceError into "absent".
 *  - Hardware limits are left to `availability()`; the feature degrades to
 *    invisible (also the headless CI case).
 *  - `create()` downloads, `availability()` never does; keeping them apart
 *    keeps the decrypt path download-free (T-AI-TRANSLATE-METADATA).
 */

/** Pack size hint for settings copy; Chrome exposes no size up front. */
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
 * Chrome reports every pair `downloadable` until THIS origin has created a
 * translator for it (anti-fingerprinting), so "downloadable" may already be
 * on disk. Never present it to the user as a definite download.
 */
export async function translationAvailability(
  pair: TranslatorPair,
): Promise<AiAvailabilityState> {
  if (!translatorSupported()) return "unavailable";
  try {
    return await Translator.availability(pair);
  } catch {
    // An unsupported pair can reject instead of resolving "unavailable".
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

/** Whether translation works here at all (decides if settings render).
 *  Detector readiness is excluded: without it we only lose auto-detection. */
export async function translationSupportedHere(): Promise<boolean> {
  if (!translatorSupported()) return false;
  // en→es stands in for "does this device translate at all".
  const state = await translationAvailability({
    sourceLanguage: "en",
    targetLanguage: "es",
  });
  return state !== "unavailable";
}
