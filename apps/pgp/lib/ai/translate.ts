/**
 * On-device translation of a decrypted message.
 *
 * Downloads are explicit: `Translator.create()` silently fetches a missing
 * pack, and which pair is fetched is observable off-device
 * (T-AI-TRANSLATE-METADATA). So `translateText` / `detectLanguage` NEVER
 * download (they check `availability()` and refuse); only the `ensure*`
 * functions and `downloadLanguagePack` fetch, and only from a user gesture
 * with visible progress. Tests pin this split.
 *
 * Sessions are per-call and destroyed in `finally`: a live Translator holds
 * decrypted plaintext, so pooling would extend plaintext lifetime (§1).
 */

import { t } from "../i18n";
import {
  detectorSupported,
  translationAvailability,
  translatorSupported,
} from "./availability";
import { baseLanguage, isSupportedLanguage } from "./languages";

/** Below this many characters we don't ask the detector: a confident wrong
 *  answer on short text is worse than none. */
export const MIN_DETECT_CHARS = 16;

/** Confidence floor for acting on a detection. A judgment call, tuned to
 *  prefer "not sure" over a wrong flag. */
export const MIN_DETECT_CONFIDENCE = 0.55;

export type DetectOutcome =
  | { status: "detected"; language: string; confidence: number }
  /** The detector ran but nothing cleared the confidence floor. */
  | { status: "uncertain" }
  /** Too little text for the detector to be worth trusting. */
  | { status: "too-short" }
  /** No detector in this realm / on this device. */
  | { status: "unavailable" };

export type TranslateOutcome =
  | { status: "translated"; text: string }
  /** Pair exists but isn't downloaded; the caller must NOT download here. */
  | { status: "needs-pack"; pair: TranslatorPair }
  /** No translator, or the device cannot run one. */
  | { status: "unavailable" }
  /** Chrome does not offer this direction. */
  | { status: "unsupported-pair"; pair: TranslatorPair };

/** Choose a language from detector results, or decline. "und" is skipped
 *  even at high confidence. */
export function pickDetectedLanguage(
  results: readonly LanguageDetectorResult[],
): DetectOutcome {
  for (const r of results) {
    if (r.detectedLanguage === "und") continue;
    // Descending confidence: if the first real candidate fails, all do.
    return r.confidence >= MIN_DETECT_CONFIDENCE
      ? {
          status: "detected",
          language: baseLanguage(r.detectedLanguage),
          confidence: r.confidence,
        }
      : { status: "uncertain" };
  }
  return { status: "uncertain" };
}

/** False when already in the target language, or for languages without a
 *  picker entry (no pack could be downloaded). */
export function shouldOfferTranslation(
  detected: string,
  target: string,
): boolean {
  const from = baseLanguage(detected);
  const to = baseLanguage(target);
  if (from === to) return false;
  return isSupportedLanguage(from) && isSupportedLanguage(to);
}

// Chrome translates sequentially anyway; one chain keeps cancellation and
// errors attributable. Rejections are swallowed from the CHAIN only, so one
// failure doesn't poison the queue.
let queueTail: Promise<unknown> = Promise.resolve();

function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const run = queueTail.then(task, task);
  queueTail = run.catch(() => undefined);
  return run;
}

/** Test seam: drop any queued work. */
export function resetTranslationQueue(): void {
  queueTail = Promise.resolve();
}

/** Detect the language of decrypted text. Never downloads. */
export async function detectLanguage(text: string): Promise<DetectOutcome> {
  if (!detectorSupported()) return { status: "unavailable" };
  if (text.trim().length < MIN_DETECT_CHARS) return { status: "too-short" };

  // create() downloads if absent, so gate on availability and decline.
  if ((await LanguageDetector.availability()) !== "available") {
    return { status: "unavailable" };
  }

  let detector: LanguageDetectorInstance | undefined;
  try {
    detector = await LanguageDetector.create();
    return pickDetectedLanguage(await detector.detect(text));
  } catch {
    // Enhancement only: failure means "no banner", never a visible error.
    return { status: "unavailable" };
  } finally {
    detector?.destroy();
  }
}

/** Translate only if the pack is already present. `signal` is wired to
 *  auto-lock so a lock doesn't leave plaintext in a live session. */
export async function translateText(
  text: string,
  pair: TranslatorPair,
  signal?: AbortSignal,
): Promise<TranslateOutcome> {
  if (!translatorSupported()) return { status: "unavailable" };

  const state = await translationAvailability(pair);
  if (state === "unavailable") return { status: "unsupported-pair", pair };
  // Not ready, and making it ready is a network event — not ours to trigger.
  if (state !== "available") return { status: "needs-pack", pair };

  return enqueue(async () => {
    signal?.throwIfAborted();
    let translator: TranslatorInstance | undefined;
    try {
      translator = await Translator.create({ ...pair, signal });
      const translated = await translator.translate(text);
      return { status: "translated" as const, text: translated };
    } finally {
      // Destroyed on every path: the session holds the plaintext.
      translator?.destroy();
    }
  });
}

/**
 * Make the language detector usable, downloading it if needed (a fresh
 * profile reports the detector "downloadable" too). The detector is one
 * shared model, so fetching it reveals nothing about the message's language.
 * Returns false when the API is absent or the device can't run it.
 */
export async function ensureDetectorReady(
  onProgress?: (loaded: number) => void,
  signal?: AbortSignal,
): Promise<boolean> {
  if (!detectorSupported()) return false;

  const state = await LanguageDetector.availability();
  if (state === "available") return true;
  if (state === "unavailable") return false;

  let detector: LanguageDetectorInstance | undefined;
  try {
    detector = await LanguageDetector.create({
      signal,
      monitor: (m) => {
        m.addEventListener("downloadprogress", (e) => onProgress?.(e.loaded));
      },
    });
    return true;
  } catch {
    return false;
  } finally {
    // Only the download matters; detection creates its own session.
    detector?.destroy();
  }
}

/** Make one translation direction usable, downloading if needed. False for a
 *  direction Chrome doesn't offer (not a user-fixable failure). */
export async function ensureLanguagePack(
  pair: TranslatorPair,
  onProgress?: (loaded: number) => void,
  signal?: AbortSignal,
): Promise<boolean> {
  const state = await translationAvailability(pair);
  if (state === "available") return true;
  if (state === "unavailable") return false;

  await downloadLanguagePack(pair, onProgress, signal);
  return true;
}

/** Download one language pack (Settings pre-download, or an explicit
 *  Translate press). `onProgress` receives 0..1. */
export async function downloadLanguagePack(
  pair: TranslatorPair,
  onProgress?: (loaded: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (!translatorSupported()) {
    throw new Error(t("settings_translation_unavailable_device"));
  }

  let translator: TranslatorInstance | undefined;
  try {
    translator = await Translator.create({
      ...pair,
      signal,
      monitor: (m) => {
        m.addEventListener("downloadprogress", (e) => onProgress?.(e.loaded));
      },
    });
  } finally {
    translator?.destroy();
  }
}
