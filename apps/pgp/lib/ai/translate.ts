/**
 * On-device translation of a decrypted message.
 *
 * DOWNLOADS ARE EXPLICIT, NOT IMPLICIT -- which is a weaker rule than the
 * one this file started with, and the weakening was deliberate.
 *
 * `Translator.create()` silently starts a model download when the pack is
 * absent, and which pair gets fetched is observable off-device: a
 * translate-on-decrypt that downloads correlates "this user just
 * decrypted something in Russian" with a network event we do not control
 * (T-AI-TRANSLATE-METADATA). The original design refused to download on
 * the decrypt path at all and sent the user to Settings.
 *
 * That was changed because it made the feature fail on first use for
 * essentially every user: nobody has a pack on a fresh profile, and on a
 * fresh profile the DETECTOR is missing too, so the honest-but-useless
 * outcome was a button that never worked. The rule now is that no
 * download happens without a user gesture and visible progress, rather
 * than that no download happens on this path.
 *
 * The split that survives, and that the tests pin: `translateText` and
 * `detectLanguage` still NEVER download -- they check `availability()`
 * and refuse. Fetching is confined to the two `ensure*` functions and
 * `downloadLanguagePack`, which only ever run from an explicit click.
 * Settings can still pre-download, which is the one way to get a pack
 * without it coinciding with a message.
 *
 * Second rule: sessions are per-call and destroyed in a `finally`. A live
 * Translator holds the text it was given, which here is decrypted
 * plaintext; pooling sessions to save the create() cost would keep that
 * plaintext alive for an unbounded time, against everything §1 promises
 * about plaintext lifetime. Slower, and correct.
 */

import {
  detectorSupported,
  translationAvailability,
  translatorSupported,
} from "./availability";
import { baseLanguage, isSupportedLanguage } from "./languages";

/**
 * Below this many characters we do not ask the detector at all.
 *
 * Chrome's own guidance is that "very short phrases and single words
 * should be avoided, as the accuracy of the results will be low". A
 * confident wrong answer is worse than no answer here: it would offer to
 * translate an English message from Dutch, and the user has no way to
 * tell the detector was guessing.
 */
export const MIN_DETECT_CHARS = 16;

/**
 * Confidence floor for acting on a detection.
 *
 * A judgment call, not a value from the spec. Detector confidences are
 * spread across candidates, so a genuine single-language message scores
 * well above this while a mixed or ambiguous one lands under it and we
 * fall back to asking the user. Tuned to prefer "we are not sure" over a
 * wrong flag next to someone's decrypted mail.
 */
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
  /** The pair is real but this origin has not downloaded it. The caller
   *  routes the user to Settings; it does NOT download here. */
  | { status: "needs-pack"; pair: TranslatorPair }
  /** No translator, or the device cannot run one. */
  | { status: "unavailable" }
  /** Chrome does not offer this direction. */
  | { status: "unsupported-pair"; pair: TranslatorPair };

// ── pure helpers (unit-tested without a browser) ──────────────────────

/**
 * Choose a language from a detector result set, or decline.
 *
 * Exported for its own sake: this is where "the detector said something"
 * becomes "we are willing to act on it", and that judgment is the part
 * worth testing directly. "und" is the detector's explicit "I cannot
 * tell" and is skipped even when it tops the list with high confidence.
 */
export function pickDetectedLanguage(
  results: readonly LanguageDetectorResult[],
): DetectOutcome {
  for (const r of results) {
    if (r.detectedLanguage === "und") continue;
    // Results arrive in descending confidence, so the first real
    // candidate is the best one; if it fails the floor, none pass.
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

/**
 * Whether a translation is worth offering.
 *
 * False when the message is already in the target language -- offering
 * "translate English to English" reads as a bug -- and false for
 * languages we do not carry a picker entry for, since the settings flow
 * could not download the pack anyway.
 */
export function shouldOfferTranslation(
  detected: string,
  target: string,
): boolean {
  const from = baseLanguage(detected);
  const to = baseLanguage(target);
  if (from === to) return false;
  return isSupportedLanguage(from) && isSupportedLanguage(to);
}

// ── sequential queue ──────────────────────────────────────────────────

/**
 * Chrome processes translations sequentially regardless of what we do, so
 * firing several concurrently buys nothing and makes cancellation and
 * error attribution murkier. One chain, awaited in order.
 *
 * Rejections are swallowed from the CHAIN (not from the caller, who still
 * gets their own rejection) so one failed translation does not poison
 * every request queued behind it.
 */
let queueTail: Promise<unknown> = Promise.resolve();

function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const run = queueTail.then(task, task);
  queueTail = run.catch(() => undefined);
  return run;
}

/** Test seam: drop any queued work so one test cannot serialise behind
 *  another's pending task. */
export function resetTranslationQueue(): void {
  queueTail = Promise.resolve();
}

// ── API glue ──────────────────────────────────────────────────────────

/**
 * Detect the language of decrypted text. Never downloads: the detector
 * model is a single small model rather than a per-pair pack, and we only
 * ever call it when `availability()` already says "available".
 */
export async function detectLanguage(text: string): Promise<DetectOutcome> {
  if (!detectorSupported()) return { status: "unavailable" };
  if (text.trim().length < MIN_DETECT_CHARS) return { status: "too-short" };

  // Same reasoning as the translator: creating downloads if absent, so
  // gate on availability first and decline rather than fetch.
  if ((await LanguageDetector.availability()) !== "available") {
    return { status: "unavailable" };
  }

  let detector: LanguageDetectorInstance | undefined;
  try {
    detector = await LanguageDetector.create();
    return pickDetectedLanguage(await detector.detect(text));
  } catch {
    // Detection is an enhancement; a failure here means "no banner",
    // never a visible error next to the user's decrypted message.
    return { status: "unavailable" };
  } finally {
    detector?.destroy();
  }
}

/**
 * Translate text, if and only if the pack is already present.
 *
 * `signal` aborts a queued or in-flight translation -- wired to auto-lock
 * so a lock does not leave plaintext sitting in a live session.
 */
export async function translateText(
  text: string,
  pair: TranslatorPair,
  signal?: AbortSignal,
): Promise<TranslateOutcome> {
  if (!translatorSupported()) return { status: "unavailable" };

  const state = await translationAvailability(pair);
  if (state === "unavailable") return { status: "unsupported-pair", pair };
  // "downloadable" and "downloading" both mean: not ready, and making it
  // ready is a network event. Neither is ours to trigger here.
  if (state !== "available") return { status: "needs-pack", pair };

  return enqueue(async () => {
    signal?.throwIfAborted();
    let translator: TranslatorInstance | undefined;
    try {
      translator = await Translator.create({ ...pair, signal });
      const translated = await translator.translate(text);
      return { status: "translated" as const, text: translated };
    } finally {
      // Destroyed on every path including abort: the session is holding
      // the plaintext we just handed it.
      translator?.destroy();
    }
  });
}

/**
 * Make the language detector usable, downloading it if this profile does
 * not have it yet.
 *
 * Needed because a fresh Chrome reports the DETECTOR as "downloadable"
 * too, not just the language packs. Without this the first press of
 * Translate would report "not available on this device" on a machine
 * that is perfectly capable, and would keep saying so forever.
 *
 * The detector is a single small model shared by every language, so
 * fetching it reveals only that this profile wants language detection --
 * not which language, and so not anything about the message. That is a
 * strictly weaker disclosure than a language pack.
 *
 * Returns false when the API is absent or the device cannot run it.
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
    // The download is the point; the session is not kept. Detection
    // creates its own, so the plaintext never touches this one.
    detector?.destroy();
  }
}

/**
 * Make one translation direction usable, downloading the pack if needed.
 *
 * Returns false for a direction Chrome does not offer at all, which is
 * not a failure the user can fix and must not be reported as one.
 */
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

/**
 * Download one language pack, with progress.
 *
 * Called from Settings (pre-download, decoupled from any message) and
 * from `ensureLanguagePack` on an explicit Translate press.
 *
 * `onProgress` receives 0..1. Resolves once the pack is usable; the
 * created translator is destroyed immediately, since the point of the
 * call is the download, not a translation.
 */
export async function downloadLanguagePack(
  pair: TranslatorPair,
  onProgress?: (loaded: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (!translatorSupported()) {
    throw new Error("Translation is not available on this device.");
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
