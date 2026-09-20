/**
 * The one translation pipeline, shared by the result box (translate a
 * decrypted message INTO the language the user reads) and the composer
 * (translate a message being written INTO the recipient's language).
 *
 * Both are: detector ready -> detect the source -> pack ready -> translate.
 * Neither step runs without the click that called this; see the rules in
 * `translate.ts` and `hooks/useTranslation.ts`. The two callers differ only
 * in where the text comes from and where the result goes, so those stay
 * with them; everything that touches a model is here, once.
 */

import { baseLanguage, languageLabel } from "./languages";
import {
  detectLanguage,
  ensureDetectorReady,
  ensureLanguagePack,
  translateText,
} from "./translate";

export type TranslationStatus =
  | { kind: "idle" }
  | { kind: "working" }
  | { kind: "done"; from: string }
  /** A one-time model download is running, triggered by this click.
   *  `progress` is 0..1; Chrome does not always report it, so the UI
   *  must stay sensible at a flat 0. */
  | { kind: "downloading"; what: string; progress: number }
  /** Already in the target language, so there is nothing to do. */
  | { kind: "same-language"; language: string }
  /** The detector would only be guessing. */
  | { kind: "uncertain" }
  /** No model on this device, or the direction is not offered. */
  | { kind: "unavailable" }
  | { kind: "error"; message: string };

export interface RunTranslationOptions {
  text: string;
  /** BCP 47 tag to translate into. */
  targetLanguage: string;
  /** BCP 47 tag the text is in, when the caller KNOWS it -- the composer
   *  does: the user writes in the language they read. Given, no detector
   *  is readied or run and the text is handed to one model, not two.
   *  Absent, the source is detected (the decrypt path, where the sender
   *  chose the language). */
  sourceLanguage?: string;
  signal: AbortSignal;
  /** Every intermediate status, in order. The terminal one is also the
   *  return value's meaning: `done` iff a translation is returned. */
  onStatus: (status: TranslationStatus) => void;
}

/**
 * Run the pipeline. Resolves to the translation and the detected source
 * language, or to `null` after reporting a terminal non-`done` status
 * (`unavailable`, `uncertain`, `same-language`, `error`). Resolves to
 * `null` silently once `signal` is aborted -- the caller has moved on.
 */
export async function runTranslation({
  text,
  targetLanguage,
  sourceLanguage,
  signal,
  onStatus,
}: RunTranslationOptions): Promise<{ text: string; from: string } | null> {
  // Read through a call, not `signal.aborted` directly: TypeScript
  // narrows that property to `false` after the first check and keeps the
  // narrowing across every `await`, which is exactly backwards here.
  const aborted = () => signal.aborted;

  try {
    onStatus({ kind: "working" });
    const from = sourceLanguage
      ? baseLanguage(sourceLanguage)
      : await detectSource(text, signal, onStatus);
    if (aborted() || from === null) return null;

    const to = baseLanguage(targetLanguage);
    if (from === to) {
      onStatus({ kind: "same-language", language: from });
      return null;
    }

    const pair: TranslatorPair = { sourceLanguage: from, targetLanguage: to };
    const packReady = await ensureLanguagePack(
      pair,
      (loaded) =>
        onStatus({
          kind: "downloading",
          what: `${languageLabel(from)} to ${languageLabel(to)}`,
          progress: loaded,
        }),
      signal,
    );
    if (aborted()) return null;
    if (!packReady) {
      // Chrome does not offer this direction at all. Not something the
      // user can fix by downloading, so it is not phrased as a pack.
      onStatus({ kind: "unavailable" });
      return null;
    }

    onStatus({ kind: "working" });
    const result = await translateText(text, pair, signal);
    if (aborted()) return null;

    switch (result.status) {
      case "translated":
        onStatus({ kind: "done", from });
        return { text: result.text, from };
      // Unreachable in practice: `ensureLanguagePack` just resolved this
      // direction. Kept as a real branch rather than a throw so a race (a
      // pack evicted between the two calls) degrades to a retryable
      // message instead of an unhandled rejection.
      case "needs-pack":
        onStatus({
          kind: "error",
          message: "The language pack went away. Try again.",
        });
        return null;
      case "unsupported-pair":
      case "unavailable":
        onStatus({ kind: "unavailable" });
        return null;
    }
  } catch (e) {
    if (aborted()) return null;
    onStatus({
      kind: "error",
      message: e instanceof Error ? e.message : "Translation failed.",
    });
    return null;
  }
}

/** Ready the detector (fetching it if this profile has none) and detect
 *  the source language, reporting the terminal status and returning
 *  null when there is no usable answer. */
async function detectSource(
  text: string,
  signal: AbortSignal,
  onStatus: (status: TranslationStatus) => void,
): Promise<string | null> {
  // Through a call, for the narrowing reason given in `runTranslation`.
  const aborted = () => signal.aborted;
  // A fresh Chrome profile has neither the detector nor any language
  // pack, so both may need fetching before anything can happen. Both
  // are one-time and both report progress; neither runs without this
  // click. Ordered detector-first because we cannot know WHICH pack to
  // fetch until the language is known.
  const detectorReady = await ensureDetectorReady(
    (loaded) =>
      onStatus({
        kind: "downloading",
        what: "language detector",
        progress: loaded,
      }),
    signal,
  );
  if (aborted()) return null;
  if (!detectorReady) {
    onStatus({ kind: "unavailable" });
    return null;
  }

  onStatus({ kind: "working" });
  const detected = await detectLanguage(text);
  if (aborted()) return null;

  if (detected.status === "unavailable") {
    onStatus({ kind: "unavailable" });
    return null;
  }
  // "too-short" and "uncertain" are the same thing to the user: we are
  // not confident enough to pick a source language for them.
  if (detected.status !== "detected") {
    onStatus({ kind: "uncertain" });
    return null;
  }
  return detected.language;
}
