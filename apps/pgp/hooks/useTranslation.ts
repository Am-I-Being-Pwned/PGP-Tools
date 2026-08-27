import { useCallback, useEffect, useRef, useState } from "react";

import { baseLanguage, languageLabel } from "../lib/ai/languages";
import {
  detectLanguage,
  ensureDetectorReady,
  ensureLanguagePack,
  translateText,
} from "../lib/ai/translate";

/**
 * Drives on-device translation of a decrypted message.
 *
 * INTENTIONAL BY CONSTRUCTION. Nothing here runs on decrypt, on mount, or
 * on output change -- `translate()` is called from a click and nothing
 * else. That includes LANGUAGE DETECTION, which is itself a model reading
 * the user's plaintext: detecting eagerly so the button could say
 * "Translate from Russian" would mean every decrypted message was fed to
 * a model whether or not the user ever wanted a translation. The button
 * stays generic and the detector runs inside the click.
 *
 * The translated text never passes through this hook's state; it goes
 * straight to `setTranslation`, which the workspace holds as a ref plus a
 * DOM node and wipes at master lock. Only the STATUS is state here.
 */

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

interface UseTranslationOptions {
  /** Read the decrypted text at the point of use, never hoisted. */
  getOutput: () => string;
  /** Bumps on every new result; a new message drops the old
   *  translation, which would otherwise sit under unrelated plaintext. */
  outputVersion: number;
  /** Write the translation into the workspace's ref + node. */
  setTranslation: (text: string) => void;
  /** BCP 47 tag to translate into. */
  targetLanguage: string;
}

export function useTranslation({
  getOutput,
  outputVersion,
  setTranslation,
  targetLanguage,
}: UseTranslationOptions) {
  const [status, setStatus] = useState<TranslationStatus>({ kind: "idle" });
  // Which of the two texts the result box is showing. The translation
  // REPLACES the message rather than sitting under it, so this is the
  // only thing that decides which one the user is reading; both strings
  // stay in their refs either way.
  const [showing, setShowing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStatus({ kind: "idle" });
    setShowing(false);
    setTranslation("");
  }, [setTranslation]);

  /** Flip between the decrypted message and its translation. */
  const toggle = useCallback(() => setShowing((v) => !v), []);

  // A new decrypt result invalidates the previous translation. Without
  // this, translating message A and then decrypting message B leaves A's
  // translation on screen beneath B's plaintext.
  useEffect(() => {
    reset();
  }, [outputVersion, reset]);

  // The target language is the other input to a translation; changing it
  // in Settings while a result is on screen makes the visible one stale.
  useEffect(() => {
    reset();
  }, [targetLanguage, reset]);

  // Abort in flight work when the panel goes away (master lock unmounts
  // the workspace), so no session outlives the plaintext it was given.
  useEffect(() => () => abortRef.current?.abort(), []);

  const translate = useCallback(async () => {
    const text = getOutput();
    if (!text.trim()) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus({ kind: "working" });

    // Read through a call, not `controller.signal.aborted` directly.
    // TypeScript narrows that property to `false` after the first check
    // and keeps the narrowing across every `await`, which is exactly
    // backwards here: the value changing WHILE we wait is the case these
    // checks exist for. A call is not narrowed.
    const aborted = () => controller.signal.aborted;

    try {
      // A fresh Chrome profile has neither the detector nor any language
      // pack, so both may need fetching before anything can happen. Both
      // are one-time and both report progress; neither runs without this
      // click. Ordered detector-first because we cannot know WHICH pack
      // to fetch until the language is known.
      const detectorReady = await ensureDetectorReady(
        (loaded) =>
          setStatus({
            kind: "downloading",
            what: "language detector",
            progress: loaded,
          }),
        controller.signal,
      );
      if (aborted()) return;
      if (!detectorReady) {
        setStatus({ kind: "unavailable" });
        return;
      }

      setStatus({ kind: "working" });
      const detected = await detectLanguage(text);
      if (aborted()) return;

      if (detected.status === "unavailable") {
        setStatus({ kind: "unavailable" });
        return;
      }
      // "too-short" and "uncertain" are the same thing to the user: we
      // are not confident enough to pick a source language for them.
      if (detected.status !== "detected") {
        setStatus({ kind: "uncertain" });
        return;
      }

      const from = detected.language;
      const to = baseLanguage(targetLanguage);
      if (from === to) {
        setStatus({ kind: "same-language", language: from });
        return;
      }

      const pair: TranslatorPair = {
        sourceLanguage: from,
        targetLanguage: to,
      };
      const packReady = await ensureLanguagePack(
        pair,
        (loaded) =>
          setStatus({
            kind: "downloading",
            what: `${languageLabel(from)} to ${languageLabel(to)}`,
            progress: loaded,
          }),
        controller.signal,
      );
      if (aborted()) return;
      if (!packReady) {
        // Chrome does not offer this direction at all. Not something the
        // user can fix by downloading, so it is not phrased as a pack.
        setStatus({ kind: "unavailable" });
        return;
      }

      setStatus({ kind: "working" });
      const result = await translateText(text, pair, controller.signal);
      if (aborted()) return;

      switch (result.status) {
        case "translated":
          setTranslation(result.text);
          setStatus({ kind: "done", from });
          // Show it immediately: the press asked for the translation, so
          // landing on the untranslated text would make the button look
          // like it had done nothing.
          setShowing(true);
          break;
        // Unreachable in practice: `ensureLanguagePack` just resolved
        // this direction. Kept as a real branch rather than a throw so a
        // race (a pack evicted between the two calls) degrades to a
        // retryable message instead of an unhandled rejection.
        case "needs-pack":
          setStatus({
            kind: "error",
            message: "The language pack went away. Try again.",
          });
          break;
        case "unsupported-pair":
        case "unavailable":
          setStatus({ kind: "unavailable" });
          break;
      }
    } catch (e) {
      if (aborted()) return;
      setStatus({
        kind: "error",
        message: e instanceof Error ? e.message : "Translation failed.",
      });
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }, [getOutput, setTranslation, targetLanguage]);

  return { status, showing, translate, toggle, reset };
}
