import { useCallback, useEffect, useRef, useState } from "react";

import type { TranslationStatus } from "../lib/ai/run-translation";
import { runTranslation } from "../lib/ai/run-translation";

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

export type { TranslationStatus };

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

    try {
      const result = await runTranslation({
        text,
        targetLanguage,
        signal: controller.signal,
        onStatus: setStatus,
      });
      if (result) {
        setTranslation(result.text);
        // Show it immediately: the press asked for the translation, so
        // landing on the untranslated text would make the button look
        // like it had done nothing.
        setShowing(true);
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }, [getOutput, setTranslation, targetLanguage]);

  return { status, showing, translate, toggle, reset };
}
