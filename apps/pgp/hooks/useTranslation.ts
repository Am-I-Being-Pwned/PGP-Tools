import { useCallback, useEffect, useRef, useState } from "react";

import {
  runTranslation,
  type TranslationStatus,
} from "~/lib/ai/run-translation";

/**
 * On-device translation of a decrypted message.
 *
 * CLICK-ONLY, including language detection: detecting eagerly would feed
 * every decrypted message to a model. The translated text bypasses state
 * (`setTranslation` -> workspace ref + node, wiped at master lock).
 */

export type { TranslationStatus };

interface UseTranslationOptions {
  /** Read at the point of use, never hoisted. */
  getOutput: () => string;
  /** A new result drops the old translation. */
  outputVersion: number;
  setTranslation: (text: string) => void;
  targetLanguage: string;
}

export function useTranslation({
  getOutput,
  outputVersion,
  setTranslation,
  targetLanguage,
}: UseTranslationOptions) {
  const [status, setStatus] = useState<TranslationStatus>({ kind: "idle" });
  // The translation REPLACES the message on screen; both stay in refs.
  const [showing, setShowing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStatus({ kind: "idle" });
    setShowing(false);
    setTranslation("");
  }, [setTranslation]);

  const toggle = useCallback(() => setShowing((v) => !v), []);

  useEffect(() => {
    reset();
  }, [outputVersion, reset]);

  useEffect(() => {
    reset();
  }, [targetLanguage, reset]);

  // No session outlives the plaintext it was given.
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
        setShowing(true);
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }, [getOutput, setTranslation, targetLanguage]);

  return { status, showing, translate, toggle, reset };
}
