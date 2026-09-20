import { useCallback, useEffect, useRef, useState } from "react";

import type { TranslationStatus } from "../lib/ai/run-translation";
import { runTranslation } from "../lib/ai/run-translation";

/**
 * Translate the message being WRITTEN into the recipient's language.
 *
 * The result box's hook translates a decrypted message into the language
 * the user reads; this one goes the other way, FROM the language the
 * user reads (the Settings "translate into" language -- the one they
 * write in) into a language they pick per message. No detection: the
 * source is known, so the text is handed to one model, not two. The
 * pipeline is otherwise the same (`runTranslation`) and so are the
 * rules: nothing runs without the click, and sessions are per call.
 *
 * The translation REPLACES the box's text, with an undo. Replacing rather
 * than appending is what "translate on encryption" means: the recipient
 * gets the translated message, not both. The original is kept in a ref
 * for the undo and dropped once the user types again, so it cannot
 * outlive the composition it belongs to.
 */

interface UseComposeTranslationOptions {
  /** Read the composed text at the point of use, never hoisted. */
  getInput: () => string;
  /** Write the translation into the box (the workspace's own setter, so
   *  detection and the draft see it like typed text). */
  setInput: (text: string) => void;
  /** The language the user reads and writes in: the SOURCE of every
   *  composer translation. */
  readingLanguage: string;
  /** A translation landed in the box (source, target). */
  onTranslated?: (from: string, to: string) => void;
}

export function useComposeTranslation({
  getInput,
  setInput,
  readingLanguage,
  onTranslated,
}: UseComposeTranslationOptions) {
  const [status, setStatus] = useState<TranslationStatus>({ kind: "idle" });
  // Null until the user picks one: there is no sensible default target
  // for "translate my message", and a guessed one would put a language
  // the user never asked for on the button.
  const [targetLanguage, setTargetLanguage] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  // The text the translation replaced, for undo. Cleared by `forget`.
  const originalRef = useRef<string | null>(null);
  const [canUndo, setCanUndo] = useState(false);

  useEffect(() => () => abortRef.current?.abort(), []);

  const forget = useCallback(() => {
    originalRef.current = null;
    setCanUndo(false);
    setStatus((s) => (s.kind === "done" ? { kind: "idle" } : s));
  }, []);

  const undo = useCallback(() => {
    const original = originalRef.current;
    originalRef.current = null;
    setCanUndo(false);
    setStatus({ kind: "idle" });
    if (original !== null) setInput(original);
  }, [setInput]);

  const translate = useCallback(
    async (language: string) => {
      const text = getInput();
      if (!text.trim()) return;
      setTargetLanguage(language);

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const result = await runTranslation({
          text,
          sourceLanguage: readingLanguage,
          targetLanguage: language,
          signal: controller.signal,
          onStatus: setStatus,
        });
        if (result) {
          originalRef.current = text;
          setCanUndo(true);
          setInput(result.text);
          onTranslated?.(result.from, language);
        }
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [getInput, setInput, readingLanguage, onTranslated],
  );

  return { status, targetLanguage, translate, canUndo, undo, forget };
}
