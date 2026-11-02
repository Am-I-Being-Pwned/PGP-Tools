import { useCallback, useEffect, useRef, useState } from "react";

import type { TranslationStatus } from "../lib/ai/run-translation";
import { runTranslation } from "../lib/ai/run-translation";

/**
 * Translate the message being WRITTEN, from the user's reading language
 * into one picked per message. Click-only, per-call sessions. The result
 * REPLACES the box's text with an undo; the original is dropped once the
 * user edits again so it cannot outlive the composition.
 */

interface UseComposeTranslationOptions {
  /** Read at the point of use, never hoisted. */
  getInput: () => string;
  setInput: (text: string) => void;
  readingLanguage: string;
  onTranslated?: (from: string, to: string) => void;
}

export function useComposeTranslation({
  getInput,
  setInput,
  readingLanguage,
  onTranslated,
}: UseComposeTranslationOptions) {
  const [status, setStatus] = useState<TranslationStatus>({ kind: "idle" });
  // No default target: a guess would name a language the user never chose.
  const [targetLanguage, setTargetLanguage] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  // Undo original; cleared by `forget` (master lock, or user edits).
  const originalRef = useRef<string | null>(null);
  // Distinguishes a user edit from our own write landing.
  const lastWrittenRef = useRef<string | null>(null);
  const [canUndo, setCanUndo] = useState(false);

  useEffect(() => () => abortRef.current?.abort(), []);

  const forget = useCallback(() => {
    originalRef.current = null;
    lastWrittenRef.current = null;
    setCanUndo(false);
    setStatus((s) => (s.kind === "done" ? { kind: "idle" } : s));
  }, []);

  const noteInputChanged = useCallback(
    (text: string) => {
      if (lastWrittenRef.current !== null && text !== lastWrittenRef.current) {
        forget();
      }
    },
    [forget],
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStatus((s) =>
      s.kind === "working" || s.kind === "downloading" ? { kind: "idle" } : s,
    );
  }, []);

  const undo = useCallback(() => {
    const original = originalRef.current;
    originalRef.current = null;
    lastWrittenRef.current = original;
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
        // The box changed while the model ran: don't replace it.
        if (result && getInput() === text) {
          originalRef.current = text;
          lastWrittenRef.current = result.text;
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

  return {
    status,
    targetLanguage,
    translate,
    canUndo,
    undo,
    forget,
    noteInputChanged,
    cancel,
  };
}
