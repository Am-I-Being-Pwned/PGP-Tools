/**
 * The one translation pipeline, shared by the result box and the composer:
 * detector ready → detect → pack ready → translate. Runs only from the click
 * that called it (see `translate.ts`).
 */

import { t } from "../i18n";
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
  /** One-time model download triggered by this click. `progress` 0..1 and
   *  not always reported, so the UI must cope with a flat 0. */
  | { kind: "downloading"; what: string; progress: number }
  /** Already in the target language, so there is nothing to do. */
  | { kind: "same-language"; language: string }
  | { kind: "uncertain" }
  /** No model on this device, or the direction is not offered. */
  | { kind: "unavailable" }
  | { kind: "error"; message: string };

export interface RunTranslationOptions {
  text: string;
  /** BCP 47 tag to translate into. */
  targetLanguage: string;
  /** Known source language (the composer); skips detection. Absent on the
   *  decrypt path, where it is detected. */
  sourceLanguage?: string;
  signal: AbortSignal;
  /** Every status, in order; the terminal one is `done` iff a translation is returned. */
  onStatus: (status: TranslationStatus) => void;
}

/** Run the pipeline. Resolves to the translation, or `null` after a terminal
 *  non-`done` status, or `null` silently once `signal` is aborted. */
export async function runTranslation({
  text,
  targetLanguage,
  sourceLanguage,
  signal,
  onStatus,
}: RunTranslationOptions): Promise<{ text: string; from: string } | null> {
  // A call, not `signal.aborted`: TS keeps the `false` narrowing across awaits.
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
          what: t("settings_translation_pack_pair", {
            from: languageLabel(from),
            to: languageLabel(to),
          }),
          progress: loaded,
        }),
      signal,
    );
    if (aborted()) return null;
    if (!packReady) {
      // Direction not offered at all; not a fixable pack problem.
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
      // Race: pack evicted since ensureLanguagePack. Retryable, not a throw.
      case "needs-pack":
        onStatus({
          kind: "error",
          message: t("settings_translation_pack_gone"),
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
      message:
        e instanceof Error ? e.message : t("settings_translation_failed"),
    });
    return null;
  }
}

/** Ready the detector (downloading if needed) and detect the source; null
 *  after reporting a terminal status. */
async function detectSource(
  text: string,
  signal: AbortSignal,
  onStatus: (status: TranslationStatus) => void,
): Promise<string | null> {
  const aborted = () => signal.aborted;
  // Detector first: we can't know which pack to fetch until the language is known.
  const detectorReady = await ensureDetectorReady(
    (loaded) =>
      onStatus({
        kind: "downloading",
        what: t("settings_translation_detector"),
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
  // "too-short" and "uncertain" mean the same to the user.
  if (detected.status !== "detected") {
    onStatus({ kind: "uncertain" });
    return null;
  }
  return detected.language;
}
