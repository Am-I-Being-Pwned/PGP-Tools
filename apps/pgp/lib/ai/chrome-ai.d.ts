/**
 * Ambient declarations for Chrome's built-in AI APIs.
 *
 * These ship in Chrome (Translator and Language Detector are stable from
 * 138) but are not in TypeScript's DOM lib, so the globals are declared
 * here rather than reached for through `any`. Only the surface this app
 * actually calls is declared: adding a member here should mean we are
 * about to use it.
 *
 * NB: neither API is available in Web Workers, and therefore not in the
 * MV3 service worker. Everything under lib/ai is side-panel-only by
 * construction -- see the realm note in `availability.ts`.
 */

/** The four states every built-in AI API reports. */
type AiAvailabilityState =
  "unavailable" | "downloadable" | "downloading" | "available";

interface AiCreateMonitor extends EventTarget {
  addEventListener(
    type: "downloadprogress",
    listener: (event: { loaded: number }) => void,
  ): void;
}

interface AiCreateOptions {
  signal?: AbortSignal;
  monitor?: (monitor: AiCreateMonitor) => void;
}

interface LanguageDetectorResult {
  /** BCP 47 code, or "und" when the detector cannot decide. */
  detectedLanguage: string;
  /** 0.0 to 1.0, descending across the returned array. */
  confidence: number;
}

interface LanguageDetectorInstance {
  detect(text: string): Promise<LanguageDetectorResult[]>;
  destroy(): void;
}

declare const LanguageDetector: {
  availability(options?: {
    expectedInputLanguages?: string[];
  }): Promise<AiAvailabilityState>;
  create(
    options?: AiCreateOptions & { expectedInputLanguages?: string[] },
  ): Promise<LanguageDetectorInstance>;
};

interface TranslatorInstance {
  translate(input: string): Promise<string>;
  destroy(): void;
}

interface TranslatorPair {
  /** BCP 47 code. */
  sourceLanguage: string;
  /** BCP 47 code. */
  targetLanguage: string;
}

declare const Translator: {
  availability(pair: TranslatorPair): Promise<AiAvailabilityState>;
  create(
    options: TranslatorPair & AiCreateOptions,
  ): Promise<TranslatorInstance>;
};
