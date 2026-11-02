/**
 * Chrome built-in AI globals (stable from 138), declaring only what we
 * call. Not available in workers, so lib/ai is side-panel-only.
 */

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
  /** 0..1, descending across the array. */
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
  sourceLanguage: string;
  targetLanguage: string;
}

declare const Translator: {
  availability(pair: TranslatorPair): Promise<AiAvailabilityState>;
  create(
    options: TranslatorPair & AiCreateOptions,
  ): Promise<TranslatorInstance>;
};
