import type { BrowserContext, Page } from "@playwright/test";

/**
 * A fake built-in AI (`Translator` / `LanguageDetector`) for specs that
 * drive the real translation UI. Headless Chrome ships no model, so the
 * real APIs are absent; these stand in for them and record every call on
 * `window.__aiCalls` so a spec can assert what was NOT called. See
 * `translate.spec.ts` for the properties that recording exists to pin.
 */

export interface StubOptions {
  /** What `Translator.availability()` reports for every pair. */
  availability: AiAvailabilityState;
  /** Detector result. "und" exercises the uncertain path. */
  detected: string;
  confidence?: number;
  /** What `LanguageDetector.availability()` reports. Defaults to
   *  "available"; "downloadable" exercises the fresh-profile path where
   *  the detector itself has to be installed first. */
  detectorAvailability?: AiAvailabilityState;
}

/**
 * Install the fake APIs for every subsequent navigation, and record each
 * call on `window.__aiCalls` so a test can assert what was NOT called.
 */
export async function stubBuiltInAi(
  context: BrowserContext,
  opts: StubOptions,
): Promise<void> {
  await context.addInitScript((o: StubOptions) => {
    const calls: string[] = [];
    (window as unknown as { __aiCalls: string[] }).__aiCalls = calls;

    // defineProperty rather than assignment: the real APIs are present
    // in current Chrome (reporting "downloadable" with no packs), and a
    // plain assignment does not reliably replace an existing global.
    const install = (name: string, value: unknown) =>
      Object.defineProperty(window, name, { value, configurable: true });

    // Stateful, because the real APIs are: creating a translator for a
    // pair is what downloads it, and availability() reports "available"
    // for that pair afterwards. A stub that kept saying "downloadable"
    // would make the install-then-translate flow look broken when it is
    // the stub that is wrong.
    const installedPairs = new Set<string>();
    let detectorInstalled =
      (o.detectorAvailability ?? "available") === "available";

    install("Translator", {
      availability: (pair: { sourceLanguage: string }) => {
        calls.push(`translator.availability:${pair.sourceLanguage}`);
        if (o.availability === "unavailable") {
          return Promise.resolve("unavailable");
        }
        return Promise.resolve(
          o.availability === "available" ||
            installedPairs.has(pair.sourceLanguage)
            ? "available"
            : o.availability,
        );
      },
      create: (pair: { sourceLanguage: string }) => {
        calls.push(`translator.create:${pair.sourceLanguage}`);
        installedPairs.add(pair.sourceLanguage);
        return Promise.resolve({
          translate: (input: string) => Promise.resolve(`TRANSLATED(${input})`),
          destroy: () => calls.push("translator.destroy"),
        });
      },
    });

    install("LanguageDetector", {
      availability: () =>
        Promise.resolve(detectorInstalled ? "available" : "downloadable"),
      create: () => {
        calls.push("detector.create");
        detectorInstalled = true;
        return Promise.resolve({
          detect: () =>
            Promise.resolve([
              {
                detectedLanguage: o.detected,
                confidence: o.confidence ?? 0.98,
              },
            ]),
          destroy: () => calls.push("detector.destroy"),
        });
      },
    });
  }, opts);
}

/** Simulate a device with no built-in AI at all, deterministically:
 *  current desktop Chrome DOES expose these globals (reporting
 *  "downloadable" with no packs installed), so the unsupported path
 *  cannot be reached just by running headless. */
export async function removeBuiltInAi(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).Translator;
    delete (window as unknown as Record<string, unknown>).LanguageDetector;
  });
}

export function aiCalls(panel: Page): Promise<string[]> {
  return panel.evaluate(
    () => (window as unknown as { __aiCalls?: string[] }).__aiCalls ?? [],
  );
}
