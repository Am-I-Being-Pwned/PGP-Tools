import { afterEach, describe, expect, it, vi } from "vitest";

import {
  detectLanguage,
  downloadLanguagePack,
  ensureDetectorReady,
  ensureLanguagePack,
  MIN_DETECT_CONFIDENCE,
  pickDetectedLanguage,
  resetTranslationQueue,
  shouldOfferTranslation,
  translateText,
} from "./translate";

// The ambient declarations type these as `const` globals that always
// exist, which is the right shape for app code (it never runs in a realm
// where they are optional -- it checks first). Tests are the one place
// that installs and removes them, hence the casts.
const realm = globalThis as unknown as {
  Translator?: unknown;
  LanguageDetector?: unknown;
};

interface TranslatorStubOptions {
  availability?: AiAvailabilityState;
  translate?: (input: string) => Promise<string>;
  availabilityThrows?: boolean;
}

function installTranslator(opts: TranslatorStubOptions = {}) {
  const destroy = vi.fn();
  const translate = vi.fn(
    opts.translate ?? ((input: string) => Promise.resolve(`[t] ${input}`)),
  );
  const create = vi.fn(() => Promise.resolve({ translate, destroy }));
  const availability = vi.fn(() =>
    opts.availabilityThrows
      ? Promise.reject(new Error("unsupported pair"))
      : Promise.resolve(opts.availability ?? "available"),
  );
  realm.Translator = { availability, create };
  return { availability, create, translate, destroy };
}

function installDetector(
  results: LanguageDetectorResult[],
  state = "available",
) {
  const destroy = vi.fn();
  const detect = vi.fn(() => Promise.resolve(results));
  const create = vi.fn(() => Promise.resolve({ detect, destroy }));
  const availability = vi.fn(() => Promise.resolve(state));
  realm.LanguageDetector = { availability, create };
  return { availability, create, detect, destroy };
}

const EN_ES = { sourceLanguage: "en", targetLanguage: "es" };

afterEach(() => {
  delete realm.Translator;
  delete realm.LanguageDetector;
  resetTranslationQueue();
  vi.restoreAllMocks();
});

describe("pickDetectedLanguage", () => {
  it("takes the top candidate when it clears the confidence floor", () => {
    expect(
      pickDetectedLanguage([
        { detectedLanguage: "ru", confidence: 0.9 },
        { detectedLanguage: "uk", confidence: 0.05 },
      ]),
    ).toEqual({ status: "detected", language: "ru", confidence: 0.9 });
  });

  it("declines rather than guessing below the floor", () => {
    expect(
      pickDetectedLanguage([
        { detectedLanguage: "nl", confidence: MIN_DETECT_CONFIDENCE - 0.01 },
      ]),
    ).toEqual({ status: "uncertain" });
  });

  it("skips 'und' even when it tops the list confidently", () => {
    expect(
      pickDetectedLanguage([
        { detectedLanguage: "und", confidence: 0.99 },
        { detectedLanguage: "fr", confidence: 0.8 },
      ]),
    ).toEqual({ status: "detected", language: "fr", confidence: 0.8 });
  });

  it("narrows a regional tag to the tag the translator accepts", () => {
    expect(
      pickDetectedLanguage([{ detectedLanguage: "pt-BR", confidence: 0.95 }]),
    ).toMatchObject({ language: "pt" });
  });

  it("keeps a script subtag, which selects a different model", () => {
    expect(
      pickDetectedLanguage([{ detectedLanguage: "zh-Hant", confidence: 0.95 }]),
    ).toMatchObject({ language: "zh-Hant" });
  });

  it("is uncertain when the detector returns nothing", () => {
    expect(pickDetectedLanguage([])).toEqual({ status: "uncertain" });
  });
});

describe("shouldOfferTranslation", () => {
  it("does not offer a translation into the same language", () => {
    expect(shouldOfferTranslation("en", "en")).toBe(false);
  });

  it("treats a regional variant as the same language", () => {
    expect(shouldOfferTranslation("pt-BR", "pt")).toBe(false);
  });

  it("offers across the two Chinese scripts, which are distinct models", () => {
    expect(shouldOfferTranslation("zh-Hant", "zh")).toBe(true);
  });

  it("declines a language the settings picker cannot download", () => {
    expect(shouldOfferTranslation("cy", "en")).toBe(false);
  });
});

describe("translateText", () => {
  it("translates when the pack is already present", async () => {
    const stub = installTranslator();
    await expect(translateText("hola", EN_ES)).resolves.toEqual({
      status: "translated",
      text: "[t] hola",
    });
    expect(stub.destroy).toHaveBeenCalled();
  });

  // The security property this whole module is shaped around: on the
  // decrypt path a missing pack must NOT become a download, because which
  // pair is fetched is observable off-device and would correlate with the
  // message just decrypted. T-AI-TRANSLATE-METADATA.
  it("never calls create() when the pack is absent", async () => {
    const stub = installTranslator({ availability: "downloadable" });
    await expect(translateText("hola", EN_ES)).resolves.toEqual({
      status: "needs-pack",
      pair: EN_ES,
    });
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("never calls create() while a pack is mid-download", async () => {
    const stub = installTranslator({ availability: "downloading" });
    await expect(translateText("hola", EN_ES)).resolves.toMatchObject({
      status: "needs-pack",
    });
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("reports an unsupported direction without creating", async () => {
    const stub = installTranslator({ availability: "unavailable" });
    await expect(translateText("hola", EN_ES)).resolves.toEqual({
      status: "unsupported-pair",
      pair: EN_ES,
    });
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("treats a throwing availability check as an unsupported pair", async () => {
    installTranslator({ availabilityThrows: true });
    await expect(translateText("hola", EN_ES)).resolves.toMatchObject({
      status: "unsupported-pair",
    });
  });

  it("is unavailable when the API is absent from the realm", async () => {
    await expect(translateText("hola", EN_ES)).resolves.toEqual({
      status: "unavailable",
    });
  });

  it("destroys the session even when translation throws", async () => {
    const stub = installTranslator({
      translate: () => Promise.reject(new Error("boom")),
    });
    await expect(translateText("hola", EN_ES)).rejects.toThrow("boom");
    expect(stub.destroy).toHaveBeenCalled();
  });

  it("runs queued translations one at a time", async () => {
    const order: string[] = [];
    installTranslator({
      translate: async (input) => {
        order.push(`start:${input}`);
        await new Promise((r) => setTimeout(r, input === "slow" ? 20 : 0));
        order.push(`end:${input}`);
        return input;
      },
    });

    await Promise.all([
      translateText("slow", EN_ES),
      translateText("fast", EN_ES),
    ]);

    // Interleaving would read start:slow, start:fast, end:fast, end:slow.
    expect(order).toEqual(["start:slow", "end:slow", "start:fast", "end:fast"]);
  });

  it("does not let a failed translation poison the ones queued behind it", async () => {
    let call = 0;
    installTranslator({
      translate: (input) => {
        call += 1;
        return call === 1
          ? Promise.reject(new Error("first fails"))
          : Promise.resolve(input);
      },
    });

    const failing = translateText("a", EN_ES);
    const following = translateText("b", EN_ES);

    await expect(failing).rejects.toThrow("first fails");
    await expect(following).resolves.toEqual({
      status: "translated",
      text: "b",
    });
  });

  it("refuses an already-aborted request without creating a session", async () => {
    const stub = installTranslator();
    await expect(
      translateText("hola", EN_ES, AbortSignal.abort()),
    ).rejects.toThrow();
    expect(stub.create).not.toHaveBeenCalled();
  });
});

describe("detectLanguage", () => {
  it("does not ask the detector about text too short to judge", async () => {
    const stub = installDetector([{ detectedLanguage: "fr", confidence: 1 }]);
    await expect(detectLanguage("oui")).resolves.toEqual({
      status: "too-short",
    });
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("detects and destroys the detector", async () => {
    const stub = installDetector([{ detectedLanguage: "fr", confidence: 0.9 }]);
    await expect(
      detectLanguage("bonjour tout le monde, comment allez-vous"),
    ).resolves.toMatchObject({ status: "detected", language: "fr" });
    expect(stub.destroy).toHaveBeenCalled();
  });

  it("never downloads the detector model", async () => {
    const stub = installDetector([], "downloadable");
    await expect(
      detectLanguage("bonjour tout le monde, comment allez-vous"),
    ).resolves.toEqual({ status: "unavailable" });
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("degrades to unavailable rather than surfacing a detector error", async () => {
    realm.LanguageDetector = {
      availability: () => Promise.resolve("available"),
      create: () => Promise.reject(new Error("no model")),
    };
    await expect(
      detectLanguage("bonjour tout le monde, comment allez-vous"),
    ).resolves.toEqual({ status: "unavailable" });
  });

  it("is unavailable when the API is absent from the realm", async () => {
    await expect(
      detectLanguage("bonjour tout le monde, comment allez-vous"),
    ).resolves.toEqual({ status: "unavailable" });
  });
});

describe("ensureDetectorReady", () => {
  it("does not download when the detector is already present", async () => {
    const stub = installDetector([], "available");
    await expect(ensureDetectorReady()).resolves.toBe(true);
    expect(stub.create).not.toHaveBeenCalled();
  });

  // A fresh Chrome profile reports the DETECTOR as downloadable too, not
  // just the language packs. Without this the first Translate press would
  // report "unavailable" on a perfectly capable machine, forever.
  it("downloads the detector when the profile does not have it", async () => {
    const stub = installDetector([], "downloadable");
    await expect(ensureDetectorReady()).resolves.toBe(true);
    expect(stub.create).toHaveBeenCalled();
    // The download is the point; the session is not kept, so the
    // plaintext never touches it.
    expect(stub.destroy).toHaveBeenCalled();
  });

  it("gives up on a device that cannot run the detector", async () => {
    const stub = installDetector([], "unavailable");
    await expect(ensureDetectorReady()).resolves.toBe(false);
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("is false when the API is absent from the realm", async () => {
    await expect(ensureDetectorReady()).resolves.toBe(false);
  });
});

describe("ensureLanguagePack", () => {
  it("does not download a pack that is already present", async () => {
    const stub = installTranslator({ availability: "available" });
    await expect(ensureLanguagePack(EN_ES)).resolves.toBe(true);
    expect(stub.create).not.toHaveBeenCalled();
  });

  it("downloads a missing pack and reports progress", async () => {
    const destroy = vi.fn();
    const create = vi.fn(
      (opts: { monitor?: (m: { addEventListener: unknown }) => void }) => {
        opts.monitor?.({
          addEventListener: (_t: string, fn: (e: unknown) => void) =>
            fn({ loaded: 0.25 }),
        });
        return Promise.resolve({ translate: vi.fn(), destroy });
      },
    );
    realm.Translator = {
      availability: () => Promise.resolve("downloadable"),
      create,
    };

    const progress: number[] = [];
    await expect(
      ensureLanguagePack(EN_ES, (p) => progress.push(p)),
    ).resolves.toBe(true);
    expect(progress).toEqual([0.25]);
  });

  it("reports a direction Chrome does not offer as unfixable, not as a download", async () => {
    const stub = installTranslator({ availability: "unavailable" });
    await expect(ensureLanguagePack(EN_ES)).resolves.toBe(false);
    expect(stub.create).not.toHaveBeenCalled();
  });
});

describe("downloadLanguagePack", () => {
  it("creates a translator and reports progress", async () => {
    const destroy = vi.fn();
    const create = vi.fn(
      (opts: { monitor?: (m: { addEventListener: unknown }) => void }) => {
        opts.monitor?.({
          addEventListener: (_type: string, fn: (e: unknown) => void) => {
            fn({ loaded: 0.5 });
          },
        });
        return Promise.resolve({ translate: vi.fn(), destroy });
      },
    );
    realm.Translator = { availability: vi.fn(), create };

    const progress: number[] = [];
    await downloadLanguagePack(EN_ES, (p) => progress.push(p));

    expect(create).toHaveBeenCalled();
    expect(progress).toEqual([0.5]);
    // The download is the point; the session is not kept.
    expect(destroy).toHaveBeenCalled();
  });

  it("throws where translation is not supported at all", async () => {
    await expect(downloadLanguagePack(EN_ES)).rejects.toThrow(
      "not available on this device",
    );
  });
});
