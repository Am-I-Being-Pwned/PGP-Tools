/**
 * Presence and readiness checks for Chrome's built-in AI APIs.
 *
 * The property that makes this module worth having, and the one pinned
 * here, is that "the API is absent" must be a first-class ANSWER rather
 * than a crash. Neither `Translator` nor `LanguageDetector` exists in a
 * Web Worker -- and therefore not in the MV3 service worker -- so a bare
 * `Translator.availability()` in the wrong realm is a ReferenceError, not
 * a `false`. Every caller goes through here precisely so the whole
 * feature degrades to INVISIBLE instead of broken.
 *
 * Second property: NOTHING here may start a model download. `create()`
 * fetches a language pack when one is absent; `availability()` never
 * does. Keeping the two apart behind named functions is what lets the
 * decrypt path be provably download-free, so these tests assert that the
 * globals are only ever consulted, never created from.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  detectorAvailability,
  detectorSupported,
  LANGUAGE_PACK_SIZE_HINT,
  translationAvailability,
  translationSupportedHere,
  translatorSupported,
} from "./availability";

const PAIR = { sourceLanguage: "en", targetLanguage: "es" };

/** Install a fake `Translator` / `LanguageDetector` global. `undefined`
 *  leaves the global absent, which is the service-worker case. */
function stubApis(opts: {
  translator?: { availability?: unknown; create?: unknown };
  detector?: { availability?: unknown; create?: unknown };
}) {
  if (opts.translator) vi.stubGlobal("Translator", opts.translator);
  if (opts.detector) vi.stubGlobal("LanguageDetector", opts.detector);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("realm guards", () => {
  it("reports both APIs unsupported when the globals are absent", () => {
    // The MV3 service worker. A bare reference here would throw.
    expect(translatorSupported()).toBe(false);
    expect(detectorSupported()).toBe(false);
  });

  it("reports supported once the globals exist", () => {
    stubApis({ translator: {}, detector: {} });
    expect(translatorSupported()).toBe(true);
    expect(detectorSupported()).toBe(true);
  });

  it("answers unavailable rather than throwing when the API is absent", async () => {
    await expect(translationAvailability(PAIR)).resolves.toBe("unavailable");
    await expect(detectorAvailability()).resolves.toBe("unavailable");
    await expect(translationSupportedHere()).resolves.toBe(false);
  });
});

describe("translationAvailability", () => {
  it("passes the pair through and returns what the browser says", async () => {
    const availability = vi.fn(() => Promise.resolve("available"));
    stubApis({ translator: { availability } });

    await expect(translationAvailability(PAIR)).resolves.toBe("available");
    expect(availability).toHaveBeenCalledWith(PAIR);
  });

  it.each([["available"], ["downloadable"], ["downloading"], ["unavailable"]])(
    "passes through the %s state verbatim",
    async (state) => {
      stubApis({ translator: { availability: () => Promise.resolve(state) } });
      await expect(translationAvailability(PAIR)).resolves.toBe(state);
    },
  );

  it("treats a rejection as unavailable", async () => {
    // An unsupported pair can reject rather than resolve "unavailable".
    // Same outcome for us either way: nothing to offer.
    stubApis({
      translator: { availability: () => Promise.reject(new Error("bad pair")) },
    });
    await expect(translationAvailability(PAIR)).resolves.toBe("unavailable");
  });

  it("treats a synchronous throw as unavailable", async () => {
    stubApis({
      translator: {
        availability: () => {
          throw new Error("boom");
        },
      },
    });
    await expect(translationAvailability(PAIR)).resolves.toBe("unavailable");
  });

  it("never calls create()", async () => {
    // create() starts a model download; availability() must not.
    const create = vi.fn();
    stubApis({
      translator: {
        availability: () => Promise.resolve("downloadable"),
        create,
      },
    });

    await translationAvailability(PAIR);

    expect(create).not.toHaveBeenCalled();
  });
});

describe("detectorAvailability", () => {
  it("returns what the browser says", async () => {
    stubApis({
      detector: { availability: () => Promise.resolve("available") },
    });
    await expect(detectorAvailability()).resolves.toBe("available");
  });

  it("treats a rejection as unavailable", async () => {
    stubApis({
      detector: { availability: () => Promise.reject(new Error("nope")) },
    });
    await expect(detectorAvailability()).resolves.toBe("unavailable");
  });

  it("never calls create()", async () => {
    const create = vi.fn();
    stubApis({
      detector: { availability: () => Promise.resolve("downloadable"), create },
    });

    await detectorAvailability();

    expect(create).not.toHaveBeenCalled();
  });
});

describe("translationSupportedHere", () => {
  it.each([["available"], ["downloadable"], ["downloading"]])(
    "reports the device capable when en->es is %s",
    async (state) => {
      // "downloadable" counts: Chrome reports every unused pair that way
      // so a page can't enumerate which packs a user already has. It
      // means "we have not used this pair", not "the bytes are absent".
      stubApis({ translator: { availability: () => Promise.resolve(state) } });
      await expect(translationSupportedHere()).resolves.toBe(true);
    },
  );

  it("reports the device incapable when en->es is unavailable", async () => {
    // A machine below the hardware floor reports "unavailable" for every
    // pair -- we never probe disk or RAM ourselves.
    stubApis({
      translator: { availability: () => Promise.resolve("unavailable") },
    });
    await expect(translationSupportedHere()).resolves.toBe(false);
  });

  it("probes with en->es as the stand-in pair", async () => {
    const availability = vi.fn(() => Promise.resolve("available"));
    stubApis({ translator: { availability } });

    await translationSupportedHere();

    expect(availability).toHaveBeenCalledWith(PAIR);
  });

  it("does not require a working detector", async () => {
    // A missing detector costs auto-detection, not translation. Requiring
    // both would hide a working feature.
    stubApis({
      translator: { availability: () => Promise.resolve("available") },
    });
    expect(detectorSupported()).toBe(false);
    await expect(translationSupportedHere()).resolves.toBe(true);
  });
});

describe("LANGUAGE_PACK_SIZE_HINT", () => {
  it("stays deliberately vague, because Chrome exposes no size", () => {
    // Better vague than precise and wrong.
    expect(LANGUAGE_PACK_SIZE_HINT).toMatch(/usually/);
    expect(LANGUAGE_PACK_SIZE_HINT).not.toMatch(/\d/);
  });
});
