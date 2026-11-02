/**
 * Pins: an absent API (service-worker realm) is an answer, not a crash; and
 * nothing here ever calls `create()` (which downloads).
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

/** Install fake AI globals; `undefined` leaves one absent (the SW case). */
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
      // Chrome reports every unused pair "downloadable" (anti-enumeration).
      stubApis({ translator: { availability: () => Promise.resolve(state) } });
      await expect(translationSupportedHere()).resolves.toBe(true);
    },
  );

  it("reports the device incapable when en->es is unavailable", async () => {
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
    // A missing detector costs auto-detection, not translation.
    stubApis({
      translator: { availability: () => Promise.resolve("available") },
    });
    expect(detectorSupported()).toBe(false);
    await expect(translationSupportedHere()).resolves.toBe(true);
  });
});

describe("LANGUAGE_PACK_SIZE_HINT", () => {
  it("stays deliberately vague, because Chrome exposes no size", () => {
    expect(LANGUAGE_PACK_SIZE_HINT).toMatch(/usually/);
    expect(LANGUAGE_PACK_SIZE_HINT).not.toMatch(/\d/);
  });
});
