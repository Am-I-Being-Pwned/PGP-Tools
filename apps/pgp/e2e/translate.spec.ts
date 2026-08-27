import type { BrowserContext, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  decryptInWorkspace,
  encryptToSelfInWorkspace,
  onboardWithPassword,
} from "./helpers";

const PASSWORD = "correct horse battery staple";
const MESSAGE = "bonjour tout le monde, comment allez-vous aujourd hui";

/**
 * Translation against a STUBBED built-in AI.
 *
 * Headless Chrome ships no Gemini/translation model, so the real APIs are
 * absent here -- which is itself worth a test (the first one below), but
 * would leave the actual feature untested. The rest of the file installs
 * a fake `Translator` / `LanguageDetector` in the panel realm before the
 * app boots and drives the real UI against it.
 *
 * The load-bearing assertions are the "before the press" steps. Since
 * translation now ships ENABLED and a missing model is installed on
 * demand, the property that keeps that honest is no longer "we never
 * download here" but "nothing happens until the button is pressed":
 * enabled-and-untouched must read no plaintext and fetch nothing
 * (T-AI-PLAINTEXT-DISCLOSURE, T-AI-TRANSLATE-METADATA). The unit tests in
 * lib/ai/translate.test.ts pin the same split at the module boundary --
 * `translateText`/`detectLanguage` never download, only the `ensure*`
 * functions do -- while these cover the wiring, which is where the rule
 * would realistically be lost.
 */

interface StubOptions {
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
async function stubBuiltInAi(
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
async function removeBuiltInAi(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).Translator;
    delete (window as unknown as Record<string, unknown>).LanguageDetector;
  });
}

function aiCalls(panel: Page): Promise<string[]> {
  return panel.evaluate(
    () => (window as unknown as { __aiCalls?: string[] }).__aiCalls ?? [],
  );
}

/** Flip the feature from its Settings page. Translation ships ON, so
 *  most tests need no setup and this is mainly used to turn it OFF. */
async function setTranslation(panel: Page, on: boolean): Promise<void> {
  await panel.getByRole("tab", { name: "Settings" }).click();
  await panel.getByRole("button", { name: "Translation" }).click();
  // Named, not `.first()`: the settings list behind the slide-over has
  // switches of its own that are still in the DOM.
  const sw = panel.getByRole("switch", {
    name: "Translate decrypted messages",
  });
  await expect(sw).toBeEnabled();
  const want = on ? "true" : "false";
  if ((await sw.getAttribute("aria-checked")) !== want) await sw.click();
  await expect(sw).toHaveAttribute("aria-checked", want);
  // Close the slide-over: while it is up it covers the tab bar and
  // swallows clicks meant for the workspace.
  await panel.getByRole("button", { name: "Back" }).click();
  await expect(sw).toHaveCount(0);
}

/** Encrypt a message to self, then decrypt it, landing on the result
 *  view where the Translate control lives. */
async function decryptedMessageOnScreen(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  const armored = await encryptToSelfInWorkspace(panel, MESSAGE);
  await decryptInWorkspace(panel, armored, MESSAGE);
}

test("the feature stays invisible where Chrome has no translation model", async ({
  context,
  panel,
}) => {
  await removeBuiltInAi(context);
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await panel.getByRole("tab", { name: "Settings" }).click();
  await panel.getByRole("button", { name: "Translation" }).click();

  await expect(
    panel.getByText("not available here", { exact: false }),
  ).toBeVisible();
  // The toggle must not be flippable into a state that cannot work.
  await expect(
    panel.getByRole("switch", { name: "Translate decrypted messages" }),
  ).toBeDisabled();
});

test("translates a decrypted message on demand", async ({ context, panel }) => {
  await stubBuiltInAi(context, { availability: "available", detected: "fr" });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await decryptedMessageOnScreen(panel);

  await expect(
    panel.getByRole("button", { name: /Translate to English/ }),
  ).toBeVisible();

  await test.step("no model has read the message before the click", async () => {
    // The "intentional" rule, stated precisely. Settings legitimately
    // probes `availability()` per language to render its pack list, and
    // those calls take no text -- so the property is not "zero AI calls"
    // but "nothing that READS the plaintext". Creating a session is the
    // first thing that could, and detection counts: it is a model
    // reading the message just as much as translation is.
    const calls = await aiCalls(panel);
    expect(
      calls.filter((c) => !c.startsWith("translator.availability")),
    ).toEqual([]);
  });

  await panel.getByRole("button", { name: /Translate to English/ }).click();

  await expect(panel.getByText(`TRANSLATED(${MESSAGE})`)).toBeVisible();
  await expect(
    panel.getByText(/Translated on this device from French/),
  ).toBeVisible();

  await test.step("both sessions are destroyed after use", async () => {
    const calls = await aiCalls(panel);
    expect(calls).toContain("detector.destroy");
    expect(calls).toContain("translator.destroy");
  });

  await test.step("the original plaintext is still on screen", async () => {
    // The translation is shown ALONGSIDE the message, never in place of
    // it: a user must be able to check the model against the original.
    await expect(panel.getByText(MESSAGE).first()).toBeVisible();
  });
});

test("installs a missing language pack on the press, then translates", async ({
  context,
  panel,
}) => {
  await stubBuiltInAi(context, {
    availability: "downloadable",
    detected: "fr",
  });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await decryptedMessageOnScreen(panel);

  await test.step("nothing is fetched before the press", async () => {
    // The boundary is the click, not the preference. Enabled-and-untouched
    // must cause no download, which is what keeps the shipped-on default
    // honest (T-AI-TRANSLATE-METADATA).
    expect(
      (await aiCalls(panel)).filter((c) => c.startsWith("translator.create")),
    ).toEqual([]);
  });

  await panel.getByRole("button", { name: /Translate to English/ }).click();

  // One press covers the download and the translation.
  await expect(panel.getByText(`TRANSLATED(${MESSAGE})`)).toBeVisible();
  expect(
    (await aiCalls(panel)).filter((c) => c.startsWith("translator.create")),
  ).not.toEqual([]);
});

test("installs the language detector when the profile lacks it", async ({
  context,
  panel,
}) => {
  // A fresh Chrome profile is missing the DETECTOR too, not just the
  // packs. Before this was handled the first press reported "not
  // available on this device" on a perfectly capable machine, forever.
  await stubBuiltInAi(context, {
    availability: "available",
    detected: "fr",
    detectorAvailability: "downloadable",
  });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await decryptedMessageOnScreen(panel);
  await panel.getByRole("button", { name: /Translate to English/ }).click();

  await expect(panel.getByText(`TRANSLATED(${MESSAGE})`)).toBeVisible();
  await expect(panel.getByText(/not available on this device/)).toHaveCount(0);
});

test("declines to guess when the detector is not confident", async ({
  context,
  panel,
}) => {
  await stubBuiltInAi(context, {
    availability: "available",
    detected: "fr",
    confidence: 0.2,
  });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await decryptedMessageOnScreen(panel);
  await panel.getByRole("button", { name: /Translate to English/ }).click();

  await expect(
    panel.getByText(/Could not identify the language/),
  ).toBeVisible();
  expect(
    (await aiCalls(panel)).filter((c) => c.startsWith("translator.create")),
  ).toEqual([]);
});

test("says so instead of translating a message already in the target language", async ({
  context,
  panel,
}) => {
  await stubBuiltInAi(context, { availability: "available", detected: "en" });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  await decryptedMessageOnScreen(panel);
  await panel.getByRole("button", { name: /Translate to English/ }).click();

  await expect(
    panel.getByText("This message is already in English."),
  ).toBeVisible();
  expect(
    (await aiCalls(panel)).filter((c) => c.startsWith("translator.create")),
  ).toEqual([]);
});

test("no translate control at all while the feature is off", async ({
  context,
  panel,
}) => {
  await stubBuiltInAi(context, { availability: "available", detected: "fr" });
  await panel.reload();

  await onboardWithPassword(panel, PASSWORD);
  // Translation ships ON, so switching it off is now the deliberate act
  // this test has to perform.
  await setTranslation(panel, false);
  await decryptedMessageOnScreen(panel);

  await expect(panel.getByRole("button", { name: /Translate to/ })).toHaveCount(
    0,
  );
  // Availability probes are excluded for the same reason as the test
  // above: visiting Settings renders the pack list, which probes. They
  // carry no text and fetch nothing.
  expect(
    (await aiCalls(panel)).filter(
      (c) => !c.startsWith("translator.availability"),
    ),
  ).toEqual([]);
});
