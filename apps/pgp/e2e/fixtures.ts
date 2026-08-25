import { existsSync } from "node:fs";
import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";
import { test as base, chromium, expect } from "@playwright/test";

function buildDir(name: string): string {
  return path.resolve(import.meta.dirname, "..", ".output", name);
}

const EXTENSION_PATH = buildDir("chrome-mv3");

/**
 * Launch a persistent Chromium context with an unpacked extension loaded.
 * Extensions load only under Chromium's *new* headless mode, not the
 * classic one `headless: true` selects -- so we launch "headed" (no
 * injected --headless=old) and pass --headless=new ourselves. HEADED=1
 * opens a real window.
 */
export async function launchExtensionContext(
  extensionDir: string,
  // Screenshot tooling (`e2e-capture/`) wants 2x pixels; tests want the
  // default. Optional so no existing caller changes behaviour.
  opts: { deviceScaleFactor?: number } = {},
): Promise<BrowserContext> {
  if (!existsSync(extensionDir)) {
    throw new Error(
      `Extension build not found at ${extensionDir}. Build it first.`,
    );
  }
  const headless = !process.env.HEADED;
  return chromium.launchPersistentContext("", {
    headless: false,
    ...(opts.deviceScaleFactor === undefined
      ? {}
      : { deviceScaleFactor: opts.deviceScaleFactor }),
    args: [
      ...(headless ? ["--headless=new"] : []),
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
    ],
  });
}

/** The extension id from the MV3 background service worker's URL. */
export async function getExtensionId(context: BrowserContext): Promise<string> {
  const sw =
    context.serviceWorkers()[0] ??
    (await context.waitForEvent("serviceworker"));
  return new URL(sw.url()).host;
}

interface Fixtures {
  context: BrowserContext;
  extensionId: string;
  /** A fresh tab pointed at the extension's side-panel page. */
  panel: Page;
}

/**
 * Loads the built extension into a persistent Chromium context and exposes
 * its generated extension id. Each test file gets its own empty profile
 * (userDataDir ""), so chrome.storage starts clean.
 */
export const test = base.extend<Fixtures>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await launchExtensionContext(EXTENSION_PATH);
    await use(context);
    await context.close();
  },

  extensionId: async ({ context }, use) => {
    await use(await getExtensionId(context));
  },

  panel: async ({ context, extensionId }, use) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/sidepanel.html`);
    await use(page);
    await page.close();
  },
});

export { expect };

/** Read a whole chrome.storage area from inside the extension page. */
export function readStorage(
  page: Page,
  areaName: "local" | "sync" | "session",
): Promise<Record<string, unknown>> {
  return page.evaluate((a) => chrome.storage[a].get(null), areaName);
}

/** Base64-decoded byte length of an { iv, ciphertext } blob's ciphertext. */
export function ciphertextBytes(blob: unknown): number {
  const ct = (blob as { ciphertext?: unknown } | null)?.ciphertext;
  if (typeof ct !== "string") {
    throw new Error("not an encrypted { iv, ciphertext } blob");
  }
  return Buffer.from(ct, "base64").length;
}
