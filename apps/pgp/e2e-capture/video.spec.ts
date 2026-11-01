/**
 * Capture the REAL side panel, state by state, for the promo video
 * (assets/store-listing/video). Tooling, not a test: it lives outside
 * `e2e/` so CI never runs it. Run by hand after `pnpm build`:
 *
 *     npx playwright test --config=playwright.capture.config.ts video
 *
 * Every frame is a screenshot of the shipped build, so the video cannot
 * drift from the product the way a hand-built mock does. Captured at 4x
 * so the video's camera can push in on a control and stay sharp.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

import { getExtensionId, launchExtensionContext } from "../e2e/fixtures";
import { importContactsBulk, setWorkspaceMode } from "../e2e/helpers";
import { keyBySlug, TEST_KEYS } from "../e2e/keys";

const APP = path.resolve(import.meta.dirname, "..");
const EXT = path.join(APP, ".output", "chrome-mv3");
const OUT = path.resolve(APP, "..", "..", "assets", "store-listing", "video", "ui");

const PASSWORD = "correct horse battery staple";
const MESSAGE = "Meet me at the usual place at 8. Bring the drive.";
// Contacts are committed example.com fixtures (IANA-reserved), never a
// real-looking address.
const ALICE = keyBySlug("standard");

/** Panel viewport. 400 wide is a real side panel; 640 tall keeps the
 *  composer roomy without a dead textarea. The video frames it at this
 *  aspect, so change both together. */
const W = 400;
const H = 640;

const test = base.extend<{ context: BrowserContext; panel: Page }>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await launchExtensionContext(EXT, { deviceScaleFactor: 4 });
    await use(context);
    await context.close();
  },
  panel: async ({ context }, use) => {
    const id = await getExtensionId(context);
    const page = await context.newPage();
    await page.setViewportSize({ width: W, height: H });
    await page.goto(`chrome-extension://${id}/sidepanel.html`);
    await use(page);
    await page.close();
  },
});

async function shot(panel: Page, name: string, settle = 450): Promise<void> {
  await panel.evaluate(() =>
    (document.activeElement as HTMLElement | null)?.blur(),
  );
  await panel.mouse.move(0, H - 1);
  await panel.waitForTimeout(settle);
  await panel.screenshot({ path: path.join(OUT, `${name}.png`), scale: "device" });
}

async function step(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    console.log(`STEP FAILED ${name}: ${(e as Error).message.split("\n")[0]}`);
  }
}

/** If an operation stops to ask for the key's password, give it. */
async function answerKeyPassword(panel: Page): Promise<void> {
  const pw = panel.getByPlaceholder("Enter password");
  if (await pw.isVisible({ timeout: 1500 }).catch(() => false)) {
    await pw.fill(PASSWORD);
    await pw.press("Enter");
  }
}

test("video capture", async ({ panel }) => {
  test.setTimeout(400_000);
  panel.setDefaultTimeout(10_000);
  mkdirSync(OUT, { recursive: true });

  // ── onboarding, as a person fit to be seen ─────────────────────────
  await shot(panel, "00-welcome");
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.waitForTimeout(400);
  await shot(panel, "01-protection");
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Set password" }).click();
  await panel.getByPlaceholder("Your full name").fill("James Arnott");
  await panel
    .getByPlaceholder("you@example.com")
    .fill("james@amibeingpwned.com");
  await shot(panel, "02-identity");
  await panel.getByRole("button", { name: "Create my PGP key" }).click();
  await panel
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 30_000 });
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });

  await importContactsBulk(
    panel,
    TEST_KEYS.filter((k) => k.encryptCapable)
      .slice(0, 6)
      .map((k) => k.publicKey),
  );

  // The app rings freshly imported contacts green for 2.6s
  // (KeysView's highlight timer); let it clear before the Keys shots.
  await panel.waitForTimeout(3000);

  // ── keys ───────────────────────────────────────────────────────────
  await step("keys", async () => {
    await panel.getByRole("tab", { name: "Keys" }).click();
    await panel.locator("main").evaluate((m) => m.scrollTo(0, 0));
    await shot(panel, "10-keys", 700);
  });
  await step("key details", async () => {
    await panel
      .getByText(ALICE.name, { exact: true })
      .filter({ visible: true })
      .first()
      .click();
    await shot(panel, "11-key-details", 1600);
    await panel.keyboard.press("Escape");
    await panel.waitForTimeout(500);
  });
  await step("generate", async () => {
    await panel.getByRole("tab", { name: "Keys" }).click();
    await panel.getByRole("button", { name: "Generate Key" }).click();
    await shot(panel, "12-generate", 1600);
    await panel.keyboard.press("Escape");
    await panel.waitForTimeout(500);
  });

  // ── encrypt, step by step ──────────────────────────────────────────
  await step("compose", async () => {
    await setWorkspaceMode(panel, "Encrypt");
    await shot(panel, "20-empty");
    await panel.getByRole("combobox", { name: /Recipients/ }).click();
    await panel.keyboard.type("a");
    await shot(panel, "21-picker", 500);
    await panel
      .getByRole("option", { name: new RegExp(ALICE.name) })
      .first()
      .click();
    await panel.keyboard.press("Escape");
    await shot(panel, "22-recipient");

    // Typed word by word: one frame per word, crossfaded in the video.
    const words = MESSAGE.split(" ");
    const input = panel.locator("#pgp-input");
    for (let i = 1; i <= words.length; i++) {
      await input.fill(words.slice(0, i).join(" "));
      await shot(panel, `23-type-${String(i).padStart(2, "0")}`, 150);
    }

    const sign = panel.getByRole("switch", { name: "Sign", exact: true });
    if ((await sign.getAttribute("aria-checked")) !== "true") await sign.click();
    await expect(sign).toHaveAttribute("aria-checked", "true");
    await shot(panel, "24-signed");
  });

  let armored = "";
  await step("encrypt", async () => {
    await panel
      .getByRole("button", { name: /^Encrypt/ })
      .last()
      .click();
    await answerKeyPassword(panel);
    await expect(panel.getByRole("button", { name: "Download" })).toBeVisible({
      timeout: 15_000,
    });
    await shot(panel, "25-encrypted", 900);
    const dl = panel.waitForEvent("download");
    await panel.getByRole("button", { name: "Download" }).click();
    armored = readFileSync(await (await dl).path(), "utf8");
    // The video types this out as the "what leaves your machine" card, so
    // it is real ciphertext from this run, not a lookalike.
    writeFileSync(path.join(OUT, "armored.asc"), armored);
  });

  // ── decrypt what we just made: plaintext and signer together ──────
  await step("decrypt", async () => {
    await panel.keyboard.press("Escape");
    await panel.keyboard.press("Escape");
    await setWorkspaceMode(panel, "Decrypt");
    await panel.locator("#pgp-input").fill(armored);
    await shot(panel, "30-ciphertext");
    await panel
      .getByRole("button", { name: /^Decrypt/ })
      .last()
      .click();
    await answerKeyPassword(panel);
    await expect(panel.getByText(MESSAGE).first()).toBeVisible({
      timeout: 15_000,
    });
    await shot(panel, "31-decrypted", 900);
  });

  // ── verify a message signed by a contact ──────────────────────────
  await step("verify", async () => {
    await panel.keyboard.press("Escape");
    await panel.keyboard.press("Escape");
    await setWorkspaceMode(panel, "Verify");
    await panel.locator("#pgp-input").fill(ALICE.signedMessage);
    await panel
      .getByRole("button", { name: /^Verify/ })
      .last()
      .click();
    await panel.waitForTimeout(1200);
    await shot(panel, "32-verified", 600);
  });

  // ── palette, settings, lock ───────────────────────────────────────
  await step("palette", async () => {
    await panel.keyboard.press("Escape");
    await panel.getByRole("tab", { name: "Main" }).click();
    await panel.getByRole("button", { name: "Commands" }).click();
    await expect(
      panel.getByRole("dialog", { name: "Command palette" }),
    ).toBeVisible();
    await panel.waitForTimeout(300);
    await panel.mouse.move(0, H - 1);
    await panel.screenshot({
      path: path.join(OUT, "40-palette.png"),
      scale: "device",
    });
    await panel.keyboard.press("Escape");
  });
  await step("settings", async () => {
    await panel.getByRole("tab", { name: "Settings" }).click();
    await shot(panel, "41-settings", 600);
  });
  await step("lock", async () => {
    await panel.reload();
    await expect(panel.getByLabel("Master password")).toBeVisible();
    await shot(panel, "50-locked", 700);
  });
});
