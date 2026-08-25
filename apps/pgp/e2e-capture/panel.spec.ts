/**
 * Capture the REAL side panel for the store listing artwork.
 *
 * This is tooling, not a test, and it deliberately lives outside `e2e/`
 * (the config's `testDir`) so `pnpm test:e2e` and CI never pick it up and
 * the e2e count stays honest. Run it by hand:
 *
 *     npx playwright test --testDir=e2e-capture
 *
 * It reuses the e2e fixtures and helpers on purpose: the artwork should
 * drift when the UI drifts, and re-implementing the onboarding flow here
 * would just give it a second way to go stale.
 *
 * Output goes to `assets/store-listing/ui/`, which the promo build inlines
 * as a data URI. Re-run it whenever the workspace UI changes, then re-run
 * `python3 build.py --render` in `assets/store-listing/promo`.
 */

import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

import { getExtensionId, launchExtensionContext } from "../e2e/fixtures";
import { importContact } from "../e2e/helpers";
import { keyBySlug } from "../e2e/keys";

const EXTENSION_PATH = path.resolve(
  import.meta.dirname,
  "..",
  ".output",
  "chrome-mv3",
);

/**
 * The e2e `panel` fixture at 3x. Same launch path, but a device scale
 * factor of 3 so the capture has real pixels behind it: the tile renders
 * this narrow panel wider than captured, and a 1x shot next to crisp CSS
 * type looks exactly as soft as it is.
 */
const test = base.extend<{ context: BrowserContext; panel: Page }>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await launchExtensionContext(EXTENSION_PATH, {
      deviceScaleFactor: 3,
    });
    await use(context);
    await context.close();
  },
  panel: async ({ context }, use) => {
    const id = await getExtensionId(context);
    const page = await context.newPage();
    await page.goto(`chrome-extension://${id}/sidepanel.html`);
    await use(page);
    await page.close();
  },
});

const OUT = path.resolve(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "assets",
  "store-listing",
  "ui",
);

const PASSWORD = "correct horse battery staple";

// The recipient is a committed test fixture on example.com, which is
// IANA-reserved for exactly this. Do NOT swap it for a real-looking
// address: a screenshot on a store listing is an invitation to mail it.
const RECIPIENT = keyBySlug("standard"); // Alice Example

// Captured NARROW and rendered wide. 400px is about what a real side
// panel is, and the tile shows it at 520, so the whole UI comes out ~1.3x
// larger than life. That is the point: at store-thumbnail size a
// life-sized UI is an unreadable grey texture, and the panel has to read
// as a panel. The 3x device scale factor pays for the upscale, leaving
// ~2.3 device pixels per rendered pixel, so it stays sharp.
//
// Height is the tile's budget: the composer textarea flexes to fill, so a
// taller viewport just buys empty box -- but too short and the composer
// collides with the Recipients label, so 560 is the floor, not a choice.
const PANEL_WIDTH = 400;
const PANEL_HEIGHT = 560;

/**
 * Onboarding, but with an identity fit to be seen. `onboardWithPassword`
 * generates "E2E Test <e2e@test.local>", which is right for a test and
 * wrong for a screenshot.
 */
async function onboardAs(
  panel: Page,
  name: string,
  email: string,
): Promise<void> {
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Set password" }).click();
  await panel.getByPlaceholder("Your full name").fill(name);
  await panel.getByPlaceholder("you@example.com").fill(email);
  await panel.getByRole("button", { name: "Create my PGP key" }).click();
  await panel
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 30_000 });
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Drive the workspace into the state both shots want: encrypt mode, a
 *  recipient chosen, a message typed, signing on. */
async function composeEncrypt(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Encrypt", exact: true }).click();

  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel
    .getByRole("option", { name: new RegExp(RECIPIENT.name) })
    .first()
    .click();
  await expect(
    panel.getByRole("button", { name: /^Remove / }).first(),
  ).toBeVisible();

  await panel
    .locator("textarea")
    .first()
    .fill("Meet me at the usual place at 8. Bring the drive.");

  // Sign is the difference between "encrypted" and "encrypted and provably
  // from me", so the shot should have it on. ToggleBadge renders a
  // role="switch" carrying aria-checked, not a checkbox or a plain button.
  const sign = panel.getByRole("switch", { name: "Sign", exact: true });
  await expect(sign).toBeVisible();
  if ((await sign.getAttribute("aria-checked")) !== "true") await sign.click();
  await expect(sign).toHaveAttribute("aria-checked", "true");

  // Drop focus so no input carries a focus ring into the artwork.
  await panel.locator("body").click({ position: { x: 5, y: 5 } });
  await panel.waitForTimeout(400);
}

test("capture: workspace in encrypt mode", async ({ panel }) => {
  test.setTimeout(120_000);

  await onboardAs(panel, "James Arnott", "james@amibeingpwned.com");
  await importContact(panel, RECIPIENT.publicKey);

  await panel.setViewportSize({ width: PANEL_WIDTH, height: PANEL_HEIGHT });
  await composeEncrypt(panel);
  await panel.screenshot({
    path: path.join(OUT, "panel-encrypt.png"),
    scale: "device",
  });

  // The 1400x560 marquee reuses this same shot: `.uicrop` in parts.css
  // frames a window onto it rather than shrinking the whole panel. A
  // separate short-and-wide capture was tried first and does not work --
  // below roughly 500px of viewport height the composer collapses and
  // overlaps the Recipients label, whatever the width.
});
