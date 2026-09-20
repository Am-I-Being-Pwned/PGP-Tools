/**
 * Capture the REAL side panel for the store listing artwork, once per
 * shipped UI language.
 *
 * This is tooling, not a test, and it deliberately lives outside `e2e/`
 * (the config's `testDir`) so `pnpm test:e2e` and CI never pick it up and
 * the e2e count stays honest. Run it by hand:
 *
 *     npx playwright test --config=playwright.capture.config.ts
 *     LOCALES=en,de npx playwright test --config=playwright.capture.config.ts
 *
 * It reuses the e2e fixtures and helpers on purpose: the artwork should
 * drift when the UI drifts, and re-implementing the onboarding flow here
 * would just give it a second way to go stale.
 *
 * Every selector is resolved through the built message bundle for the
 * locale being captured (`public/_locales/<locale>/messages.json`), so the
 * same flow drives a German or Japanese panel. The panel is put into that
 * language by loading a COPY of the build whose manifest `default_locale`
 * is the target and which carries no other locale: Chrome then has nothing
 * else to resolve to. (`--lang` would be the obvious lever, but Chromium
 * on macOS ignores it and follows the OS language.)
 *
 * Output goes to `assets/store-listing/ui/<locale>/`, which the promo build
 * inlines as a data URI per locale. Re-run it whenever the workspace UI or
 * a translation changes, then re-run `python3 build.py --render` in
 * `assets/store-listing/promo`.
 */

import {
  cpSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

import { getExtensionId, launchExtensionContext } from "../e2e/fixtures";
import { keyBySlug } from "../e2e/keys";

const APP = path.resolve(import.meta.dirname, "..");
const PROMO = path.resolve(APP, "..", "..", "assets", "store-listing", "promo");
const EXTENSION_PATH = path.join(APP, ".output", "chrome-mv3");
const OUT = path.resolve(APP, "..", "..", "assets", "store-listing", "ui");

/** Locales with a full UI translation. Everything else falls back to en
 *  in the product and gets no localised artwork. Override with LOCALES. */
const DEFAULT_LOCALES = [
  "en",
  "de",
  "es",
  "fr",
  "hi",
  "it",
  "ja",
  "pt_BR",
  "ru",
  "zh_CN",
];
const LOCALES = process.env.LOCALES
  ? process.env.LOCALES.split(",")
  : DEFAULT_LOCALES;

const PASSWORD = "correct horse battery staple";

// The recipient is a committed test fixture on example.com, which is
// IANA-reserved for exactly this. Do NOT swap it for a real-looking
// address: a screenshot on a store listing is an invitation to mail it.
const RECIPIENT = keyBySlug("standard"); // Alice Example

// Captured NARROW and rendered wide. 400px is about what a real side
// panel is, and the tile shows it at 528, so the whole UI comes out ~1.3x
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

/** Message text for `locale`, falling back to en the way Chrome does. */
function bundle(locale: string): (key: string) => string {
  const read = (l: string) =>
    JSON.parse(
      readFileSync(
        path.join(APP, "public", "_locales", l, "messages.json"),
        "utf8",
      ),
    ) as Partial<Record<string, { message: string }>>;
  const own = read(locale);
  const en = read("en");
  return (key) => {
    const m = own[key]?.message ?? en[key]?.message;
    if (m === undefined) throw new Error(`no message "${key}" for ${locale}`);
    return m;
  };
}

/** A string from the promo tiles' own copy table for this locale. */
function promoStrings(locale: string): (key: string) => string {
  const read = (l: string) =>
    JSON.parse(
      readFileSync(path.join(PROMO, "i18n", `${l}.json`), "utf8"),
    ) as Partial<Record<string, string>>;
  const en = read("en");
  const own = locale === "en" ? en : read(locale);
  return (key) => {
    const v = own[key] ?? en[key];
    if (v === undefined) throw new Error(`no promo string "${key}"`);
    return v;
  };
}

/**
 * A throwaway copy of the build forced to `locale`: `default_locale` set
 * to it and every other `_locales/*` removed, so chrome.i18n resolves to
 * it whatever language Chromium runs in. Lives under `.output/` (ignored).
 */
function forcedLocaleBuild(locale: string): string {
  if (locale === "en") return EXTENSION_PATH;
  const dir = path.join(APP, ".output", `capture-${locale}`);
  rmSync(dir, { recursive: true, force: true });
  cpSync(EXTENSION_PATH, dir, { recursive: true });
  const manifestPath = path.join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<
    string,
    unknown
  >;
  manifest.default_locale = locale;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  for (const entry of readdirSync(path.join(dir, "_locales"))) {
    if (entry !== locale)
      rmSync(path.join(dir, "_locales", entry), {
        recursive: true,
        force: true,
      });
  }
  return dir;
}

for (const locale of LOCALES) {
  const t = bundle(locale);
  const promoString = promoStrings(locale);

  const test = base.extend<{ context: BrowserContext; panel: Page }>({
    // eslint-disable-next-line no-empty-pattern
    context: async ({}, use) => {
      const context = await launchExtensionContext(forcedLocaleBuild(locale), {
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
    await panel.getByRole("button", { name: t("app_onboarding_next") }).click();
    await panel.locator('input[name="protection"]').nth(1).check();
    await panel
      .getByLabel(t("keygen_protection_password"), { exact: true })
      .fill(PASSWORD);
    await panel.getByLabel(t("keygen_confirm_password")).fill(PASSWORD);
    await panel
      .getByRole("button", { name: t("app_onboarding_set_password") })
      .click();
    await panel
      .getByPlaceholder(t("app_onboarding_name_placeholder"))
      .fill(name);
    await panel
      .getByPlaceholder(t("app_onboarding_email_placeholder"))
      .fill(email);
    await panel
      .getByRole("button", { name: t("app_onboarding_create_key") })
      .click();
    await panel
      .getByRole("button", { name: t("app_onboarding_keep_defaults") })
      .click({ timeout: 30_000 });
    await expect(
      panel.getByRole("tab", { name: t("common_keys") }),
    ).toBeVisible({ timeout: 30_000 });
  }

  /** `e2e/helpers.importContact`, with localised names. */
  async function importContact(panel: Page, armored: string): Promise<void> {
    await panel.getByRole("tab", { name: t("common_keys") }).click();
    await expect(
      panel.getByRole("heading", { name: t("actions_group_my_keys") }),
    ).toBeVisible();
    await panel
      .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
      .setInputFiles({
        name: "key.asc",
        mimeType: "application/pgp-keys",
        buffer: Buffer.from(armored, "utf8"),
      });
    await panel
      .getByRole("button", { name: t("import_action_import_contact") })
      .click();
    await expect(
      panel.getByRole("region", { name: t("import_title") }),
    ).toBeHidden();
  }

  /** Drive the workspace into the state the shot wants: encrypt mode, a
   *  recipient chosen, a message typed, signing on. */
  async function composeEncrypt(panel: Page): Promise<void> {
    await panel.getByRole("tab", { name: t("app_tab_main") }).click();
    await panel.getByRole("combobox").first().click();
    await panel
      .getByRole("option", { name: t("common_encrypt"), exact: true })
      .click();

    await panel
      .getByRole("combobox", { name: t("workspace_recipients_label") })
      .click();
    await panel
      .getByRole("option", { name: new RegExp(RECIPIENT.name) })
      .first()
      .click();
    // The chip's remove button is "Remove $name$" in every locale.
    const removeLabel = t("actions_remove_recipient").split("$name$")[0];
    await expect(
      panel
        .getByRole("button", { name: new RegExp(`^${removeLabel}`) })
        .first(),
    ).toBeVisible();

    // The typed message is listing copy, so it lives with the tile copy.
    await panel
      .locator("textarea")
      .first()
      .fill(promoString("a.panel_message"));

    // Sign is the difference between "encrypted" and "encrypted and provably
    // from me", so the shot should have it on. ToggleBadge renders a
    // role="switch" carrying aria-checked, not a checkbox or a plain button.
    const sign = panel.getByRole("switch", {
      name: t("common_sign"),
      exact: true,
    });
    await expect(sign).toBeVisible();
    if ((await sign.getAttribute("aria-checked")) !== "true")
      await sign.click();
    await expect(sign).toHaveAttribute("aria-checked", "true");

    // Drop focus so no input carries a focus ring into the artwork.
    await panel.locator("body").click({ position: { x: 5, y: 5 } });
    await panel.waitForTimeout(400);
  }

  test(`capture ${locale}: workspace in encrypt mode`, async ({ panel }) => {
    test.setTimeout(120_000);

    await onboardAs(panel, "James Arnott", "james@amibeingpwned.com");
    await importContact(panel, RECIPIENT.publicKey);

    await panel.setViewportSize({ width: PANEL_WIDTH, height: PANEL_HEIGHT });
    await composeEncrypt(panel);
    const dir = path.join(OUT, locale);
    await panel.screenshot({
      path: path.join(dir, "panel-encrypt.png"),
      scale: "device",
    });
    // The marquee reuses this shot: `.uicrop` in parts.css frames a window
    // onto it rather than shrinking the whole panel.
  });
}
