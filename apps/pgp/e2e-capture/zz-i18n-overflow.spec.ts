// Local-only i18n layout sweep (not a test, not committed output). For each
// translated locale, drive the main screens at side-panel widths and report
// every string that is truncated with an ellipsis or clipped by its box,
// mapped back to its message key. Run:
//   npx playwright test --config=playwright.capture.config.ts zz-i18n-overflow
//   LOCALES=de,fr WIDTHS=360 npx playwright test ... zz-i18n-overflow
import {
  cpSync,
  mkdirSync,
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
const EXTENSION_PATH = path.join(APP, ".output", "chrome-mv3");
const OUT = process.env.OUT ?? path.join(APP, "test-results", "i18n-overflow");
const LOCALES = (
  process.env.LOCALES ?? "en,de,es,fr,hi,it,ja,pt_BR,ru,zh_CN"
).split(",");
const WIDTHS = (process.env.WIDTHS ?? "360,400").split(",").map(Number);
const PASSWORD = "correct horse battery staple";

type Messages = Record<string, { message: string }>;
const readMessages = (l: string): Messages =>
  JSON.parse(
    readFileSync(path.join(APP, "public", "_locales", l, "messages.json"), "utf8"),
  ) as Messages;

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
  for (const entry of readdirSync(path.join(dir, "_locales")))
    if (entry !== locale)
      rmSync(path.join(dir, "_locales", entry), { recursive: true, force: true });
  return dir;
}

interface Hit {
  kind: "ellipsis" | "clipped" | "scrolled" | "cut";
  text: string;
  overBy: number;
}

/** Everything on screen whose text doesn't fit. */
async function measure(page: Page): Promise<Hit[]> {
  return page.evaluate(() => {
    const hits: { kind: "ellipsis" | "clipped" | "scrolled" | "cut"; text: string; overBy: number }[] = [];
    // A leaf whose box pokes out of the nearest ancestor that clips: the
    // ancestor hides part of it (the card cutting "Text löschen" in half).
    function clipper(el: HTMLElement) {
      for (let a = el.parentElement; a; a = a.parentElement)
        if (getComputedStyle(a).overflowX !== "visible") return a;
      return null;
    }
    const visible = (el: Element) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      if (!visible(el) || el.closest("textarea,pre,[contenteditable]")) continue;
      if (el.matches("textarea,pre,input,svg,svg *")) continue;
      const cs = getComputedStyle(el);
      const text = (el.innerText || "").trim().replace(/\s+/g, " ");
      const over = el.scrollWidth - el.clientWidth;
      // A container that has been scrolled sideways though it can't be
      // scrolled by the user: content wider than the box shoved it over.
      if (el.scrollLeft > 0 && cs.overflowX !== "auto" && cs.overflowX !== "scroll")
        hits.push({ kind: "scrolled", text: text.slice(0, 80), overBy: el.scrollLeft });
      if (text && el.children.length === 0) {
        const anc = clipper(el);
        if (anc) {
          const r = el.getBoundingClientRect();
          const a = anc.getBoundingClientRect();
          const cut = Math.max(r.right - a.right, a.left - r.left);
          if (cut > 1) hits.push({ kind: "cut", text, overBy: Math.round(cut) });
        }
      }
      if (!text || over <= 1) continue;
      if (cs.textOverflow === "ellipsis") {
        hits.push({ kind: "ellipsis", text, overBy: over });
      } else if (
        (cs.overflowX === "hidden" || cs.overflowX === "clip") &&
        el.children.length === 0
      ) {
        hits.push({ kind: "clipped", text, overBy: over });
      }
    }
    if (document.documentElement.scrollWidth > window.innerWidth)
      hits.push({
        kind: "scrolled",
        text: "<page>",
        overBy: document.documentElement.scrollWidth - window.innerWidth,
      });
    return hits;
  });
}

const report: Record<string, unknown>[] = [];

for (const locale of LOCALES) {
  const msgs = readMessages(locale);
  const t = (key: string) => {
    const m = msgs[key]?.message ?? readMessages("en")[key]?.message;
    if (m === undefined) throw new Error(`no message ${key}`);
    return m;
  };
  // Text -> keys, so a hit names the string to shorten. Placeholders are
  // dropped to their literal prefix so "63 Zeichen" still finds its key.
  const byText = new Map<string, string[]>();
  for (const [k, v] of Object.entries(msgs)) {
    const s = v.message.replace(/\s+/g, " ").trim();
    byText.set(s, [...(byText.get(s) ?? []), k]);
  }
  const keysFor = (text: string): string[] => {
    const exact = byText.get(text);
    if (exact) return exact;
    const out: string[] = [];
    for (const [k, v] of Object.entries(msgs)) {
      const fixed = v.message.split(/\$[A-Za-z_]+\$|\{[^}]*\}/)[0]?.trim();
      if (fixed && fixed.length >= 3 && text.includes(fixed)) out.push(k);
    }
    return out.slice(0, 4);
  };

  const test = base.extend<{ context: BrowserContext; panel: Page }>({
    // eslint-disable-next-line no-empty-pattern
    context: async ({}, use) => {
      const context = await launchExtensionContext(forcedLocaleBuild(locale));
      await use(context);
      await context.close();
    },
    panel: async ({ context }, use) => {
      const id = await getExtensionId(context);
      const page = await context.newPage();
      await page.setViewportSize({ width: 400, height: 760 });
      await page.goto(`chrome-extension://${id}/sidepanel.html`);
      await use(page);
    },
  });

  test(`i18n overflow ${locale}`, async ({ panel }) => {
    test.setTimeout(240_000);
    panel.setDefaultTimeout(10_000);

    const snap = async (screen: string) => {
      for (const width of WIDTHS) {
        await panel.setViewportSize({ width, height: 760 });
        await panel.waitForTimeout(250);
        const hits = await measure(panel);
        const dir = path.join(OUT, locale);
        mkdirSync(dir, { recursive: true });
        await panel.screenshot({ path: path.join(dir, `${screen}-${width}.png`) });
        for (const h of hits)
          report.push({ locale, screen, width, ...h, keys: keysFor(h.text) });
      }
      await panel.setViewportSize({ width: 400, height: 760 });
    };
    const step = async (name: string, fn: () => Promise<void>) => {
      try {
        await fn();
      } catch (e) {
        report.push({ locale, screen: name, error: (e as Error).message.split("\n")[0] });
      }
    };

    await snap("onboarding");
    await panel.getByRole("button", { name: t("app_onboarding_next") }).click();
    await panel.locator('input[name="protection"]').nth(1).check();
    await snap("onboarding-protection");
    await panel.getByLabel(t("keygen_protection_password"), { exact: true }).fill(PASSWORD);
    await panel.getByLabel(t("keygen_confirm_password")).fill(PASSWORD);
    await panel.getByRole("button", { name: t("app_onboarding_set_password") }).click();
    await panel.getByPlaceholder(t("app_onboarding_name_placeholder")).fill("James Arnott");
    await panel.getByPlaceholder(t("app_onboarding_email_placeholder")).fill("james@amibeingpwned.com");
    await snap("onboarding-key");
    await panel.getByRole("button", { name: t("app_onboarding_create_key") }).click();
    await panel.getByRole("button", { name: t("app_onboarding_keep_defaults") }).click({ timeout: 30_000 });
    await expect(panel.getByRole("tab", { name: t("common_keys") })).toBeVisible({ timeout: 30_000 });

    await step("main-empty", () => snap("main-empty"));

    await step("keys", async () => {
      await panel.getByRole("tab", { name: t("common_keys") }).click();
      await panel
        .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
        .setInputFiles({
          name: "key.asc",
          mimeType: "application/pgp-keys",
          buffer: Buffer.from(keyBySlug("standard").publicKey, "utf8"),
        });
      await snap("import-preview");
      await panel.getByRole("button", { name: t("import_action_import_contact") }).click();
      await panel.waitForTimeout(500);
      await snap("keys");
    });

    await step("generate", async () => {
      await panel.getByRole("button", { name: t("keys_generate_button") }).click();
      await panel.waitForTimeout(600);
      await snap("generate");
      await panel.keyboard.press("Escape");
    });

    await step("compose", async () => {
      await panel.getByRole("tab", { name: t("app_tab_main") }).click();
      await panel.getByRole("combobox", { name: t("workspace_recipients_label") }).click();
      await panel.getByRole("option", { name: /Alice Example/ }).first().click();
      await panel.keyboard.press("Escape");
      await panel.locator("textarea").first().fill("Meet me at the usual place at 8.");
      await panel.locator("body").click({ position: { x: 5, y: 5 } });
      await snap("compose");
    });

    for (const mode of ["common_decrypt", "common_sign", "common_verify"])
      await step(mode, async () => {
        await panel.getByRole("radio", { name: t(mode), exact: true }).click();
        await snap(mode.replace("common_", "mode-"));
      });

    await step("settings", async () => {
      await panel.getByRole("tab", { name: t("common_settings") }).click();
      await panel.waitForTimeout(500);
      await snap("settings");
    });
  });
}

base.afterAll(() => {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(path.join(OUT, "report.json"), JSON.stringify(report, null, 2));
});
