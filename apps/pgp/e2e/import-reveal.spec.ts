import { expect, test } from "./fixtures";
import { generateSshKeys, goToKeys, seedVault } from "./helpers";
import { TEST_KEYS } from "./keys";

test.use({ trace: "off" });

const MASTER = "correct horse battery staple";
/** Longer than the highlight's own 2600ms lifetime, so the seed import's
 *  highlight is gone and the only card under test is the new one. */
const HIGHLIGHT_LIFETIME_MS = 3200;

/** Where the just-imported card sits relative to what scrolls it. */
async function revealed(panel: import("@playwright/test").Page) {
  return panel.evaluate(() => {
    const main = document.querySelector("main");
    const card = document.querySelector(".just-imported");
    if (!main || !card) return { found: false, visible: false };
    const c = card.getBoundingClientRect();
    const m = main.getBoundingClientRect();
    return {
      found: true,
      visible: c.top >= m.top && c.bottom <= m.bottom,
      cardTop: Math.round(c.top),
      cardBottom: Math.round(c.bottom),
      portTop: Math.round(m.top),
      portBottom: Math.round(m.bottom),
    };
  });
}

/** Seed a list long enough that a new contact lands below the fold, then
 *  import three same-comment SSH keys -- which group into ONE contact,
 *  the shape a self-hosting correspondent's keys arrive in. */
async function importGroupedContact(panel: import("@playwright/test").Page) {
  const ssh = generateSshKeys(3, () => "otto@laptop");
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "keys.pub",
      mimeType: "text/plain",
      buffer: Buffer.from(
        ssh.map((k) => k.publicLineWithComment).join("\n"),
        "utf8",
      ),
    });
  const region = panel.getByRole("region", { name: "Import key" });
  await expect(region).toBeVisible();
  await region.getByRole("button", { name: /^Import/ }).click();
  await expect(region).toBeHidden();
}

test.describe("a just-imported card is revealed, not just highlighted", () => {
  test.beforeEach(async ({ panel }) => {
    // Short enough that the list overflows and the new card is off screen:
    // an import that needs no scroll cannot show whether scrolling works.
    await panel.setViewportSize({ width: 400, height: 500 });
    await seedVault(
      panel,
      MASTER,
      TEST_KEYS.slice(0, 5).map((k) => k.publicKey),
    );
    await goToKeys(panel);
    await panel.waitForTimeout(HIGHLIGHT_LIFETIME_MS);
  });

  test("scrolls to the new card", async ({ panel }) => {
    await importGroupedContact(panel);
    await expect.poll(() => revealed(panel)).toMatchObject({ visible: true });
  });

  test("still reveals it when something else scrolls mid-animation", async ({
    panel,
  }) => {
    // The real failure this guards: the scroll is SMOOTH, so it is
    // cancellable, and an import fires competing scrolls -- the panel's
    // focus restore as it closes, the list reflowing around the new
    // card. Losing that race leaves the card highlighted but off screen.
    // Standing in for those here is a scroll to the top the moment the
    // card appears, which aborts the animation the same way.
    await panel.evaluate(() => {
      const main = document.querySelector("main");
      if (!main) throw new Error("no scrollport");
      const observer = new MutationObserver(() => {
        if (!document.querySelector(".just-imported")) return;
        observer.disconnect();
        setTimeout(() => (main.scrollTop = 0), 60);
      });
      observer.observe(document.body, { childList: true, subtree: true });
    });

    await importGroupedContact(panel);
    await expect.poll(() => revealed(panel)).toMatchObject({ visible: true });
  });
});
