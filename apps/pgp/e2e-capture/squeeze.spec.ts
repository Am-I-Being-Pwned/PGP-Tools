/**
 * The repo page being squeezed as the side panel opens, for the promo film.
 * Tooling, not a test; run by hand:
 *
 *     npx playwright test --config=playwright.capture.config.ts squeeze
 *
 * When Chrome opens a side panel the page loses that width and reflows. This
 * records the REAL reflow: the same GitHub page (dark, 2x) laid out at every
 * width between the full window (1600 CSS px) and what is left beside the open
 * panel (1222), at the window's page height (913). The film plays these in
 * step with the panel sliding in. Widths are measured off the Chrome-window
 * captures (chrome-window.spec.ts).
 *
 * Output: assets/store-listing/video/ui/takes/squeeze/ in the takes format,
 * where a frame's `t` is the slide's progress (0 closed, 1 open).
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { chromium, test } from "@playwright/test";

const OUT = path.resolve(import.meta.dirname, "..", "..", "..", "assets", "store-listing", "video", "ui", "takes", "squeeze");
const PAGE = "https://github.com/Am-I-Being-Pwned/PGP-Tools";
const FULL = 1600, OPEN = 1222, H = 913, STEPS = 40;

test("squeeze", async () => {
  test.setTimeout(240_000);
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  // Playwright hides scrollbars in headless runs; the real window has one,
  // and its gutter changes the page's layout width, so keep it.
  const browser = await chromium.launch({ ignoreDefaultArgs: ["--hide-scrollbars"] });
  const page = await browser.newPage({ viewport: { width: FULL, height: H }, deviceScaleFactor: 2, colorScheme: "dark" });
  // networkidle can time out on a busy page; the settle below covers it.
  await page.goto(PAGE, { waitUntil: "networkidle" }).catch(() => undefined);
  await page.waitForTimeout(1500);
  const frames: { t: number; file: string; width: number }[] = [];
  for (let i = 0; i < STEPS; i++) {
    const p = i / (STEPS - 1);
    const width = Math.round(FULL + (OPEN - FULL) * p);
    await page.setViewportSize({ width, height: H });
    // Let the page reflow and repaint at the new width.
    await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    await page.waitForTimeout(120);
    const file = `frame-${String(i).padStart(5, "0")}.png`;
    await page.screenshot({ path: path.join(OUT, file), scale: "device" });
    frames.push({ t: +p.toFixed(4), file, width });
  }
  writeFileSync(path.join(OUT, "frames.json"), JSON.stringify({ w: FULL, h: H, dpr: 2, duration: 1, frames }));
  writeFileSync(path.join(OUT, "pointer.json"), "[]");
  await browser.close();
});
