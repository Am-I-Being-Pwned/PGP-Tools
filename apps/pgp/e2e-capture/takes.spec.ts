/**
 * "Takes" of the REAL extension for the promo film: Playwright drives the
 * shipped side panel at human pace (real keystrokes, real clicks, the app's
 * own transitions) while every frame is recorded. Tooling, not a test; run by
 * hand after `pnpm build`:
 *
 *     npx playwright test --config=playwright.capture.config.ts takes
 *
 * Each take lands in assets/store-listing/video/ui/takes/<name>/ as the
 * distinct frames it showed (frame-NNNNN.png, 1200x1920), an index of when
 * each appeared (frames.json, seconds of film time from the take's start)
 * and the pointer's path (pointer.json, panel CSS px), so the film can draw a
 * cursor that matches the clicks.
 *
 * How it gets 60fps at 3x: a full-resolution screenshot takes ~1/30s, so a
 * take is performed in half-speed slow motion. The page's own animations are
 * slowed with DevTools' Animation.setPlaybackRate, every wait, keystroke and
 * pointer step is stretched to match, and timestamps are compressed back by
 * the same factor. (The DevTools screencast is real-time but records CSS
 * pixels only; CSS zoom to fake 3x breaks the panel's full-height layout.)
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContext, CDPSession, Locator, Page } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

import { getExtensionId, launchExtensionContext } from "../e2e/fixtures";
import { importContactsBulk } from "../e2e/helpers";
import { keyBySlug, TEST_KEYS } from "../e2e/keys";

const APP = path.resolve(import.meta.dirname, "..");
const EXT = path.join(APP, ".output", "chrome-mv3");
const OUT = path.resolve(APP, "..", "..", "assets", "store-listing", "video", "ui", "takes");
const PASSWORD = "correct horse battery staple";
const MESSAGE = "Meet me at the usual place at 8. Bring the drive.";
const ALICE = keyBySlug("standard");
// The side panel's page area in the Chrome-window capture is exactly 360x865
// CSS px (720x1730 at 2x), so takes are recorded at that size and drop into
// the real panel pixel for pixel.
const W = 360, H = 865, DPR = 3;
/** Slow-motion factor while recording: 0.5 = everything at half speed. */
const RATE = 0.5;

const test = base.extend<{ context: BrowserContext; panel: Page }>({
  // eslint-disable-next-line no-empty-pattern
  context: async ({}, use) => {
    const context = await launchExtensionContext(EXT, { deviceScaleFactor: DPR });
    await use(context);
    await context.close();
  },
  panel: async ({ context }, use) => {
    const id = await getExtensionId(context);
    const page = await context.newPage();
    await page.setViewportSize({ width: W, height: H });
    await page.goto(`chrome-extension://${id}/sidepanel.html`);
    await use(page);
  },
});

interface PointerEvent { t: number; x: number; y: number; down?: boolean }

/** Records one take: every distinct frame, plus where the pointer went. */
class Take {
  private frames: { t: number; data: string }[] = [];
  private pointer: PointerEvent[] = [];
  private t0 = 0;
  private cdp!: CDPSession;
  private running = false;
  private loop: Promise<void> = Promise.resolve();
  constructor(private page: Page, private name: string) {}

  /** Film time: wall time since start, compressed by the slow-motion rate. */
  private now() { return (Date.now() / 1000 - this.t0) * RATE; }

  /** Wait `ms` of film time. */
  pause(ms: number) { return this.page.waitForTimeout(ms / RATE); }
  /** Type at `delay` ms per key of film time. */
  type(text: string, delay: number) { return this.page.keyboard.type(text, { delay: delay / RATE }); }

  async start() {
    this.cdp = await this.page.context().newCDPSession(this.page);
    await this.cdp.send("Animation.enable");
    await this.cdp.send("Animation.setPlaybackRate", { playbackRate: RATE });
    this.t0 = Date.now() / 1000;
    this.running = true;
    this.loop = (async () => {
      let last = "";
      while (this.running) {
        const t = this.now();
        // A clip with `scale` is what makes DevTools paint at 3x; without it
        // the capture is CSS-pixel size whatever the device scale factor.
        const { data } = await this.cdp.send("Page.captureScreenshot", {
          format: "png",
          optimizeForSpeed: true,
          clip: { x: 0, y: 0, width: W, height: H, scale: DPR },
        });
        if (data !== last) this.frames.push({ t, data });
        last = data;
      }
    })();
    await this.pause(350);
  }

  /** Glide the pointer to the middle of `el` (logged), then click it. */
  async click(el: Locator, opts: { settle?: number } = {}) {
    const box = await el.boundingBox();
    if (!box) throw new Error(`take ${this.name}: nothing to click`);
    const x = box.x + box.width / 2, y = box.y + box.height / 2;
    await this.move(x, y);
    await this.pause(opts.settle ?? 120);
    this.pointer.push({ t: this.now(), x, y, down: true });
    await this.page.mouse.down();
    await this.pause(70);
    await this.page.mouse.up();
    this.pointer.push({ t: this.now(), x, y, down: false });
  }

  async move(x: number, y: number, steps = 16) {
    const from = this.pointer.at(-1) ?? { x: W * 0.8, y: H * 0.85 };
    for (let i = 1; i <= steps; i++) {
      const k = i / steps, e = 1 - (1 - k) ** 3;
      const px = from.x + (x - from.x) * e, py = from.y + (y - from.y) * e;
      await this.page.mouse.move(px, py);
      this.pointer.push({ t: this.now(), x: px, y: py });
      await this.pause(16);
    }
  }

  async stop() {
    await this.pause(400);
    this.running = false;
    await this.loop;
    const duration = this.now();
    await this.cdp.send("Animation.setPlaybackRate", { playbackRate: 1 });
    await this.cdp.detach();
    const dir = path.join(OUT, this.name);
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    const index = this.frames.map((f, i) => {
      const file = `frame-${String(i).padStart(5, "0")}.png`;
      writeFileSync(path.join(dir, file), Buffer.from(f.data, "base64"));
      return { t: +f.t.toFixed(4), file };
    });
    writeFileSync(path.join(dir, "frames.json"), JSON.stringify({ w: W, h: H, dpr: DPR, duration, frames: index }));
    writeFileSync(path.join(dir, "pointer.json"), JSON.stringify(this.pointer));
    console.log(`take ${this.name}: ${index.length} frames, ${duration.toFixed(2)}s`);
  }
}

test("takes", async ({ panel }) => {
  test.setTimeout(600_000);
  panel.setDefaultTimeout(20_000);

  // Set up as a person fit to be seen, with contacts to show.
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Set password" }).click();
  await panel.getByPlaceholder("Your full name").fill("James Arnott");
  await panel.getByPlaceholder("you@example.com").fill("james@amibeingpwned.com");
  await panel.getByRole("button", { name: "Create my PGP key" }).click();
  await panel.getByRole("button", { name: "Keep the defaults" }).click({ timeout: 30_000 });
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({ timeout: 30_000 });
  await importContactsBulk(panel, TEST_KEYS.filter((k) => k.encryptCapable).slice(0, 6).map((k) => k.publicKey));
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("radio", { name: "Encrypt", exact: true }).click();
  await panel.locator("body").click({ position: { x: 5, y: 5 } });
  await panel.waitForTimeout(600);

  // ── encrypt: pick Alice, write, sign, encrypt ─────────────────────────
  const enc = new Take(panel, "encrypt");
  await enc.start();
  await enc.click(panel.getByRole("combobox", { name: /Recipients/ }));
  await enc.type("al", 110);
  await enc.pause(350);
  await enc.click(panel.getByRole("option", { name: new RegExp(ALICE.name) }).first());
  await panel.keyboard.press("Escape");
  await enc.pause(250);
  await enc.click(panel.locator("#pgp-input"));
  await enc.type(MESSAGE, 34);
  await enc.pause(400);
  await enc.click(panel.getByRole("switch", { name: "Sign", exact: true }));
  await enc.pause(600);
  await enc.click(panel.getByRole("button", { name: /^Encrypt/ }).last());
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  await enc.pause(900);
  await enc.stop();
  // Keep the real ciphertext for the decrypt take and the film's armor beat.
  const download = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const armored = readFileSync(await (await download).path(), "utf8");
  writeFileSync(path.join(OUT, "armored.asc"), armored);

  // ── decrypt: paste it in, get message + verified signer together ─────
  await panel.keyboard.press("Escape");
  await panel.keyboard.press("Escape");
  await panel.getByRole("radio", { name: "Decrypt", exact: true }).click();
  await panel.waitForTimeout(500);
  const dec = new Take(panel, "decrypt");
  await dec.start();
  await dec.click(panel.locator("#pgp-input"));
  await panel.keyboard.insertText(armored);
  await dec.pause(700);
  await dec.click(panel.getByRole("button", { name: /^Decrypt/ }).last());
  await expect(panel.getByText(MESSAGE).first()).toBeVisible();
  await dec.pause(1500);
  await dec.stop();

  // ── tampered: Alice's signed message with one word changed fails ─────
  await panel.keyboard.press("Escape");
  await panel.getByRole("radio", { name: "Verify", exact: true }).click();
  // The input carries the previous text across modes; start clean.
  await panel.locator("#pgp-input").fill("");
  await panel.locator("body").click({ position: { x: 5, y: 5 } });
  await panel.waitForTimeout(500);
  const tampered = ALICE.signedMessage.replace("quick brown fox", "quick brown cat");
  const bad = new Take(panel, "tampered");
  await bad.start();
  await bad.click(panel.locator("#pgp-input"));
  await panel.keyboard.insertText(tampered);
  await bad.pause(700);
  await bad.click(panel.getByRole("button", { name: /^Verify/ }).last());
  await expect(panel.getByText(/tampered/i).first()).toBeVisible();
  await bad.pause(1600);
  await bad.stop();

  // ── keys: the contact list, then Alice's key ──────────────────────────
  await panel.keyboard.press("Escape");
  const keys = new Take(panel, "keys");
  await keys.start();
  await keys.click(panel.getByRole("tab", { name: "Keys" }));
  await keys.pause(900);
  await keys.move(W / 2, H * 0.6);
  for (let i = 0; i < 10; i++) { await panel.mouse.wheel(0, 18); await keys.pause(30); }
  await keys.pause(500);
  await keys.click(panel.getByText(ALICE.name, { exact: true }).filter({ visible: true }).first());
  await keys.pause(1800);
  await keys.stop();
});
