/**
 * A real, full-window capture of Chrome with PGP Tools open in the side
 * panel, for the promo video's opening shot. Tooling, not a test: run it by
 * hand, headed, on a Mac (it uses `screencapture`, which needs the terminal
 * to have Screen Recording permission):
 *
 *     npx playwright test --config=playwright.capture.config.ts chrome-window
 *
 * Playwright cannot screenshot the browser's own UI (tabs, toolbar, the
 * side panel's frame), so this drives a real headed window and grabs it
 * from the OS. Branded Chrome no longer honours --load-extension, so the
 * window is Playwright's Chromium build.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { chromium, expect, test } from "@playwright/test";

import { getExtensionId } from "../e2e/fixtures";
import { importContact } from "../e2e/helpers";
import { keyBySlug } from "../e2e/keys";

const APP = path.resolve(import.meta.dirname, "..", "..");
const EXT = path.join(APP, ".output", "chrome-mv3");
const OUT = path.resolve(
  APP,
  "..",
  "..",
  "assets",
  "store-listing",
  "video",
  "ui",
);
const PASSWORD = "correct horse battery staple";
const PAGE = "https://github.com/Am-I-Being-Pwned/PGP-Tools";
const CDP_PORT = 9334;
const W = 1600;
const H = 1000;

/**
 * The CGWindowID of the test browser's window: owner must be EXACTLY the
 * Playwright build (never the user's own Google Chrome) and the title must
 * contain `title`. Throws rather than falling back to any other window, so
 * this can never capture someone's real browser.
 */
function testWindowId(title: string): number {
  const swift = `
import CoreGraphics
let owners: Set<String> = ["Google Chrome for Testing", "Chromium"]
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
var best = 0; var area = 0.0
for w in list {
  let owner = (w[kCGWindowOwnerName as String] as? String) ?? ""
  let name = (w[kCGWindowName as String] as? String) ?? ""
  guard owners.contains(owner), name.contains("${title}") else { continue }
  let b = w[kCGWindowBounds as String] as! [String: Double]
  let a = (b["Width"] ?? 0) * (b["Height"] ?? 0)
  if a > area { area = a; best = w[kCGWindowNumber as String] as! Int }
}
print(best)`;
  const id = Number(
    execFileSync("swift", ["-e", swift], { encoding: "utf8" }).trim(),
  );
  if (!id)
    throw new Error(`no test-browser window titled "${title}" on screen`);
  return id;
}

/**
 * A raw DevTools connection to the side panel. Playwright does not expose
 * side-panel targets as pages, so the panel is driven over CDP directly:
 * find the sidepanel.html target and evaluate in it.
 */
async function panelSession(): Promise<{
  run: (expr: string) => Promise<unknown>;
  close: () => void;
}> {
  let target: { url: string; webSocketDebuggerUrl: string } | undefined;
  for (let i = 0; i < 40 && !target; i++) {
    const list = (await (
      await fetch(`http://127.0.0.1:${CDP_PORT}/json`)
    ).json()) as { url: string; webSocketDebuggerUrl: string }[];
    target = list.find((t) => t.url.includes("sidepanel.html"));
    if (!target) await new Promise((r) => setTimeout(r, 250));
  }
  if (!target) throw new Error("side panel target not found");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r, { once: true }));
  let next = 1;
  const pending = new Map<number, (v: unknown) => void>();
  ws.addEventListener("message", (e) => {
    const msg = JSON.parse(String(e.data)) as {
      id?: number;
      result?: { result?: { value?: unknown }; exceptionDetails?: unknown };
    };
    const resolve = msg.id ? pending.get(msg.id) : undefined;
    if (msg.id && resolve) {
      if (msg.result?.exceptionDetails)
        console.log(
          "panel eval error:",
          JSON.stringify(msg.result.exceptionDetails).slice(0, 300),
        );
      resolve(msg.result?.result?.value);
      pending.delete(msg.id);
    }
  });
  const run = (expression: string) =>
    new Promise<unknown>((resolve) => {
      const id = next++;
      pending.set(id, resolve);
      ws.send(
        JSON.stringify({
          id,
          method: "Runtime.evaluate",
          params: {
            expression,
            awaitPromise: true,
            returnByValue: true,
            userGesture: true,
          },
        }),
      );
    });
  return { run, close: () => ws.close() };
}

/** In-panel helpers, evaluated in the panel's page. */
const PANEL_LIB = `
  window.__sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  window.__until = async (fn, ms = 10000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const v = fn(); if (v) return v; await __sleep(100); } throw new Error("timeout"); };
  window.__byText = (sel, text) => [...document.querySelectorAll(sel)].find((e) => e.textContent.trim() === text || e.getAttribute("aria-label") === text);
  window.__fill = (el, value) => { const set = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value").set; set.call(el, value); el.dispatchEvent(new Event("input", { bubbles: true })); };
`;

test("chrome window with the side panel open", async () => {
  test.setTimeout(240_000);
  mkdirSync(OUT, { recursive: true });
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    viewport: null,
    // Dark pages: a white page blooms into glare on a dark stage.
    colorScheme: "dark",
    deviceScaleFactor: undefined,
    args: [
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      `--window-size=${W},${H}`,
      "--window-position=40,40",
      "--hide-crash-restore-bubble",
      "--no-default-browser-check",
      "--disable-features=Translate",
      `--remote-debugging-port=${CDP_PORT}`,
    ],
    ignoreDefaultArgs: ["--enable-automation"],
  });
  const id = await getExtensionId(context);

  // 1. Set the vault up in a tab: a person fit to be seen, Alice as a contact.
  const setup = context.pages()[0] ?? (await context.newPage());
  await setup.goto(`chrome-extension://${id}/sidepanel.html`);
  await setup.getByRole("button", { name: "Next" }).click();
  await setup.locator('input[name="protection"]').nth(1).check();
  await setup.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await setup.getByLabel("Confirm password").fill(PASSWORD);
  await setup.getByRole("button", { name: "Set password" }).click();
  await setup.getByPlaceholder("Your full name").fill("James Arnott");
  await setup
    .getByPlaceholder("you@example.com")
    .fill("james@amibeingpwned.com");
  await setup.getByRole("button", { name: "Create my PGP key" }).click();
  await setup
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 30_000 });
  await expect(setup.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
  await importContact(setup, keyBySlug("standard").publicKey);

  // 2. Open the real side panel. sidePanel.open() needs a user gesture, so
  //    a trusted Playwright click on a button in an extension page calls it.
  const windowIdChrome = await setup.evaluate(
    async () => (await chrome.windows.getCurrent()).id,
  );
  await setup.evaluate((wid) => {
    const b = document.createElement("button");
    b.id = "open-panel";
    b.textContent = "open";
    Object.assign(b.style, {
      position: "fixed",
      left: "0",
      top: "0",
      zIndex: "99999",
    });
    if (wid === undefined) throw new Error("no current window");
    b.onclick = () => void chrome.sidePanel.open({ windowId: wid });
    document.body.appendChild(b);
  }, windowIdChrome);
  await setup.click("#open-panel");
  await setup.waitForTimeout(1500);

  // 3. The tab becomes an ordinary page; the panel stays open beside it.
  // networkidle can time out on a busy page; the waits below cover it.
  await setup.goto(PAGE, { waitUntil: "networkidle" }).catch(() => undefined);
  await setup.waitForTimeout(1500);

  // 4. Drive the real panel: unlock, show the empty Encrypt composer.
  const panel = await panelSession();
  await panel.run(PANEL_LIB);
  await panel
    .run(
      `(async () => {
    const pw = await __until(() => document.querySelector('input[type="password"]'));
    __fill(pw, ${JSON.stringify(PASSWORD)});
    __byText("button", "Unlock").click();
    await __until(() => __byText('[role="tab"]', "Main"), 20000);
    __byText('[role="tab"]', "Main").click();
    await __sleep(300);
    __byText('[role="radio"]', "Encrypt")?.click();
    await __sleep(300);
    // Left empty on purpose: the film's encrypt take starts from exactly
    // this state, so the panel can play it without a cut.
    await __sleep(300);
    document.activeElement?.blur();
    return "ok";
  })()`,
    )
    .then((v) => console.log("panel:", v));
  await setup.waitForTimeout(800);
  panel.close();

  // 5. Close the install-time welcome tab so the tab strip is just the page,
  //    then grab the whole window from the OS.
  for (const p of context.pages()) if (p !== setup) await p.close();
  await setup.bringToFront();
  await setup.mouse.move(W / 2, H - 200);
  await setup.waitForTimeout(800);
  const wid = testWindowId("Am-I-Being-Pwned");
  execFileSync("screencapture", [
    "-x",
    "-o",
    `-l${wid}`,
    path.join(OUT, "chrome-window.png"),
  ]);

  // 6. The same window with the panel closed (window.close() in a side
  //    panel closes the panel), so the video can show it opening.
  const again = await panelSession();
  void again.run("window.close()");
  await setup.waitForTimeout(1200);
  again.close();
  execFileSync("screencapture", [
    "-x",
    "-o",
    `-l${testWindowId("Am-I-Being-Pwned")}`,
    path.join(OUT, "chrome-window-closed.png"),
  ]);
  await context.close();
});
