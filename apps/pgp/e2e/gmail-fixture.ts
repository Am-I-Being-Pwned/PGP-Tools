import { cpSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContext, Frame, Locator, Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Test plumbing for the Gmail add-on (SECURITY.md §17).
 *
 * TWO STAND-INS, both stated so nobody mistakes them for the real thing:
 *
 * 1. THE GRANT. The add-on's host access is an OPTIONAL permission, and
 *    Chrome's prompt for it is browser UI Playwright cannot click (and
 *    headless Chrome never answers). So these specs run a copy of the
 *    built extension whose manifest moves the one optional host pattern
 *    into `host_permissions` -- granted at load, exactly the state after a
 *    user says yes. Everything downstream (the worker registering the
 *    script, injection, messaging, the panel) is the shipped code.
 *
 * 2. GMAIL. `e2e/fixtures/gmail.html` is served at https://mail.google.com
 *    by Playwright's router, so the content script injects by URL just as
 *    it would into the real site.
 */

const BUILD = path.resolve(import.meta.dirname, "..", ".output", "chrome-mv3");
const GRANTED = path.resolve(
  import.meta.dirname,
  "..",
  ".output",
  "chrome-mv3-gmail-granted",
);

/** A copy of the build with Gmail access granted at install. */
export function gmailGrantedBuild(): string {
  cpSync(BUILD, GRANTED, { recursive: true });
  const manifestPath = path.join(GRANTED, "manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    optional_host_permissions?: string[];
    host_permissions?: string[];
  };
  manifest.host_permissions = manifest.optional_host_permissions ?? [];
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return GRANTED;
}

export const GMAIL_URL = "https://mail.google.com/mail/u/0/#inbox/msg-a";

const escape = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Text as Gmail renders a plain-text email: one `<div>` per line. */
function asGmailLines(text: string): string {
  return text
    .trim()
    .split("\n")
    .map((l) => (l === "" ? "<div><br></div>" : `<div>${escape(l)}</div>`))
    .join("");
}

export interface FakeGmailOptions {
  /** Armored text shown in the first message. */
  armored: string;
  /** Attachments on the first message: Gmail-style chips whose
   *  `download_url` the stand-in serves `body` for. */
  attachments?: { name: string; body: string | Buffer }[];
  /** Addresses on the compose window's To line. */
  recipients?: string[];
  /** What the user already typed into Gmail's compose box. */
  draft?: string;
  theme?: "light" | "dark";
}

/** Route mail.google.com to the fixture and open it in a new tab. */
export async function openFakeGmail(
  context: BrowserContext,
  opts: FakeGmailOptions,
): Promise<Page> {
  const template = readFileSync(
    path.join(import.meta.dirname, "fixtures", "gmail.html"),
    "utf8",
  );
  const clipped = opts.armored.trim().split("\n").slice(0, 4).join("\n");
  const attachments = opts.attachments ?? [];
  const attachmentUrl = (i: number) =>
    `https://mail.google.com/mail/u/0/?ui=2&ik=e2e&view=att&th=msg-a&attid=0.${i + 1}&disp=safe`;
  const html = template
    .replace(
      "{{ATTACHMENTS}}",
      attachments
        .map(
          (a, i) =>
            `<span class="aZo N5jrZb" download_url="application/octet-stream:${escape(a.name)}:${attachmentUrl(i)}"><span class="aV3">${escape(a.name)}</span></span>`,
        )
        .join(""),
    )
    .replace("{{THEME}}", opts.theme ?? "light")
    .replace("{{ARMOR_LINES}}", asGmailLines(opts.armored))
    .replace("{{CLIPPED_LINES}}", asGmailLines(clipped))
    .replace(
      "{{RECIPIENTS}}",
      (opts.recipients ?? [])
        .map((r) => `<span class="vR" email="${escape(r)}">${escape(r)}</span>`)
        .join(""),
    )
    .replace("{{DRAFT_LINES}}", asGmailLines(opts.draft ?? ""));

  await context.route("https://mail.google.com/**", (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: html }),
  );
  // Attachment downloads, matched after (so ahead of) the page route.
  for (const [i, a] of attachments.entries()) {
    await context.route(attachmentUrl(i), (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        body: typeof a.body === "string" ? Buffer.from(a.body, "utf8") : a.body,
      }),
    );
  }
  const page = await context.newPage();
  await page.goto(GMAIL_URL);
  return page;
}

/**
 * Click inside one of the add-on's hosts. They are CLOSED shadow roots on
 * purpose (Gmail's scripts must not reach in), which also means no
 * Playwright locator can; a real mouse click at a point inside the host
 * is what a user does and arrives with `isTrusted`, which the add-on
 * requires. `at` picks where: the banner's button sits at its right edge.
 */
export async function clickInHost(
  page: Page,
  host: Locator,
  at: "center" | "right",
): Promise<void> {
  const box = await host.boundingBox();
  if (!box) throw new Error("add-on host has no box");
  const x = at === "center" ? box.x + box.width / 2 : box.x + box.width - 60;
  await page.mouse.click(x, box.y + box.height / 2);
}

/** The id of the Gmail tab, as the panel would address it. */
export async function gmailTabId(panel: Page): Promise<number> {
  const [tab] = await panel.evaluate(() =>
    chrome.tabs.query({ url: "https://mail.google.com/*" }),
  );
  if (tab.id === undefined) throw new Error("no Gmail tab");
  return tab.id;
}

/**
 * The add-on's inline reader frame in a Gmail page. Its host is a closed
 * shadow root, which no locator can enter -- but the frame tree is not
 * the DOM: Playwright lists every frame regardless, and the frame's own
 * document is ordinary.
 */
export async function readerFrame(
  gmail: Page,
  extensionId: string,
): Promise<Frame> {
  const prefix = `chrome-extension://${extensionId}/gmail-frame.html`;
  const find = () => gmail.frames().find((f) => f.url().startsWith(prefix));
  await expect.poll(() => find() !== undefined, { timeout: 10_000 }).toBe(true);
  const frame = find();
  if (!frame) throw new Error("no reader frame");
  return frame;
}
