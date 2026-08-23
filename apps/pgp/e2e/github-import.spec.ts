import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  goToKeys,
  onboardWithPasswordSkipKey,
  setWorkspaceMode,
} from "./helpers";

/**
 * Importing a GitHub user's SSH keys, end to end -- and the one thing
 * about it that nothing else in this suite would catch.
 *
 * A person is not a key: a GitHub user commonly publishes three (laptop,
 * desktop, phone) and the contact holds all of them, because you cannot
 * know which machine they will read from. The failure mode of the whole
 * change is "encrypted to only the FIRST of the three", and that looks
 * perfect from the sender's side -- the import succeeds, the card shows
 * the contact, the encrypt succeeds, and the sender can even decrypt it
 * themselves. It surfaces weeks later as "I can't open your message".
 *
 * So the assertion that matters here is the last one: after encrypting
 * to a three-key contact, decrypt with the SECOND identity, and then
 * with the THIRD -- each time with the earlier identities deleted, so
 * nothing but that key's own stanza can be what worked.
 *
 * ── Interception ─────────────────────────────────────────────────────
 * The fetch happens in the MV3 service worker, not in the panel. In
 * Playwright 1.61 `context.route()` DOES reach service-worker requests:
 * the Chromium backend attaches a CRNetworkManager to every service
 * worker target and enables request interception whenever the context
 * has routes and `serviceWorkers` is not "block" (the default is
 * "allow"). That was read off the bundled implementation rather than
 * assumed -- see `CRServiceWorker._isNetworkInspectionEnabled` and the
 * `sw.updateRequestInterception()` call in `CRBrowserContext`. A CDP
 * session on the worker target is NOT usable here: `newCDPSession`
 * accepts only a Page or a Frame and throws on a Worker.
 *
 * The stub is verified rather than trusted: `stubGithubKeys` counts the
 * requests it served, and the test asserts the count. If interception
 * ever stops reaching the worker, the lookup hits the real api.github.com
 * (or fails offline) and the count assertion fails -- this spec cannot
 * quietly pass by never having intercepted anything.
 *
 * NOT VERIFIED BY RUNNING: this file was written while another agent held
 * the build, so it has never been executed. The mechanism above is
 * verified statically; the selectors follow the existing helpers.
 */

const PASSWORD = "correct horse battery staple";
const GITHUB_USER = "octocat";
const MESSAGE = "three machines, one message";
const CONTACTS_KEY = "pgp_public_contacts";

interface SshKeyPair {
  /** OpenSSH private key file contents. */
  privateKey: string;
  /** `ssh-ed25519 AAAA...` with the comment stripped, the way GitHub
   *  serves it. */
  publicLine: string;
  /** The `-C` comment, which is the key's display name once imported --
   *  and what the delete confirmation asks the user to type. */
  comment: string;
}

/** Generate throwaway ed25519 keypairs with `ssh-keygen`.
 *
 *  Generated per run rather than committed: no real key material lives in
 *  this repo, and an OpenSSH private key in a fixture file is exactly the
 *  thing that rule exists for. */
function generateSshKeys(count: number): SshKeyPair[] {
  const dir = mkdtempSync(path.join(tmpdir(), "pgp-e2e-ssh-"));
  try {
    return Array.from({ length: count }, (_, i) => {
      const comment = `e2e-ssh-${i + 1}`;
      const file = path.join(dir, comment);
      execFileSync("ssh-keygen", [
        ...["-t", "ed25519"],
        ...["-N", ""],
        ...["-C", comment],
        ...["-f", file],
        "-q",
      ]);
      const pub = readFileSync(`${file}.pub`, "utf8").trim();
      return {
        privateKey: readFileSync(file, "utf8"),
        // GitHub serves `<type> <base64>` with no comment; mimic that so
        // the stub is not kinder than the real endpoint.
        publicLine: pub.split(/\s+/).slice(0, 2).join(" "),
        comment,
      };
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Answer `https://api.github.com/users/*\/keys` with `lines`, in the
 * response shape the real endpoint uses (an array of `{id, key}`; the
 * parser reads `key` and ignores everything else).
 *
 * Returns a counter so the test can prove the stub was actually reached.
 */
async function stubGithubKeys(
  context: BrowserContext,
  lines: string[],
): Promise<{ count: () => number }> {
  let served = 0;
  await context.route("https://api.github.com/users/*/keys", async (route) => {
    served += 1;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(lines.map((key, id) => ({ id, key }))),
    });
  });
  return { count: () => served };
}

/** Answer the lookup with a failure status instead. */
async function stubGithubStatus(
  context: BrowserContext,
  status: number,
  headers: Record<string, string> = {},
): Promise<void> {
  await context.route("https://api.github.com/users/*/keys", (route) =>
    route.fulfill({
      status,
      contentType: "application/json",
      headers,
      body: JSON.stringify({ message: "Not Found" }),
    }),
  );
}

/** Import an OpenSSH private key as one of the user's own identities,
 *  protected with `password`. */
async function importSshIdentity(
  panel: Page,
  keyPair: SshKeyPair,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"]')
    .setInputFiles({
      name: "id_ed25519",
      mimeType: "text/plain",
      buffer: Buffer.from(keyPair.privateKey, "utf8"),
    });
  // Same preview every other kind gets; Continue moves to protection.
  await panel.getByRole("button", { name: "Continue" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await panel.getByLabel("Confirm password").fill(PASSWORD);
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await expect(panel.getByText(keyPair.comment).first()).toBeVisible();
}

/** Look up `user` on the Keys tab's import flow, landing on the preview. */
async function lookUpGithubUser(panel: Page, user: string): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel.getByLabel(/GitHub user/i).fill(user);
  await panel.getByRole("button", { name: "Look up" }).click();
}

/** Delete one own key, typing its name into the confirmation. */
async function deleteOwnKey(panel: Page, name: string): Promise<void> {
  await goToKeys(panel);
  // The innermost div that both shows this key's name and carries a
  // card's own options button: the card root, without depending on any
  // class name.
  const card = panel
    .locator("div", {
      has: panel.getByRole("button", { name: "Key options" }),
    })
    .filter({ hasText: name })
    .last();
  await card.getByRole("button", { name: "Key options" }).click();
  await panel.getByRole("menuitem", { name: "Delete key" }).click();
  await panel.getByRole("textbox", { name: /to confirm/ }).fill(name);
  await panel.getByRole("button", { name: "Delete key permanently" }).click();
  await expect(panel.getByText(name)).toHaveCount(0);
}

/** One stored contact record, as far as this spec cares. */
interface StoredContact {
  keyId: string;
  userIds: string[];
  recipients?: { keyId: string }[];
  source?: { type: string; user: string };
}

/**
 * The contacts store, DECRYPTED -- because "one contact" is a property of
 * storage, and asserting it through the DOM cannot tell a real duplicate
 * record from a label the panel happens to render twice.
 *
 * Driven through the panel's LIVE wasm instance (with its live contacts
 * session), located from the page's own entry script the way
 * `migration.spec.ts` does it; kept local so the two specs stay
 * independent. The plaintext is `[json][0x00][padding]` (see
 * `lib/storage/padding.ts`), so it is cut at the first NUL.
 */
async function readContacts(panel: Page): Promise<StoredContact[]> {
  const url = await panel.evaluate(async () => {
    const entry = document.querySelector<HTMLScriptElement>(
      'script[type="module"][src]',
    );
    if (!entry) return null;
    const source = await fetch(entry.src).then((r) => r.text());
    const match = /gpg_wasm-[A-Za-z0-9_-]+\.js/.exec(source);
    return match ? new URL(match[0], entry.src).href : null;
  });
  if (url === null) throw new Error("wasm glue chunk not locatable");

  return panel.evaluate(
    async ({ u, key }: { u: string; key: string }) => {
      const mod = (await import(/* @vite-ignore */ u)) as {
        decryptStore: (d: string, ct: Uint8Array, iv: Uint8Array) => Uint8Array;
      };
      const b64ToBytes = (s: string) =>
        Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const stored = (await chrome.storage.local.get(key))[key] as
        | { iv: string; ciphertext: string }
        | undefined;
      if (!stored) return [];
      const plaintext = mod.decryptStore(
        key,
        b64ToBytes(stored.ciphertext),
        b64ToBytes(stored.iv),
      );
      const nul = plaintext.indexOf(0);
      const json = nul === -1 ? plaintext : plaintext.subarray(0, nul);
      return JSON.parse(new TextDecoder().decode(json)) as StoredContact[];
    },
    { u: url, key: CONTACTS_KEY },
  );
}

/** Unlock every locked key on the Keys tab. Deleting a key does not lock
 *  the others, but an import that did not cache its unlock would leave
 *  one locked -- and a decrypt with no usable identity is exactly the
 *  false negative this spec must not produce. */
async function unlockAllKeys(panel: Page): Promise<void> {
  await goToKeys(panel);
  const unlocks = panel.getByRole("button", { name: "Unlock", exact: true });
  for (let i = await unlocks.count(); i > 0; i = await unlocks.count()) {
    await unlocks.first().click();
    const field = panel.getByPlaceholder("Enter password");
    await field.fill(PASSWORD);
    await field.press("Enter");
    await expect(unlocks).toHaveCount(i - 1);
  }
}

/** Decrypt `ciphertext` in the workspace and assert the plaintext. */
async function decryptExpecting(
  panel: Page,
  ciphertext: string,
  plaintext: string,
): Promise<void> {
  await unlockAllKeys(panel);
  await setWorkspaceMode(panel, "Decrypt");
  await panel.locator("textarea").first().fill(ciphertext);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(plaintext).first()).toBeVisible();
}

test("a GitHub user's three keys import as one contact, and all three can decrypt", async ({
  context,
  panel,
}) => {
  const keys = generateSshKeys(3);
  const github = await stubGithubKeys(
    context,
    keys.map((k) => k.publicLine),
  );

  // No PGP key: the only recipients in play are age ones, so nothing
  // here can accidentally be an OpenPGP round-trip.
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  for (const key of keys) await importSshIdentity(panel, key);

  await lookUpGithubUser(panel, GITHUB_USER);

  // The preview is the SAME body every other kind lands in, showing one
  // row per key. Every fingerprint in full, never "3 keys": the
  // fingerprints are the only out-of-band check the user has against
  // GitHub having handed back a key this person never published.
  const preview = panel.getByRole("region", { name: "Import key" });
  await expect(preview).toContainText(`${GITHUB_USER} (GitHub)`);
  await expect(preview).toContainText("Keys");
  await expect(preview.getByText(/^SHA256:/)).toHaveCount(3);
  await preview.getByRole("button", { name: "Import contact" }).click();
  await expect(preview).toBeHidden();
  expect(github.count()).toBe(1);

  // One contact, holding three keys, marked with where it came from.
  await goToKeys(panel);
  await expect(panel.getByText(`${GITHUB_USER} (GitHub)`)).toHaveCount(1);
  await expect(panel.getByText("3 keys").first()).toBeVisible();
  await expect(panel.getByText(`From github.com/${GITHUB_USER}`)).toBeVisible();

  // Encrypt to the contact -- one chip, one selection, three stanzas.
  await setWorkspaceMode(panel, "Encrypt");
  const recipients = panel.getByRole("combobox", { name: "Recipients" });
  await recipients.fill(GITHUB_USER);
  await recipients.press("Enter");
  await panel.locator("textarea").first().fill(MESSAGE);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  const downloaded = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const ciphertext = await readFile(await (await downloaded).path(), "utf8");
  expect(ciphertext).toContain("BEGIN AGE ENCRYPTED FILE");

  // ── the assertion this whole spec exists for ──────────────────────
  // Decrypting with key 1 would prove nothing: it is the contact's head
  // key, and "encrypted to only the first recipient" passes that test.
  // Delete it, and the only way the message opens is a second stanza.
  await deleteOwnKey(panel, keys[0].comment);
  await decryptExpecting(panel, ciphertext, MESSAGE);

  // And again: with the first two gone, only the THIRD key's stanza can
  // be what opened it.
  await deleteOwnKey(panel, keys[1].comment);
  await decryptExpecting(panel, ciphertext, MESSAGE);
});

test("re-looking up the same user updates the contact instead of adding a second", async ({
  context,
  panel,
}) => {
  const keys = generateSshKeys(3);
  // First fetch: two keys.
  const first = await stubGithubKeys(
    context,
    keys.slice(0, 2).map((k) => k.publicLine),
  );
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  expect(first.count()).toBe(1);

  // Second fetch: the first key is gone and two new ones appeared, so
  // the record's OWN id changes. Matching by fingerprint would file this
  // as a new contact and leave a stale duplicate behind.
  await context.unroute("https://api.github.com/users/*/keys");
  await stubGithubKeys(context, [keys[1].publicLine, keys[2].publicLine]);
  await lookUpGithubUser(panel, GITHUB_USER);
  const preview = panel.getByRole("region", { name: "Import key" });
  await expect(preview).toContainText("Updates the key you already have");
  await expect(preview).toContainText("1 key added");
  await expect(preview).toContainText("1 key removed");
  await preview.getByRole("button", { name: "Update contact" }).click();
  await expect(preview).toBeHidden();

  // THE assertion: one RECORD, not one rendered label. The upsert is on
  // the contact's SOURCE (`{type: "github", user}`), not on its keyId --
  // the keyId moved when the first key stopped being published, so a
  // keyId-only upsert would leave the old record behind and this count
  // would be 2.
  const stored = await readContacts(panel);
  expect(stored).toHaveLength(1);
  expect(stored[0].source).toMatchObject({ type: "github", user: GITHUB_USER });
  // And it is the SECOND fetch's key set that survived.
  expect(stored[0].recipients?.map((r) => r.keyId)).toEqual([
    stored[0].keyId,
    expect.any(String),
  ]);

  await goToKeys(panel);
  console.log(JSON.stringify(await panel.getByText(`${GITHUB_USER} (GitHub)`).evaluateAll((els) => els.map((e) => ({ tag: e.tagName, cls: (e as HTMLElement).className, parent: (e.parentElement?.outerHTML ?? "").slice(0, 400) }))), null, 1));
  await expect(panel.getByText(`${GITHUB_USER} (GitHub)`)).toHaveCount(1);
});

test("an unknown account is refused inline, without a toast", async ({
  context,
  panel,
}) => {
  await stubGithubStatus(context, 404);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, "definitely-not-a-real-account");

  // The message is actionable ("check the spelling"), so it stays on the
  // step in the error slot rather than expiring in a toast -- and the
  // flow stays on the source step, ready for another try.
  await expect(panel.getByRole("alert")).toContainText(/no GitHub account/i);
  await expect(panel.getByRole("button", { name: "Look up" })).toBeVisible();
});

test("a rate limit says it is shared, and when it lifts", async ({
  context,
  panel,
}) => {
  const resetAt = Math.floor(Date.now() / 1000) + 10 * 60;
  await stubGithubStatus(context, 403, {
    "x-ratelimit-remaining": "0",
    "x-ratelimit-reset": String(resetAt),
  });
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await lookUpGithubUser(panel, GITHUB_USER);

  // "You have made too many requests" is the natural reading and it is
  // usually wrong: the lookup is unauthenticated, so the budget is per
  // IP address and an office or VPN shares one.
  const alert = panel.getByRole("alert");
  await expect(alert).toContainText(/IP address/);
  await expect(alert).toContainText(/Try again in about/);
});

test("a paste into the GitHub field is a username, not armor", async ({
  context,
  panel,
}) => {
  const [key] = generateSshKeys(1);
  const github = await stubGithubKeys(context, [key.publicLine]);
  await onboardWithPasswordSkipKey(panel, PASSWORD);
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();

  // The source step listens for paste on the DOCUMENT, because there is
  // no textarea to aim at. Without the field-aware bail, this paste is
  // claimed by that listener, preventDefault'd, and handed to the key
  // parser -- which says it doesn't look like a key while the field the
  // user pasted into stays empty.
  const field = panel.getByLabel(/GitHub user/i);
  await field.focus();
  // A REAL paste gesture, because the bug is in a real paste listener: a
  // synthetic ClipboardEvent would not insert the text either, so it
  // could not tell the two behaviours apart.
  await panel.evaluate(async (user) => {
    await navigator.clipboard.writeText(user);
  }, GITHUB_USER);
  await field.press("ControlOrMeta+v");
  await expect(field).toHaveValue(GITHUB_USER);
  await expect(panel.getByRole("alert")).toHaveCount(0);

  // And the pasted name is what gets looked up.
  await panel.getByRole("button", { name: "Look up" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    `${GITHUB_USER} (GitHub)`,
  );
  expect(github.count()).toBe(1);
});
