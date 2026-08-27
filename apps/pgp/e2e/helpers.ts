import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Drive the onboarding flow with a password master and generate a first
 * ECC key. Leaves the panel on the unlocked main UI (My Keys visible).
 */
export async function onboardWithPassword(
  panel: Page,
  password: string,
): Promise<void> {
  // Storage step (default: local).
  await panel.getByRole("button", { name: "Next" }).click();

  // Protection step: switch from the passkey default to password.
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  await panel.getByRole("button", { name: "Set password" }).click();

  // Identity step: fill name/email, generate an ECC key (fast).
  await panel.getByPlaceholder("Your full name").fill("E2E Test");
  await panel.getByPlaceholder("you@example.com").fill("e2e@test.local");
  await panel.getByRole("button", { name: "Create my PGP key" }).click();

  // Preset step: keep the defaults so specs see the stock preferences.
  await panel
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 30_000 });

  // Onboarding lands on the main UI (default: Main/workspace tab).
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Onboard with a password master but SKIP generating a key ("I'll set
 *  up later"), so a later import leaves exactly one key to target. */
export async function onboardWithPasswordSkipKey(
  panel: Page,
  password: string,
): Promise<void> {
  await panel.getByRole("button", { name: "Next" }).click();
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  await panel.getByRole("button", { name: "Set password" }).click();
  await panel.getByRole("button", { name: "I'll set up later" }).click();
  await panel.getByRole("button", { name: "Keep the defaults" }).click();
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Unlock the single key on the Keys tab (password protection). */
export async function unlockOnlyKey(
  panel: Page,
  password: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Unlock", exact: true }).click();
  const pw = panel.getByPlaceholder("Enter password");
  await pw.fill(password);
  await pw.press("Enter");
  // `exact: true` is LOAD-BEARING. Playwright's default accessible-name
  // match is a case-insensitive SUBSTRING, so `{ name: "Lock" }` also
  // matches the "Unlock" button -- which is exactly what is on screen
  // when the key is still locked. Without it this wait is satisfied by
  // the state it is supposed to prove we have left, so every caller
  // that relies on "the key is now unlocked" proceeds against a locked
  // key and its later assertions mean nothing. Found when it silently
  // defeated an early draft of `e2e/ssh-memory.spec.ts`.
  await expect(
    panel.getByRole("button", { name: "Lock", exact: true }),
  ).toBeVisible();
}

/** Lock the single (unlocked) key from the Keys tab -- in-app, no reload. */
export async function lockOnlyKey(panel: Page): Promise<void> {
  await goToKeys(panel);
  // Exact for the same reason as above: a substring match here would
  // happily click "Unlock" and this helper would lock nothing.
  await panel.getByRole("button", { name: "Lock", exact: true }).click();
  await expect(
    panel.getByRole("button", { name: "Unlock", exact: true }),
  ).toBeVisible();
}

/** Sign a plaintext message in the workspace with the (single) own key. */
export async function signInWorkspace(
  panel: Page,
  message: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Sign", exact: true }).click();
  await panel.locator("textarea").first().fill(message);
  await panel.getByRole("button", { name: /^sign$/i }).click();
  // Armored output is never displayed anymore; completion swaps the
  // action bar to Download + Copy. The Copy button renders ONLY when
  // armored text output exists, so its presence proves the signature
  // was produced.
  await expect(panel.getByRole("button", { name: "Download" })).toBeVisible();
  await expect(panel.getByRole("button", { name: "Copy" })).toBeVisible();
}

/** Encrypt `plaintext` to the single own key via the workspace and return
 *  the armored ciphertext (produced by the app, so it round-trips). */
export async function encryptToSelfInWorkspace(
  panel: Page,
  plaintext: string,
): Promise<string> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: "Encrypt", exact: true }).click();
  // Recipient: the box starts empty by design; pick the single own
  // (encryption-capable) key from the dropdown.
  await panel.getByRole("combobox", { name: "Recipients" }).click();
  await panel.getByRole("option").first().click();
  await expect(
    panel.getByRole("button", { name: /^Remove / }).first(),
  ).toBeVisible();
  await panel.locator("textarea").first().fill(plaintext);
  await panel.getByRole("button", { name: /^encrypt$/i }).click();
  // Ciphertext is never displayed; Download is the interface. Capture
  // the download and read the armor back out of the file.
  const downloadEvent = panel.waitForEvent("download");
  await panel.getByRole("button", { name: "Download" }).click();
  const file = await downloadEvent;
  const path = await file.path();
  const armored = await readFile(path, "utf8");
  expect(armored).toContain("BEGIN PGP MESSAGE");
  return armored;
}

/** Decrypt an armored message in the workspace (auto-selects decrypt). */
export async function decryptInWorkspace(
  panel: Page,
  ciphertext: string,
  expectedPlaintext: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(ciphertext);
  await panel.getByRole("button", { name: /^decrypt$/i }).click();
  await expect(panel.getByText(expectedPlaintext).first()).toBeVisible();
}

/** Unlock the vault from the master lock screen with a password. */
export async function unlockWithPassword(
  panel: Page,
  password: string,
  opts: {
    /** Expect the vault-unreadable screen instead of the tab bar.
     *  A session key that cannot open the stores gets its own screen --
     *  there is no tab bar to wait for, because rendering the normal UI
     *  would show an empty keyring for a vault that is intact on disk. */
    expectVaultUnreadable?: boolean;
  } = {},
): Promise<void> {
  await panel.getByLabel("Master password").fill(password);
  await panel.getByRole("button", { name: "Unlock" }).click();
  if (opts.expectVaultUnreadable) {
    await expect(panel.getByText("Your vault could not be read")).toBeVisible({
      timeout: 15_000,
    });
    return;
  }
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 15_000,
  });
}

/** Switch to the Keys tab. Purely a UI switch -- the open tab is not a
 *  preference, so this writes nothing to storage. */
export async function goToKeys(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Keys" }).click();
  await expect(panel.getByRole("heading", { name: "My Keys" })).toBeVisible();
}

/** True iff `(ciphertextBytes - 16 GCM tag)` is a power-of-two padding
 *  bucket >= 2048 -- i.e. the blob was saved with length-hiding padding. */
export function isPaddedBucket(ciphertextBytes: number): boolean {
  const plaintext = ciphertextBytes - 16;
  return plaintext >= 2048 && (plaintext & (plaintext - 1)) === 0;
}

/** Open Settings and switch key storage between "this device only" and
 *  "sync across devices", waiting for the migration to finish. Throws if
 *  the migration surfaces an error (e.g. sync quota exhausted). */
export async function switchStorageTo(
  panel: Page,
  target: "local" | "sync",
): Promise<void> {
  const label = target === "sync" ? "Sync across devices" : "This device only";
  await panel.getByRole("tab", { name: "Settings" }).click();
  await expect(
    panel.getByRole("heading", { name: "Key storage" }),
  ).toBeVisible();
  const radio = panel.getByRole("radio", { name: new RegExp(label) });
  // click(), not check(): the radio is controlled and only reflects the
  // new location once the async migration commits, so check()'s
  // post-click state assertion would fail mid-migration.
  await radio.click();
  // Migration is done once the picker reflects the new location (an inline
  // spinner shows on the target row meanwhile -- no "Migrating..." text).
  await expect(radio).toBeChecked({ timeout: 30_000 });
  // The migration error paragraph (destructive text) must not appear.
  await expect(panel.locator("p.text-destructive")).toHaveCount(0);
}

/** Import an armored public key as a contact via the Keys-tab drop zone's
 *  file input. Returns after the "Added" toast confirms success. */
export async function importContact(
  panel: Page,
  armoredPublicKey: string,
): Promise<void> {
  await goToKeys(panel);
  // The contact drop zone's hidden file input (distinct accept list).
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "key.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armoredPublicKey, "utf8"),
    });
  // A single key previews before it lands (a bundle imports straight
  // away -- see importContactsBulk).
  await panel.getByRole("button", { name: "Import contact" }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
}

/** Import an armored, unprotected private key via the Import Key page,
 *  re-protecting it with `password`. Returns once the key card appears. */
export async function importPrivateKey(
  panel: Page,
  armoredPrivateKey: string,
  password: string,
  ownerName: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, armoredPrivateKey);
  // The key is previewed before anything is stored; Continue moves on to
  // choosing how the secret is protected at rest.
  await panel.getByRole("button", { name: "Continue" }).click();
  // Protection step: choose password, set it, import.
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  // `exact` so it doesn't also match the "Import Key" button behind the page.
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  // Success closes the page; on error it stays open. Then confirm the key
  // landed on the Keys tab.
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
  await expect(panel.getByText(ownerName).last()).toBeVisible();
  // Wait for the slide-over to finish its exit animation: its onClose
  // fires a deferred nav.collapseToTop() that would dismiss any page the
  // test opens in the meantime.
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
}

/** Import an armored public key via the Import Key page, expecting it to
 *  be REJECTED with an error matching `reason` (the page stays open). */
export async function importContactExpectRejected(
  panel: Page,
  armoredPublicKey: string,
  /** Matched against the whole panel -- the health banner's wording. */
  reason: RegExp,
  /** Matched against the footer alert, which states the rejection in
   *  `importRejectionMessage`'s words rather than the banner's. Defaults
   *  to `reason` for callers where the two agree. */
  footerReason: RegExp = reason,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, armoredPublicKey);
  // An unusable key still previews -- with its health banner explaining
  // why, and no import button.
  //
  // The footer names the SPECIFIC reason now, not a generic "this key
  // can't be imported": `IncomingKey.rejection` was declared and never
  // rendered, so every refusal -- expired, revoked, an ECDSA SSH key,
  // a PuTTY file -- read as the same sentence. Asserting the reason
  // rather than the fallback is also the stronger check: the fallback
  // only proved SOMETHING was refused.
  await expect(panel.getByRole("alert")).toContainText(footerReason);
  await expect(panel.getByRole("region", { name: "Import key" })).toContainText(
    reason,
  );
  // The actual invariant behind the message: there is no way to import it.
  await expect(
    panel.getByRole("button", { name: "Import contact" }),
  ).toHaveCount(0);
}

/** Feed armored key text to the open Import Key page via its file input
 *  (the flow has no paste box -- armor is never rendered). */
export async function importFileInPanel(
  panel: Page,
  armored: string,
): Promise<void> {
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"]')
    .setInputFiles({
      name: "key.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armored, "utf8"),
    });
}

/** Pick a workspace mode explicitly (auto-detect only fires for
 *  recognizable PGP blocks, so plain-text tests set the mode by hand). */
export async function setWorkspaceMode(
  panel: Page,
  mode: "Encrypt" | "Decrypt" | "Sign" | "Verify",
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.getByRole("combobox").first().click();
  await panel.getByRole("option", { name: mode, exact: true }).click();
}

/** Import many contacts in a single file drop -- the drop zone splits a
 *  file into individual public-key blocks -- returning after the batch
 *  "Added N contacts" toast. Far faster than one import at a time; use it
 *  to seed a vault with a lot of key material. */
export async function importContactsBulk(
  panel: Page,
  armoredPublicKeys: string[],
): Promise<void> {
  // One key is a preview-then-confirm flow, not a bulk import.
  if (armoredPublicKeys.length === 1) {
    await importContact(panel, armoredPublicKeys[0]);
    return;
  }
  await goToKeys(panel);
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"]')
    .setInputFiles({
      name: "contacts.asc",
      mimeType: "application/pgp-keys",
      buffer: Buffer.from(armoredPublicKeys.join("\n"), "utf8"),
    });
  await expect(
    panel
      .getByText(new RegExp(`Added ${armoredPublicKeys.length} contact`))
      .first(),
  ).toBeVisible();
}

/**
 * One-call test setup: onboard with a password master (generating a first
 * key), then bulk-import `contactKeys` as contacts. Leaves the panel
 * unlocked on the Keys tab with a populated vault -- a ready starting
 * point for storage / backup / recipient tests without repeating the
 * onboarding + import boilerplate in every spec.
 */
export async function seedVault(
  panel: Page,
  password: string,
  contactKeys: string[] = [],
): Promise<void> {
  await onboardWithPassword(panel, password);
  if (contactKeys.length > 0) await importContactsBulk(panel, contactKeys);
}

// ── command palette ──────────────────────────────────────────────────

/** Open the command palette (the footer's "Commands" button is the
 *  click-driven equivalent of mod+K) and run the action named `name`. */
export async function runPaletteAction(
  panel: Page,
  name: string,
): Promise<void> {
  await panel.getByRole("button", { name: "Commands" }).click();
  await expect(
    panel.getByRole("dialog", { name: "Command palette" }),
  ).toBeVisible();
  // cmdk renders each item as role=option.
  await panel.getByRole("option", { name }).click();
}

/** Master-lock the vault in-app via the palette's "Lock now" (NOT a
 *  reload): this is the only path that runs `doMasterLock`, which is what
 *  encrypts + stashes the workspace draft and drops the contacts session.
 *  Leaves the panel on the master unlock screen. */
export async function lockMasterViaPalette(panel: Page): Promise<void> {
  await runPaletteAction(panel, "Lock now");
  await expect(panel.getByLabel("Master password")).toBeVisible();
}

// ── operation history (opt-in) ───────────────────────────────────────

/** Turn on the "Save to history" toggle. It only renders in encrypt mode
 *  (and only when never-cache is off), so this also selects that mode. */
export async function enableSaveToHistory(panel: Page): Promise<void> {
  await setWorkspaceMode(panel, "Encrypt");
  const toggle = panel.getByRole("switch", { name: "Save to history" });
  await expect(toggle).toBeVisible();
  if ((await toggle.getAttribute("aria-checked")) !== "true") {
    await toggle.click();
  }
  await expect(toggle).toHaveAttribute("aria-checked", "true");
}

/** Open the History page via the palette (the icon button is
 *  deliberately out of the tab order and has no stable text). */
export async function openHistoryPage(panel: Page): Promise<void> {
  await runPaletteAction(panel, "Open history");
  await expect(panel.getByRole("heading", { name: "History" })).toBeVisible();
}

// ── CRX signing (opt-in, off by default) ─────────────────────────────

/** Flip the Settings-tab "Enable CRX signing" switch on. */
/** Turn the import step's network lookups (GitHub, keys.openpgp.org) on
 *  or off. On by default, so tests only need this to turn it OFF -- or
 *  to prove that turning it back on restores the field. */
export async function setKeyDiscovery(panel: Page, on: boolean): Promise<void> {
  await panel.getByRole("tab", { name: "Settings" }).click();
  const sw = panel.getByRole("switch", { name: "Look up keys online" });
  await expect(sw).toBeVisible();
  if ((await sw.getAttribute("aria-checked")) !== String(on)) await sw.click();
  await expect(sw).toHaveAttribute("aria-checked", String(on));
}

export async function enableCrxSigning(panel: Page): Promise<void> {
  await panel.getByRole("tab", { name: "Settings" }).click();
  const sw = panel.getByRole("switch", { name: "Enable CRX signing" });
  await expect(sw).toBeVisible();
  if ((await sw.getAttribute("aria-checked")) !== "true") await sw.click();
  await expect(sw).toHaveAttribute("aria-checked", "true");
}

/** Open the Import Key page and paste a raw RSA private-key PEM, stopping
 *  on the paste step. Split out from {@link importCrxSigningKey} so a spec
 *  can inspect the page while the PEM is still on screen. Requires CRX
 *  signing to be enabled -- the page only recognises a raw RSA PEM then. */
export async function pasteCrxSigningKey(
  panel: Page,
  pem: string,
  label: string,
): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await importFileInPanel(panel, pem);
  // Detection is what routes this to the CRX branch; assert it so a
  // regression there fails loudly instead of importing as a PGP key. A
  // bare RSA PEM has no cert to show, but it still gets the preview step
  // every other key kind gets -- one classifier, one flow -- so step
  // through it before the protect step's label field.
  await expect(panel.getByText("RSA signing key")).toBeVisible();
  await panel.getByRole("button", { name: "Continue", exact: true }).click();
  await panel.getByPlaceholder("e.g. My Extension").fill(label);
}

/** Finish a {@link pasteCrxSigningKey} flow, protecting the key with a
 *  password. Returns once the Import page has fully slid out. */
export async function completeCrxSigningKeyImport(
  panel: Page,
  password: string,
): Promise<void> {
  await panel.locator('input[name="protection"]').nth(1).check();
  await panel.getByLabel("Password", { exact: true }).fill(password);
  await panel.getByLabel("Confirm password").fill(password);
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden();
}

/** Import a raw RSA private-key PEM as a password-protected CRX signing
 *  key via the Import Key page. */
export async function importCrxSigningKey(
  panel: Page,
  pem: string,
  password: string,
  label: string,
): Promise<void> {
  await pasteCrxSigningKey(panel, pem, label);
  await completeCrxSigningKeyImport(panel, password);
}

/** Paste a cleartext-signed message into the workspace (auto-switches to
 *  Verify) and run verification. */
export async function verifySignedMessage(
  panel: Page,
  signedMessage: string,
): Promise<void> {
  await panel.getByRole("tab", { name: "Main" }).click();
  await panel.locator("textarea").first().fill(signedMessage);
  // The idle action button is labelled with the (auto-selected) mode.
  await panel.getByRole("button", { name: /^verify$/i }).click();
}

// ── SSH key material and the contacts store ──────────────────────────

/** One throwaway OpenSSH keypair, in the forms the specs need it. */
export interface SshKeyPair {
  /** OpenSSH private key file contents. */
  privateKey: string;
  /** `ssh-ed25519 AAAA...` with the comment stripped, the way GitHub
   *  serves it. */
  publicLine: string;
  /** `ssh-ed25519 AAAA... comment` -- the form a `.pub` file on disk
   *  has, and the only one that can auto-group (see `sharedComment`:
   *  grouping without asking requires every line to carry the SAME
   *  comment, and a stripped line carries none). */
  publicLineWithComment: string;
  /** The `-C` comment, which is the key's display name once imported --
   *  and what the delete confirmation asks the user to type. */
  comment: string;
  /** The OpenSSH `SHA256:...` fingerprint, which is what the UI prints
   *  for this key and what a stored `ContactRecipient.keyId` holds. */
  fingerprint: string;
  /** The first argument of this key's `-> ssh-ed25519` stanza in an age
   *  header: base64 of the first four bytes of the same SHA-256 the
   *  fingerprint is. Lets a spec assert WHICH keys a ciphertext was
   *  encrypted to, from the header alone -- see {@link ageStanzaTags}. */
  stanzaTag: string;
}

/** Generate throwaway ed25519 keypairs with `ssh-keygen`.
 *
 *  Generated per run rather than committed: no real key material lives in
 *  this repo, and an OpenSSH private key in a fixture file is exactly the
 *  thing that rule exists for.
 *
 *  `comment` receives the 0-based index so a caller can give every key
 *  the SAME comment -- the one input that makes an import auto-group. */
export function generateSshKeys(
  count: number,
  comment: (index: number) => string = (i) => `e2e-ssh-${i + 1}`,
): SshKeyPair[] {
  const dir = mkdtempSync(path.join(tmpdir(), "pgp-e2e-ssh-"));
  try {
    return Array.from({ length: count }, (_, i) => {
      const label = comment(i);
      // The comment can repeat across keys, so the FILE name cannot be
      // it -- ssh-keygen would refuse to overwrite the first key.
      const file = path.join(dir, `key-${i}`);
      execFileSync("ssh-keygen", [
        ...["-t", "ed25519"],
        ...["-N", ""],
        ...["-C", label],
        ...["-f", file],
        "-q",
      ]);
      const pub = readFileSync(`${file}.pub`, "utf8").trim();
      const [algorithm, blob] = pub.split(/\s+/);
      const hash = createHash("sha256").update(Buffer.from(blob, "base64"));
      const digest = hash.digest();
      return {
        privateKey: readFileSync(file, "utf8"),
        // GitHub serves `<type> <base64>` with no comment; mimic that so
        // a stub is not kinder than the real endpoint.
        publicLine: `${algorithm} ${blob}`,
        publicLineWithComment: `${algorithm} ${blob} ${label}`,
        comment: label,
        // Base64 of the whole digest, unpadded: OpenSSH's own form.
        fingerprint: `SHA256:${digest.toString("base64").replace(/=+$/, "")}`,
        stanzaTag: digest.subarray(0, 4).toString("base64").replace(/=+$/, ""),
      };
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The `-> ssh-ed25519 <tag>` tags in an armored age file's header.
 *
 * WHICH keys a message was encrypted to, read off the ciphertext itself
 * rather than inferred from whether some identity could open it. The
 * header is ASCII inside the armor and self-delimiting: a version line,
 * one stanza per recipient, then a `---` MAC line. Stops at the MAC so
 * the binary payload after it is never scanned as text (the same rule
 * `age_header_stanzas` follows in the engine).
 */
export function ageStanzaTags(armored: string): string[] {
  const body = armored
    .replace(/-----BEGIN AGE ENCRYPTED FILE-----/, "")
    .replace(/-----END AGE ENCRYPTED FILE-----/, "")
    .replace(/\s+/g, "");
  const header = Buffer.from(body, "base64").toString("binary");
  const tags: string[] = [];
  for (const line of header.split("\n")) {
    if (line.startsWith("---")) break;
    const match = /^-> ssh-ed25519 (\S+)/.exec(line);
    if (match) tags.push(match[1]);
  }
  return tags;
}

/** One stored contact record, as far as the e2e specs care. */
export interface StoredContact {
  keyId: string;
  userIds: string[];
  alias?: string;
  recipients?: { keyId: string; disabled?: true }[];
  source?: { type: string; user: string; fetchedAt?: number };
}

/**
 * The contacts store, DECRYPTED -- because "one contact" is a property of
 * storage, and asserting it through the DOM cannot tell a real duplicate
 * record from a label the panel happens to render twice.
 *
 * Driven through the panel's LIVE wasm instance (with its live contacts
 * session), located from the page's own entry script the way
 * `migration.spec.ts` does it. The plaintext is `[json][0x00][padding]`
 * (see `lib/storage/padding.ts`), so it is cut at the first NUL.
 */
export async function readContacts(panel: Page): Promise<StoredContact[]> {
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
        { iv: string; ciphertext: string } | undefined;
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
    { u: url, key: "pgp_public_contacts" },
  );
}

/** Set the encrypt-mode "Also encrypt to me" preference. Off is what a
 *  test asserting WHICH recipients a message reached wants: with it on,
 *  the user's own key rides along and adds a stanza of its own. */
export async function setEncryptToSelf(
  panel: Page,
  on: boolean,
): Promise<void> {
  await setWorkspaceMode(panel, "Encrypt");
  const toggle = panel.getByRole("switch", { name: "Also encrypt to me" });
  await expect(toggle).toBeVisible();
  if ((await toggle.getAttribute("aria-checked")) !== String(on)) {
    await toggle.click();
  }
  await expect(toggle).toHaveAttribute("aria-checked", String(on));
}
