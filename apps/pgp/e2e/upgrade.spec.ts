import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { BrowserContext, Page } from "@playwright/test";
import { test as base, chromium } from "@playwright/test";

import type { PrfRecord } from "./webauthn-carry";
import { expect, getExtensionId } from "./fixtures";
import {
  decryptInWorkspace,
  enableSaveToHistory,
  encryptToSelfInWorkspace,
  goToKeys,
  importContact,
  importPrivateKey,
  onboardWithPassword,
  openHistoryPage,
  unlockOnlyKey,
  unlockWithPassword,
} from "./helpers";
import { TEST_KEYS } from "./keys";
import { PRIVATE_KEY_FIXTURE } from "./private-key";
import {
  addPrfAuthenticatorWithId,
  drainPrfLog,
  exportCredentials,
  installPrfRecorder,
  installPrfReplay,
  readPrfRequests,
  removePrfAuthenticator,
  restoreCredentials,
} from "./webauthn-carry";

/**
 * THE REAL UPGRADE PATH: bytes written by the SHIPPED release, read by
 * the build in `.output/chrome-mv3`.
 *
 * ## Why this exists, when `migration.spec.ts` already tests migration
 *
 * Every other migration test in this suite runs inside ONE build. The
 * closest, `migration.spec.ts`, is careful: it seals a blob with the real
 * legacy primitive through the real wasm and drives the real app over it.
 * But the bytes are still produced by TODAY's code -- by today's
 * `encryptContacts`, today's JSON shape, today's padding, today's key
 * derivation. Anything the current tree gets *consistently* wrong is
 * invisible to it, because both halves of the round trip moved together.
 *
 * What users actually have is different: **v1.4.4 wrote their blobs, and
 * the new build has to read them.** Since 1.4.4 shipped, this tree has
 * rewritten the at-rest sealing envelope, refactored the storage layer
 * into `encrypted-store` / `protected-store`, changed several
 * wasm-bindgen signatures, and added a `kind` discriminant to stored key
 * records. Any one of those is a plausible way to brick a vault, and none
 * of them is covered end to end by a test that only ever talks to itself.
 *
 * So this spec runs the actual upgrade: install 1.4.4, use it like a
 * user, then swap the extension underneath the same profile and open it
 * again.
 *
 * ## The mechanic, and the one wrinkle that makes it work
 *
 * `fixtures.ts` launches with `launchPersistentContext("")` -- an
 * ephemeral profile that is thrown away per file. That is exactly what
 * every other spec wants and exactly what this one cannot use: we need
 * `chrome.storage` to survive across two browser launches.
 *
 * Two things must line up for that:
 *
 *  1. A real `userDataDir`, reused for both launches, so the profile (and
 *     with it `Local Extension Settings/`) persists.
 *  2. The SAME extension id across both launches. An unpacked extension's
 *     id is derived from its **absolute path** -- not from a key in the
 *     manifest -- and `chrome.storage` is partitioned per extension id.
 *     Loading 1.4.4 from one directory and the new build from another
 *     would hand the new build a pristine, empty storage area and this
 *     test would "pass" while proving nothing.
 *
 * Hence: one temp directory for the profile, one temp directory for the
 * extension, and the upgrade is performed by REPLACING THE CONTENTS of
 * the extension directory in place. Same path, same id, same storage
 * partition -- which is precisely what Chrome does to a user on an
 * auto-update.
 *
 * ## What actually proves the vault survived
 *
 * A record being listed in the UI after the upgrade proves the store
 * deserialised. It does not prove the *key material* came through: a
 * corrupted private key would still render a perfectly good-looking card.
 * So the load-bearing assertion here is a **cross-version decrypt** --
 * ciphertext produced by 1.4.4, decrypted by the new build with a key
 * sealed by 1.4.4 and unsealed by the new build. That exercises the
 * master KDF, the keyring envelope, the per-key protection blob, and the
 * wasm decrypt path in one shot, and it cannot pass on a vault that only
 * looks intact.
 *
 * The second assertion is the WRITE side of the `kind` migration rule
 * (`lib/storage/key-kind.ts`): a PGP record must be persisted with the
 * `kind` field ABSENT, never `kind: "pgp"`. Absent is what every existing
 * user's blob looks like, and it is what makes a downgrade back to 1.4.4
 * survivable. `key-kind.test.ts` asserts this on the helper; nothing
 * asserted it on what the app really writes to `chrome.storage`, which is
 * the only place it matters.
 */

const execFileAsync = promisify(execFile);

const MASTER = "correct horse battery staple";

/** The shipped release under test. Absent on a fresh clone -- the zip is
 *  a release artifact, not a checked-in fixture -- so the spec skips
 *  rather than failing when it isn't there. */
const SHIPPED_ZIP = path.resolve(
  import.meta.dirname,
  "..",
  ".output",
  "amibeingpwnedpgp-1.4.4-chrome.zip",
);
const CURRENT_BUILD = path.resolve(
  import.meta.dirname,
  "..",
  ".output",
  "chrome-mv3",
);

const STORAGE_KEYRING = "pgp_keyring";
const STORAGE_CONTACTS = "pgp_public_contacts";

/** Two contacts, because 1.4.4's Keys-tab drop zone imports a batch
 *  straight away while the current build previews a lone key first --
 *  see `importContactsLegacy`. */
const CONTACT = TEST_KEYS[0];
const CONTACT_2 = TEST_KEYS[1];
/** A third, imported AFTER the upgrade, so the `kind` assertion looks at
 *  a contact record the NEW build wrote rather than one it inherited. */
const CONTACT_NEW = TEST_KEYS[2];

const SECRET = "ciphertext-minted-by-1.4.4-sentinel";

/**
 * Launch Chromium with an unpacked extension AND a persistent profile.
 *
 * Deliberately a local variant of `fixtures.launchExtensionContext`,
 * which hardcodes `userDataDir: ""`. Everything else (the `--headless=new`
 * dance -- extensions do not load under the classic headless mode that
 * `headless: true` selects) is the same, and the comment there explains
 * why.
 */
async function launchWithProfile(
  extensionDir: string,
  userDataDir: string,
): Promise<BrowserContext> {
  const headless = !process.env.HEADED;
  return chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      ...(headless ? ["--headless=new"] : []),
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
    ],
  });
}

/** Open the side panel of the loaded extension and return the page. */
async function openPanel(context: BrowserContext): Promise<Page> {
  const extensionId = await getExtensionId(context);
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  return page;
}

/**
 * Import contacts through 1.4.4's Keys-tab drop zone.
 *
 * `helpers.importContact` cannot be reused for the pre-upgrade half: the
 * preview-then-confirm step ("Import contact" button) is NEW -- that
 * string does not appear anywhere in the 1.4.4 bundle. 1.4.4 drops the
 * file straight into the store and reports an "Added N contact(s)" toast.
 * `helpers.importContactsBulk` takes exactly that path, but only for two
 * or more keys; for one it delegates to the preview flow. Rather than
 * depend on that internal branch staying put, this does the drop
 * directly.
 */
async function importContactsLegacy(
  panel: Page,
  armoredPublicKeys: string[],
): Promise<void> {
  await goToKeys(panel);
  await panel
    // `[multiple]` disambiguates the drop zone's input from the Import Key
    // page's single-file one, which carries the same accept list.
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt"][multiple]')
    .first()
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
 * Decrypt one of the app's own encrypted-array stores and return its
 * records, in the raw shape they are persisted in.
 *
 * Same technique as `migration.spec.ts`: locate the wasm-bindgen glue
 * chunk from the page's own entry script and drive the LIVE instance, so
 * the decrypt runs under the live contacts session rather than a fresh
 * one. Kept local so the two specs stay independent.
 *
 * Padding is stripped by hand (`lib/storage/padding.ts`: the plaintext is
 * `[json][0x00][0x00...]`, and `JSON.stringify` can never emit a raw NUL,
 * so the first NUL is an unambiguous end-of-data marker).
 */
async function readStoreRecords(
  panel: Page,
  storageKey: string,
): Promise<Record<string, unknown>[]> {
  const glueUrl = await panel.evaluate(async () => {
    const entry = document.querySelector<HTMLScriptElement>(
      'script[type="module"][src]',
    );
    if (!entry) return null;
    const source = await fetch(entry.src).then((r) => r.text());
    const match = /gpg_wasm-[A-Za-z0-9_-]+\.js/.exec(source);
    return match ? new URL(match[0], entry.src).href : null;
  });
  if (glueUrl === null) throw new Error("wasm glue chunk not locatable");

  return panel.evaluate(
    async ({ u, key }: { u: string; key: string }) => {
      const mod = (await import(/* @vite-ignore */ u)) as {
        decryptStore: (d: string, ct: Uint8Array, iv: Uint8Array) => Uint8Array;
      };
      const b64ToBytes = (s: string) =>
        Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const stored = (await chrome.storage.local.get(key))[key] as {
        iv: string;
        ciphertext: string;
      } | null;
      if (!stored) throw new Error(`no blob stored at ${key}`);
      const plaintext = mod.decryptStore(
        key,
        b64ToBytes(stored.ciphertext),
        b64ToBytes(stored.iv),
      );
      const nul = plaintext.indexOf(0);
      const json = nul === -1 ? plaintext : plaintext.subarray(0, nul);
      return JSON.parse(new TextDecoder().decode(json)) as Record<
        string,
        unknown
      >[];
    },
    { u: glueUrl, key: storageKey },
  );
}

base.describe("upgrade from the shipped 1.4.4 build", () => {
  base.skip(
    !existsSync(SHIPPED_ZIP),
    `Shipped release zip not found at ${SHIPPED_ZIP}. It is a release ` +
      `artifact, not a checked-in fixture -- download or build v1.4.4 to ` +
      `run the cross-version upgrade test.`,
  );

  base(
    "a vault created by v1.4.4 opens, decrypts, and keeps its contacts under the current build",
    async () => {
      // Two browser launches, a full onboarding (Argon2id at 64 MB), key
      // generation, several encrypt/decrypt round trips and a key import.
      base.setTimeout(600_000);

      const tmpRoot = await mkdtemp(path.join(os.tmpdir(), "pgp-upgrade-"));
      // The profile and the extension live side by side, but the
      // extension dir's PATH is the thing that must never change: it is
      // what the extension id is derived from.
      const userDataDir = path.join(tmpRoot, "profile");
      const extensionDir = path.join(tmpRoot, "extension");

      /** Armored ciphertext produced BY 1.4.4 -- the whole point. */
      let armoredFrom144 = "";
      let idBefore = "";
      let idAfter = "";

      try {
        await base.step("install the shipped 1.4.4 build", async () => {
          await execFileAsync("unzip", ["-q", SHIPPED_ZIP, "-d", extensionDir]);
          expect(
            existsSync(path.join(extensionDir, "manifest.json")),
            "1.4.4 unpacked",
          ).toBe(true);
        });

        await base.step("use 1.4.4 like a user would", async () => {
          const context = await launchWithProfile(extensionDir, userDataDir);
          try {
            idBefore = await getExtensionId(context);
            const panel = await openPanel(context);

            // Onboarding drives the same strings in both builds (verified
            // against the 1.4.4 bundle), so the shared helper is reused --
            // if it ever stops matching, that is itself a finding.
            await onboardWithPassword(panel, MASTER);

            // History on, so the encrypt below leaves a record in the
            // segmented history store as well -- another format that
            // changed since 1.4.4.
            await enableSaveToHistory(panel);

            // Mint the ciphertext BEFORE importing contacts: the
            // recipient picker's first option is the only one the shared
            // helper can address, and with contacts present it is no
            // longer guaranteed to be our own key.
            armoredFrom144 = await encryptToSelfInWorkspace(panel, SECRET);
            expect(armoredFrom144).toContain("BEGIN PGP MESSAGE");

            await importContactsLegacy(panel, [
              CONTACT.publicKey,
              CONTACT_2.publicKey,
            ]);
            await goToKeys(panel);
            await expect(panel.getByText(CONTACT.label).first()).toBeVisible();

            // Close cleanly so chrome.storage is flushed to the profile.
            await panel.close();
          } finally {
            await context.close();
          }
        });

        await base.step(
          "swap in the current build at the SAME path",
          async () => {
            expect(
              existsSync(CURRENT_BUILD),
              `Current build missing at ${CURRENT_BUILD} -- run \`pnpm build\`.`,
            ).toBe(true);
            await rm(extensionDir, { recursive: true, force: true });
            await cp(CURRENT_BUILD, extensionDir, { recursive: true });
          },
        );

        const context = await launchWithProfile(extensionDir, userDataDir);
        try {
          idAfter = await getExtensionId(context);
          // If this ever fails the rest of the test is meaningless: a
          // different id means a different, empty storage partition, and
          // every assertion below would pass on an empty vault.
          expect(
            idAfter,
            "extension id must be identical across the upgrade, or the " +
              "new build gets a fresh storage partition and this test " +
              "proves nothing",
          ).toBe(idBefore);

          const panel = await openPanel(context);

          await base.step(
            "the vault unlocks with the original master password",
            async () => {
              // The master protection blob (Argon2id params, salt,
              // wrapped key) was written by 1.4.4.
              await unlockWithPassword(panel, MASTER);
            },
          );

          await base.step("the contacts are still there", async () => {
            await goToKeys(panel);
            await expect(panel.getByText(CONTACT.label).first()).toBeVisible({
              timeout: 15_000,
            });
            await expect(
              panel.getByText(CONTACT_2.label).first(),
            ).toBeVisible();
          });

          await base.step(
            "ciphertext minted by 1.4.4 decrypts under the new build",
            async () => {
              // THE assertion. Unlocking the key unseals a private-key
              // blob written by 1.4.4 under 1.4.4's protection format;
              // the decrypt then proves the recovered material is the
              // actual key, not merely a well-formed record.
              await unlockOnlyKey(panel, MASTER);
              await decryptInWorkspace(panel, armoredFrom144, SECRET);
            },
          );

          await base.step("the 1.4.4 history entry still reads", async () => {
            await openHistoryPage(panel);
            // The entry is titled by its operation; a history store the
            // new build could not open would render the empty state.
            await expect(
              panel.getByRole("heading", { name: "History" }),
            ).toBeVisible();
            await expect(panel.getByText(/no history/i)).toHaveCount(0);
          });

          await base.step(
            "and it all survives one more round trip",
            async () => {
              await panel.reload();
              await unlockWithPassword(panel, MASTER);
              await goToKeys(panel);
              await expect(panel.getByText(CONTACT.label).first()).toBeVisible({
                timeout: 15_000,
              });
              await unlockOnlyKey(panel, MASTER);
              await decryptInWorkspace(panel, armoredFrom144, SECRET);
            },
          );
          await base.step(
            "records WRITTEN by the new build carry no `kind` field",
            async () => {
              // The other half of the `kind` migration rule
              // (lib/storage/key-kind.ts): absent means pgp, and a PGP
              // record must be persisted with the field ABSENT so that
              // (a) it is byte-compatible with every blob already on
              // disk and (b) a downgrade back to 1.4.4 still reads it.
              // Asserting this on the INHERITED records would prove
              // nothing -- 1.4.4 had no such field to write -- so force
              // the new build to write fresh records first.
              await panel.reload();
              await unlockWithPassword(panel, MASTER);
              await importContact(panel, CONTACT_NEW.publicKey);
              await importPrivateKey(
                panel,
                PRIVATE_KEY_FIXTURE.privateKey,
                MASTER,
                PRIVATE_KEY_FIXTURE.name,
              );

              const keyring = await readStoreRecords(panel, STORAGE_KEYRING);
              expect(
                keyring.length,
                "the imported key joined the 1.4.4 one",
              ).toBeGreaterThan(1);
              for (const record of keyring) {
                expect(
                  "kind" in record,
                  `keyring record ${String(record.keyId)} must not persist a ` +
                    `\`kind\` field (absent means pgp)`,
                ).toBe(false);
              }

              const contacts = await readStoreRecords(panel, STORAGE_CONTACTS);
              expect(contacts.length).toBeGreaterThan(2);
              for (const record of contacts) {
                expect(
                  "kind" in record,
                  `contact record ${String(record.keyId)} must not persist a ` +
                    `\`kind\` field (absent means pgp)`,
                ).toBe(false);
              }
            },
          );
        } finally {
          await context.close();
        }
      } finally {
        await rm(tmpRoot, { recursive: true, force: true });
      }
    },
  );
});

/**
 * THE SAME UPGRADE, BUT PASSKEY-PROTECTED.
 *
 * ## Why a second block rather than another step above
 *
 * The block above covers a password vault: Argon2id, a canary, a
 * password the user can always type again. The passkey path shares
 * almost none of that. The master key is HKDF-SHA256 over a WebAuthn PRF
 * output and a `storedSecret` kept in plaintext beside it, mixed inside
 * wasm; there is no canary, no KDF parameters, and -- this is the part
 * that matters -- **no fallback**. A password vault that fails to unlock
 * is an inconvenience. A passkey vault that fails to unlock is a user
 * whose keys are gone, permanently, with nothing to type instead.
 *
 * Since 1.4.4 shipped, this tree has rewritten the at-rest sealing
 * envelope (`protected.rs`), changed wasm-bindgen signatures on the
 * PRF-taking exports, and refactored storage into
 * `encrypted-store`/`protected-store`. `passkey.spec.ts` exercises all
 * of it, but only ever against bytes today's build just wrote. Nothing
 * checked that today's build can open a passkey vault that 1.4.4 sealed.
 *
 * Two code paths are covered, separately, because they are separate:
 *
 *  1. **Master protection** -- `initContactsSessionWithPrf` over the
 *     `pgp_master_protection` record 1.4.4 wrote. Note there is no
 *     canary on this path (`MasterUnlockScreen.handlePasskeyUnlock`
 *     calls `onUnlocked()` unconditionally once wasm returns), so
 *     "the lock screen went away" proves NOTHING. The assertion has to
 *     be that vault CONTENT decrypts under the derived session key --
 *     i.e. the 1.4.4 key is actually listed.
 *  2. **Per-key protection** -- a keyring blob with
 *     `protection.method === "passkey"` (`credentialId` / `prfSalt` /
 *     `storedSecret`), opened via `unlockWithPrf`, which binds its own
 *     AAD to the key id. Onboarding with a passkey reuses the master
 *     credential and salt but mints a FRESH `storedSecret` per blob, so
 *     this really is a different derivation from the master one.
 *
 * The load-bearing assertion is the same as above and for the same
 * reason: a sentinel encrypted BY 1.4.4, decrypted after the upgrade
 * with a key 1.4.4 sealed.
 *
 * ## The authenticator, and the one thing that is stubbed
 *
 * A PRF-capable credential cannot be carried across two browser
 * launches. That is a platform limit, not a shortcut: Chrome's virtual
 * authenticator is scoped to a tab, `WebAuthn.enable` does not exist at
 * browser scope, and `WebAuthn.getCredentials` does not export the
 * hmac-secret seed, so a credential restored with `addCredential`
 * asserts fine but returns NO `prf` extension result at all. All three
 * were measured against the Chrome build these tests run under -- see
 * `webauthn-carry.ts`, which documents what was tried.
 *
 * So the credential IS carried (real export, real restore, real
 * ceremony) and only the PRF output is replayed from what the real
 * authenticator produced in the first launch. Stubbing is confined to a
 * function of two inputs whose only specified property is that it is
 * deterministic; the storage records, the stored secrets, the HKDF, the
 * unseal and both builds' code are untouched. The replay is exact-match
 * and fail-closed, which turns it into an assertion of its own: if the
 * current build read a different `credentialId` or `prfSalt` out of the
 * 1.4.4 blob than 1.4.4 wrote, it misses and the unlock fails.
 *
 * The third test is the negative control for exactly that, and it is
 * permanent rather than a one-off manual check: same real ceremony, same
 * restored credential, same salt, same stored secret, and ONE BIT
 * flipped in the replayed PRF output. Nothing may open.
 */

const PASSKEY_NAME = "Passkey Upgrade";
const PASSKEY_EMAIL = "passkey-upgrade@test.local";
const PASSKEY_SECRET = "passkey-ciphertext-minted-by-1.4.4-sentinel";
const STORAGE_MASTER_PROTECTION = "pgp_master_protection";

/** The plaintext `pgp_master_protection` record, as stored. */
interface StoredMasterProtection {
  method: string;
  credentialId?: string;
  prfSalt?: string;
  storedSecret?: string;
}

/** Everything the 1.4.4 phase produces and the upgraded phase needs. */
interface PasskeyPhaseOne {
  tmpRoot: string;
  extensionDir: string;
  userDataDir: string;
  extensionId: string;
  /** Armored ciphertext produced BY 1.4.4. */
  armored: string;
  credentials: unknown[];
  prfRecords: PrfRecord[];
  masterProtection: StoredMasterProtection;
  keyProtection: Record<string, unknown>;
}

/** Read the (plaintext) master-protection record straight out of
 *  `chrome.storage.local`. Deliberately not via the app: the point is to
 *  compare the bytes 1.4.4 wrote with the bytes that are there after the
 *  upgrade, and any app-mediated read could normalise them. */
async function readMasterProtection(
  panel: Page,
): Promise<StoredMasterProtection> {
  return panel.evaluate(async (key: string) => {
    const stored = (await chrome.storage.local.get(key))[key] as
      StoredMasterProtection | undefined;
    if (!stored) throw new Error(`no master protection stored at ${key}`);
    return stored;
  }, STORAGE_MASTER_PROTECTION);
}

/** Onboard 1.4.4 with the PASSKEY (default) protection method.
 *
 *  A local variant because `helpers.onboardWithPassword` deliberately
 *  switches away from the passkey default, and `passkey.spec.ts` drives
 *  this inline against the current build rather than exporting it.
 *  Every string here was checked against the 1.4.4 bundle. */
async function onboardWithPasskey144(panel: Page): Promise<void> {
  await panel.getByRole("button", { name: "Next" }).click();
  // Passkey is the default protection method; no radio to switch.
  await panel.getByRole("button", { name: "Create passkey" }).click();
  await panel.getByPlaceholder("Your full name").fill(PASSKEY_NAME);
  await panel.getByPlaceholder("you@example.com").fill(PASSKEY_EMAIL);
  await panel.getByRole("button", { name: "Create my PGP key" }).click();
  await panel
    .getByRole("button", { name: "Keep the defaults" })
    .click({ timeout: 60_000 });
  await expect(panel.getByRole("tab", { name: "Keys" })).toBeVisible({
    timeout: 30_000,
  });
}

/** Drive the master lock screen's passkey unlock.
 *
 *  The screen auto-prompts on mount, but that races the page regaining
 *  focus, so clicking re-runs the ceremony deterministically; the
 *  `.catch` covers the auto-prompt having already won. Same shape as
 *  `passkey.spec.ts`, which is why it is not asserted on here -- the
 *  caller asserts on VAULT CONTENT, because this path has no canary and
 *  leaves the lock screen either way. */
async function clickUnlockWithPasskey(panel: Page): Promise<void> {
  await panel
    .getByRole("button", { name: "Unlock with passkey" })
    .click({ timeout: 8_000 })
    .catch(() => undefined);
}

base.describe.serial("upgrade from 1.4.4: passkey (WebAuthn PRF) vault", () => {
  base.skip(
    !existsSync(SHIPPED_ZIP),
    `Shipped release zip not found at ${SHIPPED_ZIP}. It is a release ` +
      `artifact, not a checked-in fixture -- download or build v1.4.4 to ` +
      `run the cross-version upgrade test.`,
  );

  let phase1: PasskeyPhaseOne;

  /**
   * The 1.4.4 half, run once. The three tests below are three separate
   * assertions about the SAME upgraded vault, and re-onboarding for each
   * would triple a slow setup without testing anything extra. They run
   * `.serial` and each takes its own browser launch off the shared
   * profile, so the upgrade itself is still cold-start for every one.
   */
  base.beforeAll(async () => {
    base.setTimeout(600_000);

    const tmpRoot = await mkdtemp(path.join(os.tmpdir(), "pgp-upgrade-pk-"));
    const userDataDir = path.join(tmpRoot, "profile");
    const extensionDir = path.join(tmpRoot, "extension");
    await execFileAsync("unzip", ["-q", SHIPPED_ZIP, "-d", extensionDir]);

    const context = await launchWithProfile(extensionDir, userDataDir);
    let auth;
    try {
      const extensionId = await getExtensionId(context);
      const panel = await context.newPage();
      // Authenticator and recorder both have to exist before the app's
      // first script runs.
      auth = await addPrfAuthenticatorWithId(context, panel);
      await installPrfRecorder(panel);
      await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
      // WebAuthn ceremonies require the page to hold focus.
      await panel.bringToFront();

      await onboardWithPasskey144(panel);

      // Mint the sentinel under 1.4.4, with 1.4.4's key.
      const armored = await encryptToSelfInWorkspace(panel, PASSKEY_SECRET);
      expect(armored).toContain("BEGIN PGP MESSAGE");

      const masterProtection = await readMasterProtection(panel);
      expect(
        masterProtection.method,
        "1.4.4 must have written a PASSKEY master protection record -- if " +
          "this says `password`, the onboarding flow was driven wrong and " +
          "nothing below tests the PRF path",
      ).toBe("passkey");

      const keyring = await readStoreRecords(panel, STORAGE_KEYRING);
      expect(keyring.length, "1.4.4 generated exactly one key").toBe(1);
      const keyProtection = keyring[0].protection as Record<string, unknown>;
      expect(
        keyProtection.method,
        "the key 1.4.4 generated during passkey onboarding must itself be " +
          "passkey-protected, or the per-key test below is vacuous",
      ).toBe("passkey");

      const prfRecords = await drainPrfLog(panel);
      expect(
        prfRecords.length,
        "the real virtual authenticator must have performed at least one " +
          "PRF evaluation during onboarding",
      ).toBeGreaterThan(0);
      // Every observation of the same (credential, salt) pair must agree.
      // This is the property the replay in the second launch stands on;
      // if it did not hold, the whole approach would be invalid.
      for (const record of prfRecords) {
        const twin = prfRecords.find(
          (r) =>
            r.credentialId === record.credentialId && r.salt === record.salt,
        );
        expect(
          twin?.output,
          "PRF output must be a pure function of (credential, salt)",
        ).toBe(record.output);
      }
      // 1.4.4 seals the onboarding key with the MASTER credential and
      // salt (`prfReuse`), differing only in `storedSecret`. If that
      // ever stops being true the recorder will simply have two entries.
      expect(keyProtection.credentialId).toBe(masterProtection.credentialId);

      const credentials = await exportCredentials(auth);
      expect(
        credentials.length,
        "the resident credential 1.4.4 registered must be exportable",
      ).toBe(1);

      await panel.close();
      phase1 = {
        tmpRoot,
        extensionDir,
        userDataDir,
        extensionId,
        armored,
        credentials,
        prfRecords,
        masterProtection,
        keyProtection,
      };
    } finally {
      if (auth) await removePrfAuthenticator(auth);
      await context.close();
    }

    // The upgrade: same path, same extension id, same storage partition.
    expect(
      existsSync(CURRENT_BUILD),
      `Current build missing at ${CURRENT_BUILD} -- run \`pnpm build\`.`,
    ).toBe(true);
    await rm(extensionDir, { recursive: true, force: true });
    await cp(CURRENT_BUILD, extensionDir, { recursive: true });
  });

  base.afterAll(async () => {
    if (phase1) await rm(phase1.tmpRoot, { recursive: true, force: true });
  });

  /**
   * Open the upgraded build against the 1.4.4 profile, with the carried
   * credential restored and the PRF replay armed.
   */
  async function openUpgraded(options: { corrupt?: boolean } = {}) {
    const context = await launchWithProfile(
      phase1.extensionDir,
      phase1.userDataDir,
    );
    const extensionId = await getExtensionId(context);
    // If this ever fails, every assertion below would be running against
    // a fresh, empty storage partition and would prove nothing.
    expect(
      extensionId,
      "extension id must be identical across the upgrade",
    ).toBe(phase1.extensionId);

    const panel = await context.newPage();
    const auth = await addPrfAuthenticatorWithId(context, panel);
    await restoreCredentials(auth, phase1.credentials);
    await installPrfReplay(panel, phase1.prfRecords, options);
    await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
    await panel.bringToFront();
    return { context, panel, auth };
  }

  base(
    "master protection: a passkey vault sealed by v1.4.4 opens under the current build",
    async () => {
      base.setTimeout(300_000);
      const { context, panel, auth } = await openUpgraded();
      try {
        await clickUnlockWithPasskey(panel);

        await base.step(
          "vault CONTENT decrypts under the derived session key",
          async () => {
            // Not "the lock screen went away" -- the passkey path has no
            // canary and dismisses the lock screen whatever wasm was
            // handed. The only honest evidence that
            // HKDF(PRF, storedSecret) reproduced 1.4.4's session key is
            // that a store 1.4.4 encrypted with it now decrypts.
            await goToKeys(panel);
            await expect(panel.getByText(PASSKEY_NAME).first()).toBeVisible({
              timeout: 20_000,
            });
          },
        );

        await base.step(
          "the current build asked for exactly what 1.4.4 stored",
          async () => {
            // The replay is exact-match, so a request the recorder never
            // saw would already have failed the unlock. Asserting it
            // explicitly turns a confusing timeout into a clear message.
            const requests = await readPrfRequests(panel);
            expect(requests.length).toBeGreaterThan(0);
            for (const request of requests) {
              expect(
                request.replayed,
                `the current build asked for PRF over credential ` +
                  `${request.credentialId} / salt ${request.salt}, which ` +
                  `1.4.4 never used -- it misread the stored blob`,
              ).toBe(true);
            }
            expect(requests[0].credentialId).toBe(
              phase1.masterProtection.credentialId,
            );
          },
        );

        await base.step(
          "the master-protection record is untouched by the upgrade",
          async () => {
            // A rewrite would be survivable but is worth knowing about:
            // it would mean a downgrade to 1.4.4 is no longer safe.
            const after = await readMasterProtection(panel);
            expect(after).toEqual(phase1.masterProtection);
          },
        );
      } finally {
        await removePrfAuthenticator(auth);
        await context.close();
      }
    },
  );

  base(
    "per-key protection: a key sealed by v1.4.4 under a passkey decrypts 1.4.4 ciphertext",
    async () => {
      base.setTimeout(300_000);
      const { context, panel, auth } = await openUpgraded();
      try {
        await clickUnlockWithPasskey(panel);
        await goToKeys(panel);
        await expect(panel.getByText(PASSKEY_NAME).first()).toBeVisible({
          timeout: 20_000,
        });

        await base.step("the key unlocks via unlockWithPrf", async () => {
          // A passkey-protected card's Unlock button runs the ceremony
          // directly -- no password field -- so this is `unlockWithPrf`
          // over 1.4.4's `[iv][ct]`, its `storedSecret`, and its key id
          // as AAD.
          await panel
            .getByRole("button", { name: "Unlock", exact: true })
            .click();
          await expect(panel.getByRole("button", { name: "Lock" })).toBeVisible(
            {
              timeout: 20_000,
            },
          );
        });

        await base.step(
          "and ciphertext minted by 1.4.4 decrypts with it",
          async () => {
            // THE assertion: an unsealed blob that merely looks intact
            // would still show an unlocked card. Only a real private key
            // recovers the sentinel.
            await decryptInWorkspace(panel, phase1.armored, PASSKEY_SECRET);
          },
        );

        await base.step(
          "the key's protection blob is untouched by the upgrade",
          async () => {
            const keyring = await readStoreRecords(panel, STORAGE_KEYRING);
            expect(keyring.length).toBe(1);
            expect(keyring[0].protection).toEqual(phase1.keyProtection);
          },
        );
      } finally {
        await removePrfAuthenticator(auth);
        await context.close();
      }
    },
  );

  base(
    "negative control: one bit wrong in the PRF output opens nothing",
    async () => {
      base.setTimeout(300_000);
      // Everything real except the PRF bytes: real ceremony, real
      // restored credential, the credentialId and prfSalt and
      // storedSecret 1.4.4 wrote -- and one flipped bit in the PRF
      // output. If the tests above could pass with this too, they would
      // be proving nothing about the PRF at all.
      const { context, panel, auth } = await openUpgraded({ corrupt: true });
      try {
        await clickUnlockWithPasskey(panel);

        // The lock screen still goes away (no canary on this path -- see
        // the block comment), so the evidence has to be that the vault is
        // unreadable: the wrong session key cannot decrypt the keyring.
        // The app now says exactly that, instead of rendering an empty
        // vault -- which for a passkey user with no password to fall back
        // on was indistinguishable from having lost every key.
        await expect(
          panel.getByText("Your vault could not be read"),
        ).toBeVisible();
        await expect(
          panel.getByText(PASSKEY_NAME),
          "a one-bit-wrong PRF output must NOT reveal the 1.4.4 key -- if " +
            "it does, the unlock is not actually keyed on the PRF and the " +
            "two tests above are worthless",
        ).toHaveCount(0);
        await expect(
          panel.getByRole("button", { name: "Unlock", exact: true }),
          "no key card should be listed at all",
        ).toHaveCount(0);
      } finally {
        await removePrfAuthenticator(auth);
        await context.close();
      }
    },
  );
});
