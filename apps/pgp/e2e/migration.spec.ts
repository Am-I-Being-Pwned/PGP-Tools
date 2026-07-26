import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { goToKeys, seedVault, unlockWithPassword } from "./helpers";
import { TEST_KEYS } from "./keys";

/**
 * UPGRADE PATH: a vault written by a release that predates domain
 * separation must still open, and must be upgraded in place.
 *
 * Why this exists as an e2e rather than a unit test: the unit suites
 * (`lib/storage/envelope.test.ts`, `history.test.ts`, `upgrade.test.ts`)
 * exercise the migration CONTROL FLOW against `fake-store-crypto.ts`, a
 * test double that models the legacy envelope as an identity transform.
 * That proves "try domain, fall back to legacy, re-seal" branches
 * correctly -- it cannot prove that a real AES-256-GCM blob written by
 * the shipped v1.4.3 code actually decrypts under the new code path.
 * `encrypt_contacts` changed signature (borrowed -> owned `Vec<u8>`) in
 * the same change set, which is exactly the class of thing a fake hides.
 *
 * So this test seals with the REAL legacy primitive, through the REAL
 * wasm instance, and drives the REAL app over it. Users have these blobs
 * on disk; this is the only test that looks at what they actually have.
 *
 * The legacy blob is produced by round-tripping the app's own current
 * blob rather than by hand-building the plaintext -- that way the padding
 * and JSON shape are whatever the app really writes, and the test cannot
 * drift from the format by guessing at it.
 */

const MASTER = "correct horse battery staple";
const CONTACT = TEST_KEYS.find((k) => k.slug === "standard");
if (!CONTACT) throw new Error("missing `standard` fixture key");
const CONTACTS_KEY = "pgp_public_contacts";

/**
 * Locate the wasm-bindgen glue chunk from the page's own entry script, so
 * we can drive the LIVE instance (with its live contacts session) rather
 * than a fresh one. Same technique as `hostile-dep.spec.ts`; kept local so
 * the two specs stay independent.
 */
async function wasmChunkUrl(page: Page): Promise<string> {
  const url = await page.evaluate(async () => {
    const entry = document.querySelector<HTMLScriptElement>(
      'script[type="module"][src]',
    );
    if (!entry) return null;
    const source = await fetch(entry.src).then((r) => r.text());
    const match = /gpg_wasm-[A-Za-z0-9_-]+\.js/.exec(source);
    return match ? new URL(match[0], entry.src).href : null;
  });
  if (url === null) throw new Error("wasm glue chunk not locatable");
  return url;
}

/** Re-seal the contacts blob under the pre-domain-separation envelope. */
async function downgradeContactsToLegacy(panel: Page): Promise<void> {
  const url = await wasmChunkUrl(panel);
  const ok = await panel.evaluate(
    async ({ u, key }: { u: string; key: string }) => {
      const mod = (await import(/* @vite-ignore */ u)) as {
        decryptStore: (d: string, ct: Uint8Array, iv: Uint8Array) => Uint8Array;
        encryptContacts: (pt: Uint8Array) => Uint8Array;
      };
      const b64ToBytes = (s: string) =>
        Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const bytesToB64 = (b: Uint8Array) => {
        // Chunked: String.fromCharCode(...b) overflows the stack on a
        // padded multi-KB blob.
        let out = "";
        for (let i = 0; i < b.length; i += 0x8000) {
          out += String.fromCharCode(...b.subarray(i, i + 0x8000));
        }
        return btoa(out);
      };

      const stored = (await chrome.storage.local.get(key))[key] as {
        iv: string;
        ciphertext: string;
      };
      // Decrypt through the CURRENT scheme to recover the exact plaintext
      // the app writes, padding and all.
      const plaintext = mod.decryptStore(
        key,
        b64ToBytes(stored.ciphertext),
        b64ToBytes(stored.iv),
      );
      // Re-seal it the way a pre-domain-separation release would have.
      const packed = mod.encryptContacts(plaintext);
      await chrome.storage.local.set({
        [key]: {
          iv: bytesToB64(packed.subarray(0, 12)),
          ciphertext: bytesToB64(packed.subarray(12)),
        },
      });
      return true;
    },
    { u: url, key: CONTACTS_KEY },
  );
  expect(ok, "legacy re-seal ran").toBe(true);
}

/** Which envelope does the stored contacts blob currently use? */
async function envelopeScheme(
  panel: Page,
): Promise<{ domain: boolean; legacy: boolean }> {
  const url = await wasmChunkUrl(panel);
  return panel.evaluate(
    async ({ u, key }: { u: string; key: string }) => {
      const mod = (await import(/* @vite-ignore */ u)) as {
        decryptStore: (d: string, ct: Uint8Array, iv: Uint8Array) => Uint8Array;
        decryptContacts: (ct: Uint8Array, iv: Uint8Array) => Uint8Array;
      };
      const b64ToBytes = (s: string) =>
        Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const stored = (await chrome.storage.local.get(key))[key] as {
        iv: string;
        ciphertext: string;
      };
      const ct = b64ToBytes(stored.ciphertext);
      const iv = b64ToBytes(stored.iv);
      let domain = false;
      let legacy = false;
      try {
        mod.decryptStore(key, ct, iv);
        domain = true;
      } catch {
        /* not domain-sealed */
      }
      try {
        mod.decryptContacts(ct, iv);
        legacy = true;
      } catch {
        /* not legacy-sealed */
      }
      return { domain, legacy };
    },
    { u: url, key: CONTACTS_KEY },
  );
}

test("a vault sealed by a pre-domain-separation release opens and upgrades in place", async ({
  panel,
}) => {
  // Onboarding runs Argon2id at 64 MB, plus a lock/unlock cycle.
  test.setTimeout(180_000);

  await seedVault(panel, MASTER, [CONTACT.publicKey]);
  await goToKeys(panel);
  await expect(panel.getByText(CONTACT.label).first()).toBeVisible();

  await test.step("the app writes the domain-bound envelope today", async () => {
    const scheme = await envelopeScheme(panel);
    expect(scheme, "freshly written blob is domain-sealed only").toEqual({
      domain: true,
      legacy: false,
    });
  });

  await test.step("rewrite it the way a pre-upgrade release would have", async () => {
    await downgradeContactsToLegacy(panel);
    const scheme = await envelopeScheme(panel);
    // Positive control: the downgrade really did land, and it is genuinely
    // the old envelope -- not merely something the new path fails to read.
    expect(scheme, "blob is now legacy-sealed only").toEqual({
      domain: false,
      legacy: true,
    });
    // The canary must not be readable as plaintext either way.
    const dump = JSON.stringify(await readStorage(panel, "local"));
    expect(dump.includes(CONTACT.fingerprint)).toBe(false);
  });

  await test.step("after reload + unlock the legacy vault still opens", async () => {
    await panel.reload();
    await unlockWithPassword(panel, MASTER);
    await goToKeys(panel);
    // THE assertion users care about: their contacts survive the upgrade.
    await expect(panel.getByText(CONTACT.label).first()).toBeVisible({
      timeout: 15_000,
    });
  });

  await test.step("and the blob is upgraded in place, not left legacy forever", async () => {
    // `normalizeContactsPadding` runs on unlock and owns the upgrade for a
    // store the user only ever reads. Poll rather than assume it has
    // already flushed -- it is fire-and-forget from App's perspective.
    await expect
      .poll(async () => (await envelopeScheme(panel)).domain, {
        timeout: 15_000,
        message: "legacy blob should be re-sealed under the domain scheme",
      })
      .toBe(true);
    const scheme = await envelopeScheme(panel);
    expect(scheme, "upgraded blob is domain-sealed only").toEqual({
      domain: true,
      legacy: false,
    });
  });

  await test.step("the contact is still there after one more round trip", async () => {
    await panel.reload();
    await unlockWithPassword(panel, MASTER);
    await goToKeys(panel);
    await expect(panel.getByText(CONTACT.label).first()).toBeVisible({
      timeout: 15_000,
    });
  });
});
