import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Page } from "@playwright/test";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import { strongRetainers } from "./heap-retainers";
import {
  goToKeys,
  lockMasterViaPalette,
  onboardWithPasswordSkipKey,
  unlockWithPassword,
} from "./helpers";
import { scanWasmMemory } from "./wasm-memory";
import {
  addPrfAuthenticatorWithId,
  drainPrfLog,
  installPrfRecorder,
  removePrfAuthenticator,
} from "./webauthn-carry";

// An OpenSSH private key is the app's THIRD class of crown-jewel secret,
// after the OpenPGP certs (KEY_STORE) and the CRX signing key
// (CRX_KEY_STORE). It has its own wasm store (`SSH_KEY_STORE` in
// gpg-wasm/src/age.rs), its own unlock exports
// (`unlockSshIdentityWith{Password,Prf}`) and its own drop
// (`dropSshIdentity`) -- and until this spec existed it had no memory
// evidence at all, so SECURITY.md's SSH isolation claims rested on
// reading the code.
//
// `crx-memory.spec.ts` is the model this follows, including its central
// argument: an "absent from memory" assertion is worth nothing on its own,
// because a needle that was never findable also reads as absent. So every
// absence here is paired with a moment the SAME needle IS present.
//
// WHAT IS IN SSH_KEY_STORE. Not raw key bytes: `normalize_openssh_identity`
// decrypts the user's key and re-serializes it as an *unencrypted OpenSSH
// PEM*, and that text is what gets sealed and, on unlock, what the store
// holds. Measured against this build: for a key that had no passphrase the
// normalized text is byte-identical to the file `ssh-keygen` wrote -- the
// round trip preserves the checkint and the 70-column wrapping. That is
// why a slice of the source file's own base64 is a valid needle for wasm
// memory, and it is checked rather than assumed: every wasm test below
// asserts the needle IS found while the identity is unlocked.

const MASTER = "correct horse battery staple";
const KEY_PW = "ssh-identity-password-123";
/** Present on every screen (AppFooter), so it proves the heap scan works. */
const HEAP_CONTROL = "A privacy tool by";
/** A static string in the wasm data segment (see memory.spec.ts). */
const WASM_CONTROL = "gpg-wasm ok";

interface SshIdentity {
  /** OpenSSH private key file contents (no passphrase). */
  privateKey: string;
  /** The `-C` comment, which is the key's display name once imported. */
  comment: string;
  /**
   * A 24-character slice of the key file's base64 body that lies wholly
   * inside the ed25519 *seed* -- the 32 secret bytes -- and wholly inside
   * one wrapped line, so it is newline-free as both scanners require.
   *
   * Deliberately not "a line of the PEM": the first lines carry the
   * cleartext public half, which is published (and stored in the keyring
   * metadata), so a hit on them would prove nothing.
   */
  secretNeedle: string;
}

/**
 * Generate a throwaway ed25519 identity with `ssh-keygen` and derive a
 * needle that is unambiguously secret material.
 *
 * Generated per run rather than committed: no real key material lives in
 * this repo (`github-import.spec.ts` generates the same way).
 *
 * Deriving the needle:
 *  - The OpenSSH v1 body decodes to `...[pub blob]...[checkint][checkint]
 *    [keytype][pub][seed||pub][comment][pad]`, so the SECOND occurrence of
 *    the 32 public bytes is the tail of the 64-byte private field, and the
 *    seed sits in the 32 bytes before it.
 *  - Byte offsets map to base64 character offsets in groups of 3 -> 4, so
 *    the characters lying strictly inside the seed are
 *    `[ceil(seed/3)*4, floor((seed+32)/3)*4)`.
 *  - That window is then clipped to a single wrapped line.
 */
function generateSshIdentity(): SshIdentity {
  const dir = mkdtempSync(path.join(tmpdir(), "pgp-e2e-ssh-mem-"));
  try {
    const comment = "e2e-ssh-mem";
    const file = path.join(dir, comment);
    execFileSync("ssh-keygen", [
      ...["-t", "ed25519"],
      ...["-N", ""],
      ...["-C", comment],
      ...["-f", file],
      "-q",
    ]);
    const privateKey = readFileSync(file, "utf8");
    const publicLine = readFileSync(`${file}.pub`, "utf8").trim();

    const lines = privateKey.trim().split("\n").slice(1, -1);
    const stream = lines.join("");
    const body = Buffer.from(stream, "base64");
    // An `ssh-ed25519` blob is [4]["ssh-ed25519"][4][32 pub]; 19 = 4+11+4.
    const pub = Buffer.from(publicLine.split(/\s+/)[1], "base64").subarray(19);
    const firstPub = body.indexOf(pub);
    const secondPub = body.indexOf(pub, firstPub + 1);
    expect(
      secondPub,
      "the public bytes must appear twice (public section + private field)",
    ).toBeGreaterThan(firstPub);
    const seed = secondPub - 32;

    const from = Math.ceil(seed / 3) * 4;
    const to = Math.floor((seed + 32) / 3) * 4;
    // Keep the window inside ONE wrapped line: a needle that straddled a
    // wrap would have to match the newline too. The seed's ~40 characters
    // can fall either side of a 70-column break, so take the longer of the
    // two pieces -- whichever side it lands on, one of them is >= 20
    // characters, i.e. >= 120 bits of a random seed.
    const breakAt = Math.min(to, (Math.floor(from / 70) + 1) * 70);
    const pieces = [stream.slice(from, breakAt), stream.slice(breakAt, to)];
    const needle = pieces.sort((a, b) => b.length - a.length)[0];
    expect(
      needle.length,
      "the needle must be a long enough slice of the 32-byte seed",
    ).toBeGreaterThanOrEqual(20);
    const secretNeedle = needle.slice(0, 24);

    // The needle must be secret: not part of the published half, and
    // present in the file exactly once, so a hit in wasm is this key's
    // seed rather than a coincidence of the encoding.
    expect(
      publicLine.includes(secretNeedle),
      "the needle must not be part of the public key line",
    ).toBe(false);
    expect(privateKey.indexOf(secretNeedle)).toBe(
      privateKey.lastIndexOf(secretNeedle),
    );
    return { privateKey, comment, secretNeedle };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Drive the private-key import UI to the protection step with `key`
 *  loaded (adapted from `github-import.spec.ts`'s local helper). */
async function pasteSshIdentity(panel: Page, key: SshIdentity): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Import Key" }).click();
  await panel
    .locator('input[accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"]')
    .setInputFiles({
      name: "id_ed25519",
      mimeType: "text/plain",
      buffer: Buffer.from(key.privateKey, "utf8"),
    });
  await panel.getByRole("button", { name: "Continue" }).click();
}

/** Finish an import that `pasteSshIdentity` started, under `protection`.
 *  Leaves the key on the Keys tab LOCKED: the import caches no unlock,
 *  which the callers assert by finding the key material absent from wasm
 *  at that point. */
async function completeSshImport(
  panel: Page,
  key: SshIdentity,
  protection: "password" | "passkey",
): Promise<void> {
  if (protection === "password") {
    await panel.locator('input[name="protection"]').nth(1).check();
    await panel.getByLabel("Password", { exact: true }).fill(KEY_PW);
    await panel.getByLabel("Confirm password").fill(KEY_PW);
  } else {
    await panel.locator('input[name="protection"]').nth(0).check();
  }
  await panel.getByRole("button", { name: "Import", exact: true }).click();
  await expect(panel.getByRole("region", { name: "Import key" })).toBeHidden({
    timeout: 30_000,
  });
  await expect(panel.getByText(key.comment).first()).toBeVisible();
}

/** Import an SSH identity end to end. */
async function importSshIdentity(
  panel: Page,
  key: SshIdentity,
  protection: "password" | "passkey" = "password",
): Promise<void> {
  await pasteSshIdentity(panel, key);
  await completeSshImport(panel, key, protection);
}

/** Unlock the (single) password-protected SSH identity on the Keys tab.
 *
 *  `exact: true` on every Lock/Unlock locator in this file, deliberately:
 *  Playwright's default accessible-name match is a case-insensitive
 *  SUBSTRING, so `{ name: "Lock" }` also matches the "Unlock" button --
 *  which makes "wait until it is unlocked" pass while the key is still
 *  locked. That silently defeated an early draft of this spec. */
async function unlockSshWithPassword(panel: Page): Promise<void> {
  await goToKeys(panel);
  await panel.getByRole("button", { name: "Unlock", exact: true }).click();
  const pw = panel.getByPlaceholder("Enter password");
  await pw.fill(KEY_PW);
  await pw.press("Enter");
  await expect(
    panel.getByRole("button", { name: "Lock", exact: true }),
  ).toBeVisible();
}

/** Assert the needle IS in wasm linear memory right now. This is the half
 *  that keeps every absence below honest. */
async function expectPresentInWasm(
  panel: Page,
  needle: string,
  why: string,
): Promise<void> {
  const counts = await scanWasmMemory(panel, [needle, WASM_CONTROL]);
  expect(counts[WASM_CONTROL], "control present (scan works)").toBeGreaterThan(
    0,
  );
  expect(counts[needle], why).toBeGreaterThan(0);
}

/** Assert the needle is gone from wasm -- and that the scan still works,
 *  so the zero is a zeroized key rather than a scan that stopped working. */
async function expectGoneFromWasm(
  panel: Page,
  needle: string,
  why: string,
): Promise<void> {
  await expect
    .poll(async () => (await scanWasmMemory(panel, [needle]))[needle], {
      timeout: 15_000,
      message: why,
    })
    .toBe(0);
  const after = await scanWasmMemory(panel, [WASM_CONTROL]);
  expect(
    after[WASM_CONTROL],
    "still scanning live wasm memory",
  ).toBeGreaterThan(0);
}

test("an unlocked SSH identity lives in wasm memory and is zeroized when it is locked", async ({
  panel,
}) => {
  const key = generateSshIdentity();

  await onboardWithPasswordSkipKey(panel, MASTER);
  await importSshIdentity(panel, key);

  await test.step("the import itself leaves nothing behind in wasm", async () => {
    // `normalize_openssh_identity` decrypts and re-serializes the key and
    // `protectSshIdentityWithPassword` seals it, all in `Zeroizing`
    // buffers, and the import caches no unlock. So between import and
    // unlock the key must not be resident at all.
    await expectGoneFromWasm(
      panel,
      key.secretNeedle,
      "the normalized key must not survive the import call",
    );
  });

  await test.step("positive control: unlocking makes the seed resident", async () => {
    await unlockSshWithPassword(panel);
    await expectPresentInWasm(
      panel,
      key.secretNeedle,
      "an unlocked identity's seed should be findable in SSH_KEY_STORE -- if this is 0 the needle is wrong and every absence in this file is vacuous",
    );
  });

  await test.step("locking the key drops the handle and zeroizes it", async () => {
    // The card's Lock button routes through `dropHandle`, which for a
    // `kind: "ssh"` entry calls `closeSshIdentity` -> `dropSshIdentity`
    // -> `SSH_KEY_STORE.remove`. A PGP-store drop here would be a no-op
    // and the needle would still be resident.
    await panel.getByRole("button", { name: "Lock", exact: true }).click();
    await expect(
      panel.getByRole("button", { name: "Unlock", exact: true }),
    ).toBeVisible();
    await expectGoneFromWasm(
      panel,
      key.secretNeedle,
      "a locked SSH identity must not remain in wasm memory",
    );
  });

  await test.step("at rest the key is an opaque blob", async () => {
    for (const area of ["local", "sync", "session"] as const) {
      const dump = JSON.stringify(await readStorage(panel, area));
      expect(
        dump.includes(key.secretNeedle),
        `SSH private key material must not be readable in chrome.storage.${area}`,
      ).toBe(false);
    }
  });
});

test("a master lock drops the SSH handle and wipes the key", async ({
  panel,
}) => {
  const key = generateSshIdentity();

  await onboardWithPasswordSkipKey(panel, MASTER);
  await importSshIdentity(panel, key);
  await unlockSshWithPassword(panel);
  await expectPresentInWasm(
    panel,
    key.secretNeedle,
    "positive control: the identity is unlocked, so its seed is resident",
  );

  // "Lock now" runs `doMasterLock`, which locks every key session. For an
  // SSH identity that means `lockAll` -> `dropHandle({ kind: "ssh" })`,
  // exactly as it does for an OpenPGP cert.
  await lockMasterViaPalette(panel);
  await expectGoneFromWasm(
    panel,
    key.secretNeedle,
    "a master lock must wipe the SSH identity out of wasm memory",
  );

  // ...and it stays gone across a re-unlock of the VAULT: unlocking the
  // master does not re-open key handles.
  await unlockWithPassword(panel, MASTER);
  await expectGoneFromWasm(
    panel,
    key.secretNeedle,
    "unlocking the vault must not re-open the SSH identity",
  );
});

test("the decrypted SSH private key never reaches the JS heap", async ({
  panel,
}) => {
  const key = generateSshIdentity();

  await onboardWithPasswordSkipKey(panel, MASTER);

  await test.step("needle sanity: the key text is findable while the import step holds it", async () => {
    // Pins the needle down for the heap scanner. The key file DOES cross
    // into JS as a string on the import path -- `ImportKeyPage` keeps the
    // loaded text in `secretArmorRef` so the user can retry with a
    // passphrase -- and an immutable JS String cannot be zeroized. What
    // must be true is that it does not OUTLIVE the import.
    await pasteSshIdentity(panel, key);
    const counts = await scanJsHeap(panel, [key.secretNeedle]);
    expect(
      counts[key.secretNeedle],
      "the loaded key text should be findable while the import step holds it",
    ).toBeGreaterThan(0);
  });

  await test.step("finishing the import drops the key text", async () => {
    // `handleImportSsh` nulls `secretArmorRef` on success, and
    // `importSshIdentity` zeroizes the bytes it encoded for wasm.
    await completeSshImport(panel, key, "password");
    const counts = await scanJsHeap(panel, [key.secretNeedle, HEAP_CONTROL]);
    expect(
      counts[HEAP_CONTROL],
      "control present (scan works)",
    ).toBeGreaterThan(0);
    // Retainer-aware first, so a failure names the object still holding
    // it rather than just reporting a count.
    const { count, report } = await strongRetainers(panel, key.secretNeedle);
    expect(count, `still retained by:${report}`).toBe(0);
    expect(
      counts[key.secretNeedle],
      "the imported SSH key text must not survive the import page closing",
    ).toBe(0);
  });

  // A fresh JS context, so what follows measures the unlock cycle alone
  // and cannot be satisfied by leftovers from the import.
  await panel.reload();
  await unlockWithPassword(panel, MASTER);

  await test.step("unlocking puts the key in wasm and NOT in the heap", async () => {
    await unlockSshWithPassword(panel);
    // The positive control is in wasm, not the heap: the whole claim is
    // that the two never hold the key at the same time.
    await expectPresentInWasm(
      panel,
      key.secretNeedle,
      "positive control: the identity is unlocked",
    );
    const counts = await scanJsHeap(panel, [key.secretNeedle, HEAP_CONTROL]);
    expect(
      counts[HEAP_CONTROL],
      "control present (scan works)",
    ).toBeGreaterThan(0);
    expect(
      counts[key.secretNeedle],
      "an unlocked SSH identity must not be readable from the JS heap -- unlock returns an opaque handle",
    ).toBe(0);
  });
});

// ── the lock race, on the passkey path ───────────────────────────────

/**
 * Hold the NEXT passkey ceremony open.
 *
 * The virtual authenticator cannot be made to pause and then resume:
 * with `automaticPresenceSimulation` off `navigator.credentials.get`
 * stays pending, but turning it back on does NOT resume the request
 * already waiting (measured against this build -- the ceremony never
 * completed and the card stayed locked). So the delay is installed one
 * level up: a wrapper around `navigator.credentials.get` that waits for
 * the test to release it before calling through.
 *
 * Nothing about the ceremony is faked. The real virtual authenticator
 * runs it, produces a real PRF output, and the app unlocks with it; the
 * only thing the test controls is WHEN it starts -- which is exactly the
 * variable this race is about. A real passkey ceremony is seconds of user
 * interaction; this makes that window precise instead of racy.
 *
 * Installed after {@link installPrfRecorder}, so the recorder still sees
 * (and logs) every ceremony that completes.
 */
async function installCeremonyGate(panel: Page): Promise<void> {
  await panel.addInitScript(`(() => {
  const state = { hold: false, entered: 0 };
  Object.defineProperty(window, "__ceremonyGate", {
    value: state,
    configurable: true,
  });
  const container = navigator.credentials;
  const original = container.get.bind(container);
  Object.defineProperty(container, "get", {
    configurable: true,
    writable: true,
    value: async function (options) {
      state.entered += 1;
      while (state.hold) {
        await new Promise((r) => setTimeout(r, 25));
      }
      return original(options);
    },
  });
})();`);
}

/** Arm (or release) the gate. While armed, a ceremony the app starts sits
 *  in the wrapper instead of reaching the authenticator. */
function holdCeremonies(panel: Page, hold: boolean): Promise<void> {
  return panel.evaluate((h) => {
    (
      window as unknown as { __ceremonyGate: { hold: boolean } }
    ).__ceremonyGate.hold = h;
  }, hold);
}

/** How many ceremonies the app has STARTED in this document -- proof that
 *  the Unlock click really reached `navigator.credentials.get`. */
function ceremoniesStarted(panel: Page): Promise<number> {
  return panel.evaluate(
    () =>
      (window as unknown as { __ceremonyGate?: { entered: number } })
        .__ceremonyGate?.entered ?? 0,
  );
}

/** How many ceremonies have COMPLETED (with a PRF result) since the last
 *  {@link drainPrfLog}. */
function prfCeremonyCount(panel: Page): Promise<number> {
  return panel.evaluate(
    () => (window as unknown as { __prfLog?: unknown[] }).__prfLog?.length ?? 0,
  );
}

test("a passkey unlock that resolves after a master lock leaves nothing in wasm", async ({
  context,
  extensionId,
}) => {
  const key = generateSshIdentity();

  // Both init scripts must be installed before the first navigation. The
  // recorder only observes; the gate only delays.
  const panel = await context.newPage();
  await installPrfRecorder(panel);
  await installCeremonyGate(panel);
  const auth = await addPrfAuthenticatorWithId(context, panel);
  await panel.goto(`chrome-extension://${extensionId}/sidepanel.html`);
  // WebAuthn ceremonies require the page to hold focus.
  await panel.bringToFront();

  try {
    await onboardWithPasswordSkipKey(panel, MASTER);
    await importSshIdentity(panel, key, "passkey");

    await test.step("positive control: a passkey unlock puts the identity in wasm", async () => {
      await goToKeys(panel);
      await panel.getByRole("button", { name: "Unlock", exact: true }).click();
      await expect(
        panel.getByRole("button", { name: "Lock", exact: true }),
      ).toBeVisible({ timeout: 20_000 });
      await expectPresentInWasm(
        panel,
        key.secretNeedle,
        "a passkey-unlocked identity's seed should be findable in SSH_KEY_STORE",
      );
    });

    await test.step("a master lock drops the passkey-protected handle too", async () => {
      await lockMasterViaPalette(panel);
      await expectGoneFromWasm(
        panel,
        key.secretNeedle,
        "a master lock must wipe a passkey-protected SSH identity out of wasm",
      );
      await unlockWithPassword(panel, MASTER);
    });

    // `useKeySession`'s INVARIANT 1: an unlock captures the lock
    // generation before it awaits and re-checks it before inserting, so a
    // ceremony that completes after a lock has its handle DROPPED rather
    // than stored. The unit tests pin that bookkeeping; what they cannot
    // show is that the key is really absent from wasm afterwards -- by
    // then the wasm unlock has genuinely happened, the handle exists, and
    // it is dropped a tick later.
    await test.step("control: with no lock in between, the held ceremony DOES store the key", async () => {
      // The same hold-and-release, minus the lock. Without this half the
      // absence asserted below could just mean the ceremony never
      // finished and no key ever reached wasm.
      await goToKeys(panel);
      await drainPrfLog(panel);
      await holdCeremonies(panel, true);
      const startedBefore = await ceremoniesStarted(panel);
      await panel.getByRole("button", { name: "Unlock", exact: true }).click();
      await expect
        .poll(() => ceremoniesStarted(panel))
        .toBeGreaterThan(startedBefore);
      // Held, so nothing has been unlocked yet.
      expect(await prfCeremonyCount(panel)).toBe(0);
      await expectGoneFromWasm(
        panel,
        key.secretNeedle,
        "nothing is in wasm while the ceremony is still held",
      );

      await holdCeremonies(panel, false);
      await expect(
        panel.getByRole("button", { name: "Lock", exact: true }),
      ).toBeVisible({ timeout: 20_000 });
      expect(
        await prfCeremonyCount(panel),
        "the ceremony completed once the gate opened",
      ).toBeGreaterThan(0);
      await expectPresentInWasm(
        panel,
        key.secretNeedle,
        "a held-then-released ceremony stores the key like any other unlock",
      );

      // Back to a locked, empty state for the race itself.
      await panel.getByRole("button", { name: "Lock", exact: true }).click();
      await expect(
        panel.getByRole("button", { name: "Unlock", exact: true }),
      ).toBeVisible();
      await expectGoneFromWasm(
        panel,
        key.secretNeedle,
        "locking the key again clears wasm before the race starts",
      );
    });

    await test.step("the race: lock, THEN let the ceremony finish", async () => {
      await drainPrfLog(panel);
      await holdCeremonies(panel, true);
      const startedBefore = await ceremoniesStarted(panel);
      await panel.getByRole("button", { name: "Unlock", exact: true }).click();
      await expect
        .poll(() => ceremoniesStarted(panel))
        .toBeGreaterThan(startedBefore);
      expect(await prfCeremonyCount(panel)).toBe(0);

      // The lock lands while the ceremony is still in flight -- with an
      // EMPTY handle map, which is the state App.tsx's "UNCONDITIONAL
      // lockAll" comment describes: there is nothing to drop, only a
      // generation to bump.
      await lockMasterViaPalette(panel);

      await holdCeremonies(panel, false);
      // NON-VACUITY: the ceremony really did complete, after the lock. If
      // this stayed 0 the test would be asserting the absence of a key
      // that was never unlocked in the first place.
      await expect
        .poll(() => prfCeremonyCount(panel), { timeout: 20_000 })
        .toBeGreaterThan(0);

      // So `unlockSshIdentityWithPrf` ran and produced a live
      // SSH_KEY_STORE entry -- and the generation re-check dropped it.
      await expectGoneFromWasm(
        panel,
        key.secretNeedle,
        "an unlock that resolved after a lock must not leave the identity in wasm",
      );
      // The lock screen is still up: nothing re-entered the unlocked UI
      // behind it.
      await expect(panel.getByLabel("Master password")).toBeVisible();
    });
  } finally {
    await removePrfAuthenticator(auth);
    await panel.close();
  }
});
