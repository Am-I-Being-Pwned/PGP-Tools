import { createPrivateKey, generateKeyPairSync } from "node:crypto";

import { zipSync } from "fflate";

import { expect, readStorage, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import {
  completeCrxSigningKeyImport,
  enableCrxSigning,
  importCrxSigningKey,
  pasteCrxSigningKey,
  seedVault,
  setWorkspaceMode,
  unlockWithPassword,
} from "./helpers";
import { scanWasmMemory } from "./wasm-memory";

// CRX signing (off by default) puts a *raw RSA-2048 PKCS#8 DER private
// key* in WASM's CRX_KEY_STORE -- a second class of crown-jewel secret
// alongside the OpenPGP certs, with its own store, its own unlock paths
// (`unlockCrxWith*`) and its own `dropCrxKey`. gpg-wasm/src/crx.rs holds
// it as `Zeroizing<Vec<u8>>`; lib/pgp/wasm-secrets.ts promises "the
// private key crosses to JS only as its public half".
//
// This spec generates a throwaway RSA key at runtime (never a repo
// fixture), so we know its bytes, and checks both halves of that promise:
//
//  * JS heap: across unlock -> sign -> drop, a base64 slice of the key's
//    own PEM must not appear in a V8 heap snapshot.
//  * WASM: the same key's secret prime `p`, as raw bytes, IS present in
//    WASM linear memory while a CRX_KEY_STORE handle is open, and must be
//    GONE once the handle is dropped. The present-then-absent pair is the
//    positive control -- without it a zero could just mean "the needle was
//    never findable".
//
// The PEM does pass through JS as an immutable String at import time (see
// importCrxKeyWithPassword's @secret-handling note -- it cannot be
// zeroized), so the heap test pins the needle down there first, then shows
// the import page dropping it, then reloads for a clean context before
// exercising unlock/sign/drop.

const MASTER = "correct horse battery staple";
const CRX_PW = "crx-signing-key-password-123";
const LABEL = "E2E CRX Key";
/** Present on every screen (AppFooter), so it proves the heap scan works. */
const HEAP_CONTROL = "A privacy tool by";
/** A static string in the wasm data segment (see memory.spec.ts). */
const WASM_CONTROL = "gpg-wasm ok";

/** V8 truncates a string node's recorded value at 1024 characters, so a
 *  needle from beyond that offset is unfindable regardless of retention --
 *  see the note in heap.ts. Keep a small margin. */
const SNAPSHOT_VALUE_LIMIT = 1020;

/** A throwaway RSA-2048 signing key plus needles derived from it:
 *  - `pemNeedle`: one 64-char base64 line of the PEM body, taken as deep
 *    into the key as the snapshot truncation limit allows (past the
 *    modulus, so it covers genuinely secret material) and newline-free as
 *    scanJsHeap requires.
 *  - `primeNeedle`: 24 raw bytes from the middle of the secret prime `p`,
 *    latin1-encoded so it lines up with how scanWasmMemory stringifies
 *    linear memory. `p`'s interior bytes appear verbatim in the PKCS#8
 *    DER that CRX_KEY_STORE holds. */
function generateCrxSigningKey(): {
  pem: string;
  pemNeedle: string;
  primeNeedle: string;
} {
  const { privateKey: pem, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const body = pem.trim().split("\n").slice(1, -1);
  const usable = body.filter(
    (line) => pem.indexOf(line) + line.length <= SNAPSHOT_VALUE_LIMIT,
  );
  // The deepest still-findable line. For a 2048-bit PKCS#8 body that lands
  // past the modulus and the public exponent, inside the private exponent /
  // primes -- so a hit really would be secret material.
  const pemNeedle = usable[usable.length - 1];
  expect(pemNeedle.length).toBeGreaterThanOrEqual(40);
  expect(
    publicKey.includes(pemNeedle),
    "the PEM needle must not be part of the public half",
  ).toBe(false);

  const jwk = createPrivateKey(pem).export({ format: "jwk" }) as { p: string };
  const p = Buffer.from(jwk.p, "base64url");
  const primeNeedle = p.subarray(40, 64).toString("latin1");
  expect(primeNeedle.length).toBe(24);
  return { pem, pemNeedle, primeNeedle };
}

/** A minimal packed "extension": a zip whose central directory lists a
 *  manifest.json, which is all `zipHasManifest` looks for. */
function extensionZip(): Buffer {
  const manifest = JSON.stringify({
    manifest_version: 3,
    name: "E2E Fixture",
    version: "1.0.0",
  });
  return Buffer.from(
    zipSync({ "manifest.json": new TextEncoder().encode(manifest) }),
  );
}

test("the CRX signing key does not reach the JS heap across unlock → sign → drop", async ({
  panel,
}) => {
  const { pem, pemNeedle } = generateCrxSigningKey();

  await seedVault(panel, MASTER);
  await enableCrxSigning(panel);

  await test.step("needle sanity: the PEM is findable while it sits in the paste box", async () => {
    // Pins the needle down. Without this, the zeroes asserted later could
    // just mean the needle was never findable in the first place.
    await pasteCrxSigningKey(panel, pem, LABEL);
    const counts = await scanJsHeap(panel, [pemNeedle]);
    expect(
      counts[pemNeedle],
      "a base64 slice of the pasted PEM should be findable while it is on screen",
    ).toBeGreaterThan(0);
  });

  await test.step("finishing the import already drops the pasted PEM", async () => {
    await completeCrxSigningKeyImport(panel, CRX_PW);
    // ImportKeyPage holds the pasted armor in a ref and blanks both the ref
    // and the textarea's DOM value in `resetAndClose` -- so it goes even
    // though the PEM crossed into JS as an unzeroizable String.
    const counts = await scanJsHeap(panel, [pemNeedle, HEAP_CONTROL]);
    expect(
      counts[HEAP_CONTROL],
      "control present (scan works)",
    ).toBeGreaterThan(0);
    expect(
      counts[pemNeedle],
      "the pasted CRX PEM must not survive the import page closing",
    ).toBe(0);
  });

  await test.step("at rest the key is an opaque blob", async () => {
    const local = await readStorage(panel, "local");
    const blob = local.pgp_crx_keys;
    expect(Object.keys(blob as object).sort()).toEqual(["ciphertext", "iv"]);
    for (const area of ["local", "sync", "session"] as const) {
      const dump = JSON.stringify(await readStorage(panel, area));
      expect(
        dump.includes(pemNeedle),
        `CRX private key material must not be readable in chrome.storage.${area}`,
      ).toBe(false);
    }
  });

  // A fresh JS context, so what follows measures the unlock/sign/drop cycle
  // alone and cannot be satisfied by leftovers from the import.
  await panel.reload();
  await unlockWithPassword(panel, MASTER);

  await test.step("sign an extension zip with the CRX key", async () => {
    await setWorkspaceMode(panel, "Sign");
    // The workspace DropZone's hidden input is the only file input with no
    // `accept` list (the contact drop zone and import page both have one).
    await panel
      .locator('input[type="file"]:not([accept])')
      .first()
      .setInputFiles({
        name: "e2e-extension.zip",
        mimeType: "application/zip",
        buffer: extensionZip(),
      });
    // A manifest-bearing zip flips the sign flow to CRX and auto-selects
    // the only CRX key.
    const signButton = panel.getByRole("button", {
      name: "Sign for Web Store",
    });
    await expect(signButton).toBeVisible({ timeout: 15_000 });
    await signButton.click();
    // Password-protected CRX keys prompt inline; submitting runs
    // unlockCrxWithPassword -> signCrxWithHandle -> dropCrxKey.
    const pw = panel.getByPlaceholder("Enter key password");
    await expect(pw).toBeVisible();
    await pw.fill(CRX_PW);
    await pw.press("Enter");
    // The Save button only renders for a produced .crx.
    await expect(
      panel.getByRole("button", { name: /^Save .*\.crx$/ }),
    ).toBeVisible({ timeout: 30_000 });
  });

  await test.step("the RSA private key never entered the JS heap", async () => {
    const counts = await scanJsHeap(panel, [pemNeedle, HEAP_CONTROL]);
    expect(
      counts[HEAP_CONTROL],
      "control present (scan works)",
    ).toBeGreaterThan(0);
    expect(
      counts[pemNeedle],
      "CRX RSA private key material must not be retained in the JS heap",
    ).toBe(0);
  });
});

test("an unlocked CRX key is zeroized out of WASM memory when its handle is dropped", async ({
  panel,
}) => {
  const { pem, primeNeedle } = generateCrxSigningKey();

  await seedVault(panel, MASTER);
  await enableCrxSigning(panel);
  await importCrxSigningKey(panel, pem, CRX_PW, LABEL);

  // The bulk-export flow is the one UI path that holds a CRX_KEY_STORE
  // handle open across a user step (ExportKeysPage keeps them for the life
  // of the flow), which is what makes a positive control possible.
  await test.step("open the export flow and unlock the CRX key", async () => {
    await panel.getByRole("tab", { name: "Settings" }).click();
    await panel.getByRole("button", { name: "Export all keys" }).click();
    const inputs = panel.getByPlaceholder("Key password");
    await expect(inputs.first()).toBeVisible();
    const before = await inputs.count();
    // CRX rows render after the PGP key rows, so the last one is the CRX
    // key's. Its row's password input disappears once unlocked.
    await inputs.last().fill(CRX_PW);
    await inputs.last().press("Enter");
    await expect.poll(() => inputs.count(), { timeout: 30_000 }).toBe(
      before - 1,
    );
  });

  await test.step("positive control: the secret prime is live in WASM memory", async () => {
    const counts = await scanWasmMemory(panel, [primeNeedle, WASM_CONTROL]);
    expect(
      counts[WASM_CONTROL],
      "control present (scanning live wasm memory)",
    ).toBeGreaterThan(0);
    expect(
      counts[primeNeedle],
      "an unlocked CRX key's DER should be findable in CRX_KEY_STORE -- if this is 0 the needle is wrong and the negative check below is vacuous",
    ).toBeGreaterThan(0);
  });

  await test.step("closing the flow drops the handle and zeroizes the key", async () => {
    // Unmount runs closeCrxKey for every handle the flow opened. Escape
    // rather than the header Back button: with a key list this long the
    // header scrolls out of the viewport.
    await panel.keyboard.press("Escape");
    await expect(
      panel.getByRole("button", { name: "Export all keys" }),
    ).toBeVisible();
    await expect(panel.getByPlaceholder("Key password")).toHaveCount(0);
    await expect
      .poll(
        async () => (await scanWasmMemory(panel, [primeNeedle]))[primeNeedle],
        { timeout: 15_000 },
      )
      .toBe(0);
    // ...and we are still scanning live wasm memory, so the zero above is
    // a zeroized key rather than a scan that stopped working.
    const after = await scanWasmMemory(panel, [WASM_CONTROL]);
    expect(after[WASM_CONTROL]).toBeGreaterThan(0);
  });
});
