import { expect, test } from "./fixtures";
import { scanJsHeap } from "./heap";
import {
  decryptInWorkspace,
  importPrivateKey,
  lockOnlyKey,
  onboardWithPasswordSkipKey,
  signInWorkspace,
  unlockOnlyKey,
} from "./helpers";
import { PRIVATE_KEY_FIXTURE } from "./private-key";

// The point of running crypto in WASM is to keep private key material out
// of the GC-managed JS heap. This walks the full lifecycle of a key whose
// secret we know (a distinctive base64 slice) and asserts, at every stage,
// that the secret is NOT retained in the V8 heap -- only the encrypted-at-
// rest blob is. A control string that IS present proves the scan works.

const MASTER = "correct horse battery staple";
const IMPORT_PW = "import-protect-password-123";
const { name, secretNeedle, privateKey, encryptedMessage, decryptedPlaintext } =
  PRIVATE_KEY_FIXTURE;

test("private key material stays out of the JS heap across the lifecycle", async ({
  panel,
}) => {
  const assertClean = async (stage: string, control: string = name) => {
    const counts = await scanJsHeap(panel, [secretNeedle, control]);
    expect(
      counts[control],
      `${stage}: control present (scan works)`,
    ).toBeGreaterThan(0);
    expect(
      counts[secretNeedle],
      `${stage}: secret key material must not be in the JS heap`,
    ).toBe(0);
  };

  // One key only, so unlock/lock/sign target it unambiguously.
  await onboardWithPasswordSkipKey(panel, MASTER);
  await importPrivateKey(panel, privateKey, IMPORT_PW, name);

  await test.step("after import (armor passed through JS)", () =>
    assertClean("import"));

  await test.step("after unlock (blob decrypted in WASM)", async () => {
    await unlockOnlyKey(panel, IMPORT_PW);
    await assertClean("unlock");
  });

  await test.step("after sign (WASM handle)", async () => {
    await signInWorkspace(panel, "a message to sign");
    await assertClean("sign");
  });

  await test.step("after decrypt (WASM handle; plaintext crosses to JS)", async () => {
    await decryptInWorkspace(panel, encryptedMessage, decryptedPlaintext);
    // The decrypted plaintext IS in JS by design -- use it as the control.
    await assertClean("decrypt", decryptedPlaintext);
  });

  await test.step("after in-app lock (key dropped from WASM)", async () => {
    await lockOnlyKey(panel);
    await assertClean("lock");
  });

  await test.step("after re-unlock", async () => {
    await unlockOnlyKey(panel, IMPORT_PW);
    await assertClean("re-unlock");
  });
});
