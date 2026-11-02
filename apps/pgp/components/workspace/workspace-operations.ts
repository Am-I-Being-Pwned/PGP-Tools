import { presentError } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import type { RunContext } from "./operations/context";
import { decrypt } from "./operations/decrypt";
import { encrypt } from "./operations/encrypt";
import { sign, verify } from "./operations/sign";
import type { Outcome } from "./workspace-state";

/**
 * Workspace operations, each returning an {@link Outcome}; no React state.
 * Plaintext is read via `getInput()` at the point of use and never hoisted
 * into anything that outlives the run (SECURITY.md §8.11).
 */

export {
  AUTO_RUN_MAX_BYTES,
  download,
  outputName,
  type RunContext,
} from "./operations/context";
export {
  decryptWithMessagePassword,
  matchDecryptionKey,
  scanMessageEncryption,
} from "./operations/decrypt";
export { signCrx, verifyCrx } from "./operations/sign";

export async function runMode(c: RunContext): Promise<Outcome> {
  try {
    switch (c.mode) {
      case "encrypt":
        return await encrypt(c);
      case "decrypt":
        return await decrypt(c);
      case "sign":
        return await sign(c);
      case "verify":
        return await verify(c);
    }
  } catch (e) {
    return {
      kind: "error",
      error: presentError(e, t("workspace_operation_failed")),
    };
  }
}
