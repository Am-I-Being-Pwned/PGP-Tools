import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { ProtectionInput } from "../../lib/protection/protect-runner";
import { t } from "../../lib/i18n";

export type ProtectionMethod = "passkey" | "password";

/** What the protection step has collected. */
export interface ProtectionChoiceState {
  method: ProtectionMethod;
  password: string;
  confirmPassword: string;
  /** Reuse the vault's passkey; only meaningful with a credential to reuse. */
  reusePasskey: boolean;
}

export interface ProtectionContext {
  reusePasskeyCredentialId?: string;
  /** Seal under the master's PRF salt so the vault ceremony opens the
   *  key. Only ever applied together with the reused credential. */
  masterSealSalt?: ArrayBuffer;
}

export function validatePassword(
  password: string,
  confirmPassword: string,
): string | null {
  if (password.length < 8) return t("keygen_error_password_short");
  if (password !== confirmPassword) return t("keygen_error_password_mismatch");
  return null;
}

/** A passkey needs no validation here: the ceremony is the check. */
export function validateProtection(s: ProtectionChoiceState): string | null {
  return s.method === "password"
    ? validatePassword(s.password, s.confirmPassword)
    : null;
}

export function protectionInput(
  s: ProtectionChoiceState,
  ctx: ProtectionContext,
  extra: { cache?: boolean } = {},
): ProtectionInput {
  if (s.method === "password") {
    return { method: "password", password: s.password, ...extra };
  }
  return {
    method: "passkey",
    reusePasskeyCredentialId: s.reusePasskey
      ? ctx.reusePasskeyCredentialId
      : undefined,
    prfSalt: s.reusePasskey ? ctx.masterSealSalt : undefined,
    ...extra,
  };
}

/** CRX keys never take the master salt: they are sealed at rest and
 *  never opened by the vault ceremony. */
export function crxProtectionInput(
  s: ProtectionChoiceState,
  ctx: ProtectionContext,
): CrxProtectionInput {
  return s.method === "password"
    ? { method: "password", password: s.password }
    : {
        method: "passkey",
        reusePasskeyCredentialId: s.reusePasskey
          ? ctx.reusePasskeyCredentialId
          : undefined,
      };
}
