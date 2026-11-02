import { useState } from "react";

import type { ProtectionContext, ProtectionMethod } from "./protection-choice";
import { checkPrfSupport } from "../../lib/protection/webauthn-prf";
import {
  crxProtectionInput,
  protectionInput,
  validateProtection,
} from "./protection-choice";

export function getDefaultProtectionMethod(): ProtectionMethod {
  return checkPrfSupport() ? "passkey" : "password";
}

/**
 * The protection step's state, its validation, and the input it builds,
 * for every flow that seals a new secret. `pickerProps` spreads into
 * `ProtectionMethodPicker`.
 */
export function useProtectionChoice(ctx: ProtectionContext = {}) {
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [reusePasskey, setReusePasskey] = useState(true);
  const state = { method, password, confirmPassword, reusePasskey };

  return {
    method,
    password,
    /** The vault passkey will be reused (no new registration). */
    reusing:
      method === "passkey" && reusePasskey && !!ctx.reusePasskeyCredentialId,
    validate: () => validateProtection(state),
    toInput: (extra?: { cache?: boolean }) =>
      protectionInput(state, ctx, extra),
    toCrxInput: () => crxProtectionInput(state, ctx),
    /** Typed secrets are strings: this bounds their lifetime, no more. */
    clear: () => {
      setPassword("");
      setConfirmPassword("");
    },
    clearConfirmation: () => setConfirmPassword(""),
    pickerProps: {
      method,
      onMethodChange: setMethod,
      password,
      onPasswordChange: setPassword,
      confirmPassword,
      onConfirmPasswordChange: setConfirmPassword,
      reusePasskeyCredentialId: ctx.reusePasskeyCredentialId,
      reusePasskey,
      onReusePasskeyChange: setReusePasskey,
    },
  };
}

export type ProtectionChoice = ReturnType<typeof useProtectionChoice>;
