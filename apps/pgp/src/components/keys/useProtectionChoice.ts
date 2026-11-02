import { useState } from "react";

import { checkPrfSupport } from "~/lib/protection/webauthn-prf";
import {
  crxProtectionInput,
  protectionInput,
  validateProtection,
  type ProtectionContext,
  type ProtectionMethod,
} from "./protection-choice";

export function getDefaultProtectionMethod(): ProtectionMethod {
  return checkPrfSupport() ? "passkey" : "password";
}

/** The protection step's state, validation, and built input. */
export function useProtectionChoice(ctx: ProtectionContext = {}) {
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [reusePasskey, setReusePasskey] = useState(true);
  const state = { method, password, confirmPassword, reusePasskey };

  return {
    method,
    password,
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
