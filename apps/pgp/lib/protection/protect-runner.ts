/**
 * The one protect path, parameterised by key type. Key types supply only
 * the wasm export and the blob mapping ({@link ProtectSpec}); the password
 * gate, PRF ownership and zeroization live here once so no per-type copy
 * can forget them (SECURITY.md §5).
 *
 * @secret-handling
 *  - The password crosses as `Uint8Array` and is `.fill(0)`'d in a
 *    `finally` covering wasm call, blob assembly and cached unlock.
 *  - A PRF output we obtained is `.fill(0)`'d; one passed via `prfReuse`
 *    is NOT -- the caller owns it (shared across several blobs).
 *  - `storedSecret` is an HKDF salt, persisted in the clear.
 */

import type { PasswordBlobParts, PrfBlobParts } from "./protected-blob";
import { AppError } from "../errors/app-error";
import { t } from "../i18n";
import { unpackPasswordBlob, unpackPrfBlob } from "./protected-blob";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "./webauthn-prf";

export type ProtectionInput =
  | {
      method: "password";
      password: string;
      /** Unlock the new blob into KEY_STORE via the standard unlock path,
       *  so insertion stays tied to a user-initiated unlock. */
      cache?: boolean;
    }
  | {
      method: "passkey";
      reusePasskeyCredentialId?: string;
      /** As above; reuses the just-obtained PRF output. */
      cache?: boolean;
      /** Skip the ceremony by reusing a PRF output already obtained for
       *  `reusePasskeyCredentialId`. `storedSecret` is still fresh per
       *  blob so derived AES keys stay distinct. Caller owns `prfOutput`;
       *  NOT zeroed here. */
      prfReuse?: {
        prfOutput: Uint8Array;
        prfSalt: ArrayBuffer;
      };
      /** Seal under THIS salt (the master's, when `unlockKeysOnOpen`) so
       *  the vault unlock ceremony can open it. Opt-in: a shared salt
       *  lets one PRF output open many blobs. Ignored with `prfReuse`. */
      prfSalt?: ArrayBuffer;
    };

export interface PackedProtectResult {
  blob: Uint8Array;
}

export interface PrfMaterial {
  credentialId: string;
  prfSalt: ArrayBuffer;
  /** Live PRF output. Do NOT retain past the assembler call. */
  prfOutput: Uint8Array;
  storedSecret: ArrayBuffer;
  storedSecretBytes: Uint8Array;
}

/** The per-key-type half of a protect flow. */
export interface ProtectSpec<R extends PackedProtectResult, B> {
  /** Labels a freshly-registered passkey. */
  userIdHint: string;
  runPassword: (password: Uint8Array) => Promise<R>;
  runPrf: (prfOutput: Uint8Array, storedSecret: Uint8Array) => Promise<R>;
  fromPassword: (result: R, parts: PasswordBlobParts) => B;
  fromPrf: (result: R, parts: PrfBlobParts, prf: PrfMaterial) => B;
  /** Chained unlock for `cache: true`, run while the password is live. */
  cachePassword?: (
    result: R,
    parts: PasswordBlobParts,
    password: Uint8Array,
  ) => Promise<number>;
  cachePrf?: (
    result: R,
    parts: PrfBlobParts,
    prf: PrfMaterial,
  ) => Promise<number>;
}

export interface ProtectResult<B> {
  blob: B;
  /** Present iff `cache: true` was requested AND the unlock succeeded. */
  handle?: number;
}

export function assertStrongPassword(password: string): void {
  if (!password || password.length < 8) {
    throw new AppError(
      "weak-password",
      "Password must be at least 8 characters",
    );
  }
}

async function registerPasskeyWithPrf(userIdHint: string): Promise<string> {
  const reg = await registerPasskey(userIdHint, userIdHint);
  if (!reg.prfEnabled) {
    throw new Error(t("keygen_error_prf_unsupported_authenticator"));
  }
  return reg.credentialId;
}

/** Protect a key and assemble its stored blob; plaintext exists only
 *  inside the wasm call. */
export async function runProtect<R extends PackedProtectResult, B>(
  protection: ProtectionInput,
  spec: ProtectSpec<R, B>,
): Promise<ProtectResult<B>> {
  if (protection.method === "password") {
    assertStrongPassword(protection.password);
    const passwordBytes = new TextEncoder().encode(protection.password);
    try {
      const result = await spec.runPassword(passwordBytes);
      const parts = unpackPasswordBlob(result.blob);
      const blob = spec.fromPassword(result, parts);
      const handle =
        protection.cache && spec.cachePassword
          ? await spec.cachePassword(result, parts, passwordBytes)
          : undefined;
      return { blob, handle };
    } finally {
      passwordBytes.fill(0);
    }
  }

  const credentialId =
    protection.reusePasskeyCredentialId ??
    (await registerPasskeyWithPrf(spec.userIdHint));

  // `storedSecret` is fresh per blob so the AES key is unique even when
  // prfOutput is shared.
  let prfSalt: ArrayBuffer;
  let prfOutput: Uint8Array;
  let ownsPrfOutput: boolean;
  if (protection.prfReuse) {
    prfSalt = protection.prfReuse.prfSalt;
    prfOutput = protection.prfReuse.prfOutput;
    ownsPrfOutput = false; // caller zeros it
  } else {
    prfSalt = protection.prfSalt ?? generatePrfSalt();
    ({ prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt));
    ownsPrfOutput = true;
  }

  const storedSecret = generateStoredSecret();
  const storedSecretBytes = new Uint8Array(storedSecret);
  try {
    const material: PrfMaterial = {
      credentialId,
      prfSalt,
      prfOutput,
      storedSecret,
      storedSecretBytes,
    };
    const result = await spec.runPrf(prfOutput, storedSecretBytes);
    const parts = unpackPrfBlob(result.blob);
    const blob = spec.fromPrf(result, parts, material);
    const handle =
      protection.cache && spec.cachePrf
        ? await spec.cachePrf(result, parts, material)
        : undefined;
    return { blob, handle };
  } finally {
    if (ownsPrfOutput) prfOutput.fill(0);
  }
}
