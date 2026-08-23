/**
 * ============================================================================
 * The one protect path, parameterised by key type.
 * ============================================================================
 *
 * Every "produce a fresh encrypted-key blob" flow — OpenPGP certs
 * (`protect-flow.ts`), CRX RSA signing keys (`crx/operations.ts`), and
 * whatever comes next — does the identical dance:
 *
 *   encode the password / obtain the PRF output -> call the wasm protect
 *   export -> unpack the packed blob -> assemble the stored blob ->
 *   `.fill(0)` the secret buffer in a `finally`.
 *
 * Only two things genuinely differ per key type: *which* wasm export is
 * called, and *how* the wasm metadata lands in the stored blob. Those are
 * the two callbacks in {@link ProtectSpec}; everything else — the
 * password-strength gate, the ownership rules for a reused PRF output,
 * and above all the zeroization — lives here once. This is deliberate:
 * the `.fill(0)` contract is per-secret (SECURITY.md §5), and a
 * per-key-type copy of it is a per-key-type chance to forget it.
 *
 * @secret-handling
 *  - The password crosses as `Uint8Array` (never a JS string past the
 *    boundary) and is `.fill(0)`'d in a `finally` — covering the wasm
 *    call, the blob assembly and the optional cached unlock, so the bytes
 *    are live for exactly as long as something needs them.
 *  - A PRF output we obtained ourselves is `.fill(0)`'d in a `finally`.
 *    One handed to us via `prfReuse` is NOT: the caller owns its
 *    lifetime, because it is deliberately shared across several blobs
 *    (one ceremony, many keys) and zeroizing it here would break the
 *    second one.
 *  - `storedSecret` is an HKDF salt, not a secret. It is persisted in the
 *    clear in the blob and needs no scrubbing.
 */

import type { PasswordBlobParts, PrfBlobParts } from "./protected-blob";
import { AppError } from "../errors/app-error";
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
      /** If true, immediately unlock the new blob into KEY_STORE so the
       *  caller can use the key without re-prompting. The unlock goes
       *  through the standard `unlockWithPassword` path so KEY_STORE
       *  insertion is always tied to a user-initiated unlock action. */
      cache?: boolean;
    }
  | {
      method: "passkey";
      reusePasskeyCredentialId?: string;
      /** See above. Reuses the just-obtained PRF output -- no second
       *  WebAuthn prompt. */
      cache?: boolean;
      /** Skip the WebAuthn ceremony entirely by reusing a PRF output
       *  already obtained for `reusePasskeyCredentialId` (e.g. during
       *  onboarding where the master setup just authenticated, or a
       *  bulk import protecting several keys off one ceremony). The
       *  returned blob will carry `prfSalt` so later unlocks
       *  re-authenticate with the same WebAuthn challenge and reproduce
       *  the same PRF output. A fresh `storedSecret` is still generated
       *  per blob to keep the derived AES key distinct from the master
       *  / other blobs. Caller owns `prfOutput`'s lifetime; this fn
       *  does NOT zero it. */
      prfReuse?: {
        prfOutput: Uint8Array;
        prfSalt: ArrayBuffer;
      };
    };

/** The shape every wasm protect export returns: metadata plus the packed
 *  protection blob. `blob`'s layout is the only part this module reads. */
export interface PackedProtectResult {
  blob: Uint8Array;
}

/** Everything the PRF branch resolved before calling wasm, handed to the
 *  blob assembler so it can persist the public half of it. */
export interface PrfMaterial {
  credentialId: string;
  prfSalt: ArrayBuffer;
  /** Live PRF output. Do NOT retain past the assembler call. */
  prfOutput: Uint8Array;
  storedSecret: ArrayBuffer;
  storedSecretBytes: Uint8Array;
}

/**
 * The per-key-type half of a protect flow.
 *
 * @typeParam R - the wasm protect result (`ProtectFlowResult`,
 *                `CrxProtectFlowResult`, ...): `{ blob, meta }`.
 * @typeParam B - the stored blob this key type persists.
 */
export interface ProtectSpec<R extends PackedProtectResult, B> {
  /** Labels a freshly-registered passkey. Ignored when a credential is
   *  reused or the password path is taken. */
  userIdHint: string;
  /** The `*_with_password` wasm export for this key type. */
  runPassword: (password: Uint8Array) => Promise<R>;
  /** The `*_with_prf` wasm export for this key type. */
  runPrf: (prfOutput: Uint8Array, storedSecret: Uint8Array) => Promise<R>;
  /** Map wasm metadata + the unpacked `[16 salt][12 iv][ct]` blob into
   *  the stored blob. */
  fromPassword: (result: R, parts: PasswordBlobParts) => B;
  /** Map wasm metadata + the unpacked `[12 iv][ct]` blob into the stored
   *  blob. */
  fromPrf: (result: R, parts: PrfBlobParts, prf: PrfMaterial) => B;
  /** Optional chained unlock for `cache: true`, run while the password
   *  bytes are still live. Omit for key types that never cache. */
  cachePassword?: (
    result: R,
    parts: PasswordBlobParts,
    password: Uint8Array,
  ) => Promise<number>;
  /** As above, for the PRF path. */
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

/** The minimum we accept before handing a password to Argon2id. Shared so
 *  every key type refuses the same passwords. */
export function assertStrongPassword(password: string): void {
  if (!password || password.length < 8) {
    throw new AppError(
      "weak-password",
      "Password must be at least 8 characters",
    );
  }
}

/** Register a passkey for `userIdHint`, refusing an authenticator that
 *  can't do PRF — without it there is nothing to derive a key from. */
async function registerPasskeyWithPrf(userIdHint: string): Promise<string> {
  const reg = await registerPasskey(userIdHint, userIdHint);
  if (!reg.prfEnabled) {
    throw new Error(
      "Your authenticator doesn't support PRF. Try a different passkey or use a password instead.",
    );
  }
  return reg.credentialId;
}

/**
 * Protect a key under the chosen method and assemble its stored blob.
 * The plaintext key exists only inside the wasm call; when `cache: true`
 * is set, the blob is then unlocked through the standard `unlockWith*`
 * path, so KEY_STORE insertion stays tied to an explicit
 * (user-just-typed-credentials) unlock rather than to the protect call.
 */
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

  // PRF + prfSalt: either reuse from caller (no new WebAuthn dialog) or
  // run our own ceremony. `storedSecret` is always fresh per blob so the
  // derived AES key is unique even when prfOutput is shared.
  let prfSalt: ArrayBuffer;
  let prfOutput: Uint8Array;
  let ownsPrfOutput: boolean;
  if (protection.prfReuse) {
    prfSalt = protection.prfReuse.prfSalt;
    prfOutput = protection.prfReuse.prfOutput;
    ownsPrfOutput = false; // caller zeros it
  } else {
    prfSalt = generatePrfSalt();
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
