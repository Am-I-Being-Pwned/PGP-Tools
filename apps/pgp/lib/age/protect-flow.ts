/**
 * Import / unlock / drop for SSH identities (age engine). Secret lifetime
 * lives in `protection/protect-runner.ts`; this file only picks the wasm
 * exports and shapes the blob.
 *
 * Import-only, and no plaintext export: an SSH key leaves the app only as
 * ciphertext it produced. Stored in the same keyring as PGP, `kind: "ssh"`,
 * `keyId` = `SHA256:...` fingerprint, `publicKeyArmored` = recipient line.
 *
 * @secret-handling The OpenSSH private key crosses as `Uint8Array` and is
 * `.fill(0)`'d in a `finally` that wraps the WHOLE flow, including the
 * password gate and WebAuthn ceremony (both can throw before wasm).
 */

import type { ContactGroup } from "../import/types";
import type { SshProtectFlowResult, SshRecipientInfo } from "../pgp/wasm";
import type {
  ProtectionInput,
  ProtectSpec,
} from "../protection/protect-runner";
import type { PublicContactKey } from "../storage/contacts";
import type { ProtectedKeyBlob } from "../storage/keyring";
import { fromBase64, toBase64 } from "../encoding";
import { AppError } from "../errors/app-error";
import { t } from "../i18n";
import {
  dropSshIdentity,
  protectSshIdentityWithPassword,
  protectSshIdentityWithPrf,
  sshPassphraseRequiredMessage,
  unlockSshIdentityWithPassword,
  unlockSshIdentityWithPrf,
} from "../pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../protection/password-kdf";
import { runProtect } from "../protection/protect-runner";
import { authenticateAndGetPrf } from "../protection/webauthn-prf";
import { recipientsField } from "../storage/contacts";
import { kindField } from "../storage/key-kind";
import { blobFromEncrypted } from "../storage/keyring";
import { errorMessage } from "../utils/errors";

const EMPTY = new Uint8Array(0);

type SshSpec = ProtectSpec<SshProtectFlowResult, ProtectedKeyBlob>;

/** The key comment as `userIds`; `[]` (not `[""]`) when there is none. */
export function sshUserIds(comment: string): string[] {
  const trimmed = comment.trim();
  return trimmed ? [trimmed] : [];
}

function sshBlob(
  result: SshProtectFlowResult,
  encrypted: Parameters<typeof blobFromEncrypted>[4],
): ProtectedKeyBlob {
  return blobFromEncrypted(
    result.meta.fingerprint,
    sshUserIds(result.meta.comment),
    result.meta.algorithm,
    result.meta.recipient,
    encrypted,
    "ssh",
  );
}

function sshSpec(
  userIdHint: string,
  runPassword: SshSpec["runPassword"],
  runPrf: SshSpec["runPrf"],
): SshSpec {
  return {
    userIdHint,
    runPassword,
    runPrf,

    fromPassword: (result, { salt, iv, ct }) =>
      sshBlob(result, {
        method: "password",
        ciphertext: toBase64(ct),
        iv: toBase64(iv),
        salt: toBase64(salt),
      }),

    fromPrf: (result, { iv, ct }, prf) =>
      sshBlob(result, {
        method: "passkey",
        ciphertext: toBase64(ct),
        iv: toBase64(iv),
        credentialId: prf.credentialId,
        prfSalt: toBase64(prf.prfSalt),
        // storedSecret is HKDF salt, persisted in plaintext alongside ct.
        storedSecret: toBase64(prf.storedSecret),
      }),

    // Cache via a real unlock of the blob just written (SECURITY.md §4).
    cachePassword: (result, { salt, iv, ct }, passwordBytes) =>
      unlockSshIdentityWithPassword(
        ct,
        iv,
        salt,
        result.meta.fingerprint,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      ),

    cachePrf: (result, { iv, ct }, prf) =>
      unlockSshIdentityWithPrf(
        ct,
        iv,
        prf.prfOutput,
        prf.storedSecretBytes,
        result.meta.fingerprint,
      ),
  };
}

export interface SshImportOutput {
  blob: ProtectedKeyBlob;
  /** Present iff `cache: true` was requested AND the unlock succeeded. */
  handle?: number;
}

/**
 * Import an OpenSSH private key and re-protect it. Returns the blob
 * WITHOUT persisting it; the caller is the one persist path.
 *
 * @secret-handling `keyFile` (bytes so it can be wiped) and
 * `sourcePassphrase` are `.fill(0)`'d on every exit.
 */
export async function importSshIdentity(
  keyFile: Uint8Array,
  /** The passphrase already on the key file; null when it has none. */
  sourcePassphrase: string | null,
  protection: ProtectionInput,
  opts: { userIdHint?: string } = {},
): Promise<SshImportOutput> {
  const sourceBytes = sourcePassphrase
    ? new TextEncoder().encode(sourcePassphrase)
    : EMPTY;
  try {
    return await runProtect(
      protection,
      sshSpec(
        opts.userIdHint ?? t("import_default_ssh_name"),
        (password) =>
          protectSshIdentityWithPassword(
            keyFile,
            sourceBytes,
            password,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
          ),
        (prfOutput, storedSecret) =>
          protectSshIdentityWithPrf(
            keyFile,
            sourceBytes,
            prfOutput,
            storedSecret,
          ),
      ),
    );
  } catch (e) {
    // Tag the engine's "needs passphrase" error, compared against the
    // engine's own runtime string. NOT `e instanceof Error`: wasm-bindgen
    // throws a Rust `Err(String)` as a JS string.
    const raw = errorMessage(e, "");
    if (!(e instanceof AppError) && raw !== "") {
      // If the sentinel lookup fails, the ORIGINAL error must propagate.
      let needsPassphrase: string | null;
      try {
        needsPassphrase = await sshPassphraseRequiredMessage();
      } catch {
        needsPassphrase = null;
      }
      if (needsPassphrase !== null && raw === needsPassphrase) {
        throw new AppError("ssh-passphrase-required", raw);
      }
    }
    throw e;
  } finally {
    keyFile.fill(0);
    if (sourceBytes.length > 0) sourceBytes.fill(0);
  }
}

/**
 * Unlock a stored SSH identity into wasm. The caller OWNS the handle and
 * MUST {@link closeSshIdentity} it.
 *
 * @secret-handling password / PRF output cross as bytes, wiped in `finally`.
 */
export async function openSshIdentity(
  blob: ProtectedKeyBlob,
  password?: string,
): Promise<number> {
  const ciphertext = fromBase64(blob.encryptedPrivateKey);
  const iv = fromBase64(blob.iv);

  if (blob.protection.method === "password") {
    if (!password) {
      throw new AppError(
        "password-required",
        "Password required to unlock this SSH key",
      );
    }
    const passwordBytes = new TextEncoder().encode(password);
    try {
      return await unlockSshIdentityWithPassword(
        ciphertext,
        iv,
        fromBase64(blob.protection.kdfSalt),
        blob.keyId,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
    } finally {
      passwordBytes.fill(0);
    }
  }

  const { prfOutput } = await authenticateAndGetPrf(
    blob.protection.credentialId,
    fromBase64(blob.protection.prfSalt),
  );
  try {
    return await unlockSshIdentityWithPrf(
      ciphertext,
      iv,
      prfOutput,
      fromBase64(blob.protection.storedSecret),
      blob.keyId,
    );
  } finally {
    prfOutput.fill(0);
  }
}

/** Drop (and zeroize) a handle returned by {@link openSshIdentity}. */
export async function closeSshIdentity(handle: number): Promise<void> {
  await dropSshIdentity(handle);
}

/**
 * A parsed SSH public key line as a stored contact (`armoredPublicKey` is
 * the recipient line). Always `usableForEncryption`: an age recipient is
 * an encryption key.
 */
export function sshContact(
  info: SshRecipientInfo,
  now: number = Date.now(),
): PublicContactKey {
  return {
    ...kindField("ssh"),
    keyId: info.fingerprint,
    userIds: sshUserIds(info.comment),
    algorithm: info.algorithm,
    armoredPublicKey: info.recipient,
    addedAt: now,
    lastUsedAt: now,
    usableForEncryption: true,
  };
}

/**
 * A group of SSH public keys as ONE stored contact -- the only
 * constructor for a multi-key contact, however the group was assembled.
 *
 * `keyId`/`armoredPublicKey` are the first member's (head-agreement
 * invariant, `storage/contacts`); a one-key group gets the plain
 * single-key shape. `expiresAt: null`, not absent: `undefined` makes the
 * contacts backfill parse the recipient line as PGP armor on every load.
 */
export function groupContact(
  group: ContactGroup,
  now: number = Date.now(),
): PublicContactKey {
  if (group.members.length === 0) {
    // A headless contact would fail `isValidContact` on read and vanish.
    throw new Error("groupContact: group has no usable keys");
  }
  const head = group.members[0];
  return {
    ...kindField("ssh"),
    keyId: head.keyId,
    userIds: [group.label],
    algorithm: head.algorithm,
    armoredPublicKey: head.armored,
    addedAt: now,
    lastUsedAt: now,
    usableForEncryption: true,
    expiresAt: null,
    // Omit, don't emit `source: undefined`.
    ...(group.source ? { source: group.source } : {}),
    ...recipientsField(group.members),
  };
}
