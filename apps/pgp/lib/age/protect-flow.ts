/**
 * ============================================================================
 * Import / unlock / drop for SSH identities (age engine).
 * ============================================================================
 *
 * The SSH half of the shared protect machinery. Everything about secret
 * lifetime -- encode -> call wasm -> unpack -> assemble -> `.fill(0)` in
 * a `finally` -- lives once in `protection/protect-runner.ts`; what is
 * here is the same two things `protect-flow.ts` (PGP) and
 * `crx/operations.ts` (CRX) keep: which wasm export to call, and how its
 * metadata lands in a stored blob.
 *
 * There is no `generate`: `ssh-keygen` is the generator, and the app only
 * ever imports a key the user already has. There is no plaintext export
 * either -- the OpenPGP trapdoor (`getKeyArmored`) has no SSH sibling, so
 * an imported SSH key can leave this app only as ciphertext it produced.
 *
 * An SSH identity is stored in the SAME keyring as PGP certs, discriminated
 * by `kind: "ssh"` (see `storage/key-kind.ts`). Its `keyId` is the OpenSSH
 * `SHA256:...` fingerprint and its `publicKeyArmored` is the canonical
 * `<type> <base64>` recipient line -- the SSH stand-ins for the two fields
 * every stored key needs.
 *
 * @secret-handling The OpenSSH private key crosses as `Uint8Array` (never
 * a JS string past the boundary) and is `.fill(0)`'d in a `finally` that
 * wraps the WHOLE flow -- including the password-strength gate and the
 * WebAuthn ceremony, both of which can throw before wasm is reached. That
 * ordering was a real bug in `importAndProtect` once; see
 * `protection/protect-runner.test.ts`.
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
import { errorMessage } from "../utils/errors";
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

const EMPTY = new Uint8Array(0);

type SshSpec = ProtectSpec<SshProtectFlowResult, ProtectedKeyBlob>;

/**
 * An SSH key's name, for the UI.
 *
 * It has no User IDs -- only the free-text comment `ssh-keygen` puts at
 * the end of the line, conventionally `user@host`. It goes into `userIds`
 * as the sole element so every consumer keeps reading one field for "who
 * is this", and the list is empty (not `[""]`) when the key has no
 * comment, so "no name" stays distinguishable from "named empty".
 */
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

    // `cache: true` chains a real unlock against the blob just written,
    // so an SSH_KEY_STORE entry always traces back to an unlock path --
    // the same invariant SECURITY.md §4 states for KEY_STORE.
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
 * Import an OpenSSH private key and re-protect it under the chosen
 * method. Returns the blob WITHOUT persisting it -- the caller stores it,
 * so there is one persist path (same rule as `generateCrxKey`).
 *
 * @secret-handling `keyFile` and `sourcePassphrase` are both `.fill(0)`'d
 * on every exit. `keyFile` is taken as bytes rather than a string
 * precisely so it CAN be: an OpenSSH private key is secret material for
 * the whole of its life in JS.
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
        opts.userIdHint ?? "Imported SSH key",
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
    // Translate the engine's "I need the passphrase" into a tagged code
    // ONCE, here, so no caller has to know its wording. The comparison is
    // against the value the engine itself reports at runtime, never a
    // transcription -- see `sshPassphraseRequiredMessage`.
    // NOT `e instanceof Error`: wasm-bindgen surfaces a Rust `Err(String)`
    // as a thrown JS *string*, so an instanceof gate here discards every
    // message the engine writes -- see the note on `errorMessage`. This
    // exact mistake made passphrase-protected SSH keys unimportable
    // (the message rendered, the field to answer it never appeared),
    // which is the failure this tagging exists to prevent.
    const raw = errorMessage(e, "");
    if (!(e instanceof AppError) && raw !== "") {
      // Guarded end to end: if the sentinel can't be read for any
      // reason, the ORIGINAL error must still be what propagates.
      // Tagging is an improvement on the error, never a replacement for
      // it -- swallowing a real failure to report a lookup failure would
      // be strictly worse than not tagging at all.
      let needsPassphrase: string | null = null;
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
 * Unlock a stored SSH identity into wasm and return its handle. The
 * caller OWNS the handle and MUST {@link closeSshIdentity} it.
 *
 * @secret-handling the password / PRF output crosses as bytes and is
 * `.fill(0)`'d in a `finally`.
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
 * A parsed SSH public key line as a stored contact.
 *
 * Same store, same envelope as a PGP contact -- only `kind: "ssh"` and
 * the meaning of `armoredPublicKey` (a recipient line, not armor) differ.
 * `usableForEncryption` is true unconditionally: an age recipient IS an
 * encryption key, there is no sign-only SSH recipient to exclude.
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
 * A fetched group of SSH public keys as ONE stored contact.
 *
 * The sibling of {@link sshContact}, here for the same reason that one
 * is here: what an SSH contact's record looks like -- the `kind` marker,
 * the canonical recipient line as "armor", `usableForEncryption` -- is
 * this module's business, and a second hand-rolled copy in the import
 * panel would be free to drift from the one `importSshIdentity` writes.
 *
 * `keyId`/`armoredPublicKey` are the FIRST member's, and the full list
 * goes through `recipientsField`, which writes nothing at all for a
 * single key. So a GitHub user with exactly one key produces the same
 * record shape a pasted `.pub` line does -- no `recipients` array to
 * migrate, and an older build reads it as the plain single-key contact
 * it also is (see the head-agreement invariant in `storage/contacts`).
 *
 * `expiresAt: null` rather than absent for the same reason the pasted
 * path sets it: `undefined` means "not computed yet" and sends the
 * contacts backfill off to parse a recipient line as PGP armor on every
 * refresh (see useContacts). SSH keys simply do not expire.
 */
export function githubContact(
  group: ContactGroup,
  now: number = Date.now(),
): PublicContactKey {
  if (group.members.length === 0) {
    // Unreachable through the import flow -- a group with no usable
    // member is classified `rejected` and never reaches an import -- but
    // a contact whose head is undefined would fail `isValidContact` on
    // the way back OUT of storage, i.e. silently vanish. Refuse here.
    throw new Error("githubContact: group has no usable keys");
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
    source: group.source,
    ...recipientsField(group.members),
  };
}
