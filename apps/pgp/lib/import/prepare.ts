import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { IncomingKey } from "./types";
import {
  LEGACY_PEM_ENCRYPTED,
  looksLikeForeignSshPrivateKey,
  splitSshPrivateKeyBlocks,
  splitSshPublicKeyLines,
} from "../armor-blocks";
import { detectImportOverwrite } from "../import-overwrite";
import { importRejectionMessage, isUsableContact } from "../import-public-keys";
import {
  extractPublicKey,
  parseKeyDetails,
  parseKeys,
  parseSshRecipient,
  sshPrivateKeyFormatRejection,
} from "../pgp/wasm";
import { PENDING_KEY_ID } from "./types";

/**
 * Turn pasted/dropped text into the objects the import UI renders.
 *
 * Everything the old flow made the user discover by pressing Next --
 * "is this a key at all", "whose is it", "do I already have it", "is it
 * even usable" -- is answered here, up front, so the panel can show a
 * preview instead of a wall of armor.
 */

/** One stored key an import can collide with, plus its public armor so a
 *  byte-identical re-import can be told from a real change. */
export interface StoredKey {
  keyId: string;
  userIds: string[];
  /** PUBLIC armor -- `ProtectedKeyBlob.publicKeyArmored` for own keys,
   *  `PublicContactKey.armoredPublicKey` for contacts. */
  armored: string;
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
}

export interface StoredKeys {
  /** The user's own keys (keyring), matched against private imports. */
  own: StoredKey[];
  /** Contacts, matched against public imports. */
  contacts: StoredKey[];
}

/** Normalized armor, for the byte-identical comparison that separates a
 *  no-op re-import from a genuine update. Line endings and trailing
 *  whitespace differ freely between tools that emit the same cert. */
function normalizeArmor(armored: string): string {
  return armored.replace(/\r\n/g, "\n").trim();
}

/** Best-effort breakdown: a cert we can't decompose still previews from
 *  its KeyInfo, the subkey list simply doesn't render. */
async function safeDetails(armored: string): Promise<KeyDetails | null> {
  try {
    return await parseKeyDetails(armored);
  } catch {
    return null;
  }
}

/** Cheap change `detectImportOverwrite` can't see: it compares stored
 *  metadata, which records no subkeys. */
function subkeyChanges(
  incoming: KeyDetails | null,
  stored: KeyDetails | null,
): string[] {
  if (!incoming || !stored) return [];
  const known = new Set(stored.keys.map((k) => k.fingerprint));
  const added = incoming.keys.filter((k) => !known.has(k.fingerprint)).length;
  return added === 0 ? [] : [`${added} new subkey${added === 1 ? "" : "s"}`];
}

/**
 * Classify one parsed cert against what's already stored.
 *
 * `duplicate` means importing would change nothing -- same fingerprint
 * AND byte-identical public armor. Anything else sharing a fingerprint
 * is an `update`: the owner extended the expiry, added a user ID or
 * rotated a subkey, and the stored record should catch up.
 */
export async function classifyCert(
  keyInfo: KeyInfo,
  publicArmored: string,
  stored: StoredKey[],
): Promise<IncomingKey> {
  const kind: IncomingKey["kind"] = keyInfo.isPrivate
    ? "pgp-private"
    : "pgp-public";
  const details = await safeDetails(publicArmored);
  const base = {
    keyId: keyInfo.keyId,
    kind,
    userIds: keyInfo.userIds,
    info: keyInfo,
    details,
    securityWarning: keyInfo.securityWarning,
    publicArmored,
  };

  if (!isUsableContact(keyInfo)) {
    return {
      ...base,
      status: "rejected",
      changes: [],
      rejection: importRejectionMessage(keyInfo),
    };
  }

  const match = stored.find(
    (s) => s.keyId.toUpperCase() === keyInfo.keyId.toUpperCase(),
  );
  if (!match) return { ...base, status: "new", changes: [] };

  if (normalizeArmor(match.armored) === normalizeArmor(publicArmored)) {
    return {
      ...base,
      status: "duplicate",
      changes: [],
      existingAddedAt: match.addedAt ?? match.createdAt ?? null,
    };
  }

  const overwrite = detectImportOverwrite(keyInfo.keyId, stored, {
    expiresAt: keyInfo.expiresAt,
    userIds: keyInfo.userIds,
  });
  const changes = [
    ...(overwrite?.changes ?? []),
    ...subkeyChanges(details, await safeDetails(match.armored)),
  ];

  return {
    ...base,
    status: "update",
    // The fingerprint matched but nothing we display differs -- say that,
    // rather than showing an empty "what changed" list.
    changes: changes.length > 0 ? changes : ["The key has been re-issued"],
    existingAddedAt: overwrite?.addedAt ?? null,
  };
}

/**
 * Which non-OpenPGP engines this import accepts.
 *
 * A disabled engine is not merely refused, it is not recognised: its key
 * falls through to the OpenPGP parse and comes back `unparseable`, which
 * is exactly what the panel showed before the engine existed. That is why
 * the flag lives here rather than in the panel -- the classifier is the
 * one place that decides what a blob of text IS.
 */
export interface ImportEngines {
  /** RSA signing keys for Chrome extensions (.crx). */
  crx?: boolean;
  /** OpenSSH keys, used with age: `.pub` recipient lines and OpenSSH
   *  private key containers. */
  ssh?: boolean;
}

/** A raw RSA private key PEM (PKCS#8 or PKCS#1) -- a CRX signing key, not
 *  OpenPGP. Matched only when it is NOT a PGP armored block, so a PGP
 *  private key that happens to mention the phrase can't be mistaken for
 *  one -- and not when the PEM is encrypted with the legacy
 *  `Proc-Type: 4,ENCRYPTED` scheme, which `parse_rsa_private_pem` cannot
 *  read either: claiming it here only replaced the age engine's "convert
 *  it with `ssh-keygen -p -f`" with a generic CRX parse failure. */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return (
    RSA_PEM_RE.test(text) &&
    !text.includes("PGP") &&
    !text.includes(LEGACY_PEM_ENCRYPTED)
  );
}

/**
 * The CRX signing key as the rest of the flow sees it.
 *
 * There is nothing to parse: no certificate, no user IDs, no dates, and
 * no fingerprint until the extension ID is derived at import time. It is
 * still an IncomingKey so it gets the same source -> preview -> protect
 * path as everything else -- the preview simply has less to show, which
 * is a rendering question (see KeyFacts) rather than a second flow.
 */
function crxSigningKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "crx",
    status: "new",
    info: null,
    details: null,
    // Not a real user ID -- the preview's headline, for a key that
    // carries no identity of its own.
    userIds: ["Chrome extension signing key"],
    changes: [],
    publicArmored: "",
  };
}

// ── SSH (age engine) ─────────────────────────────────────────────────

/**
 * An SSH key as the rest of the flow sees it.
 *
 * There is nothing certificate-shaped to parse: no user IDs, no created
 * date, no expiry, no subkeys -- so `info` and `details` are null, the
 * CRX precedent for an engine whose keys carry no certificate. What an
 * SSH key does carry is a free-text comment (`ssh-keygen` writes
 * `user@host`), which becomes the display name.
 */
function sshPublicKey(
  info: { fingerprint: string; recipient: string; comment: string },
  stored: StoredKey[],
): IncomingKey {
  const trimmed = info.comment.trim();
  const base = {
    keyId: info.fingerprint,
    kind: "ssh-public" as const,
    info: null,
    details: null,
    // Not a real user ID -- the preview's headline, for a key that
    // carries no identity beyond its comment.
    userIds: trimmed ? [trimmed] : ["SSH key"],
    changes: [],
    publicArmored: info.recipient,
  };
  // No `update` state for an SSH key: the recipient line is canonical and
  // carries nothing that can change -- no expiry to extend, no user ID to
  // add, no subkey to rotate. Same fingerprint means the same key, so
  // re-importing it is always a no-op.
  return stored.some((s) => s.keyId === info.fingerprint)
    ? { ...base, status: "duplicate" }
    : { ...base, status: "new" };
}

/**
 * An OpenSSH private key. Like a CRX signing key, its identity is only
 * recovered inside the protect step -- the fingerprint lives in the
 * key file, which may be passphrase-encrypted and is in any case never
 * parsed outside wasm -- so it arrives as {@link PENDING_KEY_ID} with no
 * public half to preview.
 */
function sshPrivateKey(): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-private",
    status: "new",
    info: null,
    details: null,
    userIds: ["SSH private key"],
    changes: [],
    publicArmored: "",
  };
}

/**
 * A `.pub` line the engine refuses, carrying the engine's own reason.
 *
 * The OpenPGP path has said why a key is unusable since it existed
 * (`importRejectionMessage`); this is the same contract for the age
 * engine. Its messages are more actionable still -- each names the key
 * type and the `ssh-keygen` command that fixes it -- so dropping the line
 * silently, as this loop used to, replaced the one thing worth saying
 * with "that doesn't look like a key".
 *
 * `keyId` is {@link PENDING_KEY_ID}: the fingerprint is computed inside
 * wasm from a blob it just refused, so there is none to report -- the same
 * position a CRX signing key is in before its extension id is derived.
 */
function rejectedSshPublicKey(line: string, rejection: string): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-public",
    status: "rejected",
    info: null,
    details: null,
    userIds: ["SSH key"],
    changes: [],
    rejection,
    // The line as pasted: unusable as a recipient, but it is what the
    // user is being told about, so the preview can still show it.
    publicArmored: line.trim(),
  };
}

/** A private key file in a format the age engine names and refuses --
 *  PuTTY `.ppk`, PKCS#8, legacy encrypted PEM. Nothing is parsed and
 *  nothing is carried in `secrets`: it is rejected, not imported. */
function rejectedSshPrivateKey(rejection: string): IncomingKey {
  return {
    keyId: PENDING_KEY_ID,
    kind: "ssh-private",
    status: "rejected",
    info: null,
    details: null,
    userIds: ["SSH private key"],
    changes: [],
    rejection,
    publicArmored: "",
  };
}

/** The message an engine threw, or a last-resort generic. Engine errors
 *  are already user-facing prose (see `gpg-wasm/src/age.rs`), so they are
 *  surfaced verbatim rather than re-worded here.
 *
 *  Exported for `github.ts`, which refuses fetched lines through the
 *  same engine and must report them in the same words -- two copies of
 *  this would be two wordings for one refusal. */
export function engineRejection(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.trim() || "This SSH key can't be used for encryption.";
}

export interface PreparedImport {
  /** Every cert found, classified, in the order they appeared. */
  keys: IncomingKey[];
  /**
   * Private armor per fingerprint, for the keys that carry secret
   * material. Handed to the protect step and dropped with the panel --
   * it is deliberately NOT on IncomingKey, which flows into React state
   * and the preview component (see SECURITY.md's zeroization table).
   */
  secrets: Map<string, string>;
  /** The text carried no OpenPGP certificate at all. */
  unparseable: boolean;
}

/**
 * Classify every cert in a blob of armor.
 *
 * A single block may bundle several certs (publishers rotate keys
 * yearly); when a block has at least one usable cert its unusable
 * siblings are stale rotations, dropped rather than reported -- the same
 * rule `importPublicKeyBlocks` already applies.
 *
 * This is the ONE place that decides what pasted text is. Every engine
 * is recognised here and returns an IncomingKey, so the panel routes a
 * CRX signing key exactly as it routes an OpenPGP cert -- an engine
 * added by short-circuiting the panel instead would be a third flow to
 * keep in step with the other two.
 */
export async function prepareImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines = {},
): Promise<PreparedImport> {
  // Recognised before the OpenPGP parse, which would only fail on it.
  // The PEM is secret material, so it travels in `secrets` like any
  // other private half -- never on the IncomingKey.
  //
  // Before the SSH branch too, and that ordering settles the one overlap
  // between the engines: a plain `-----BEGIN PRIVATE KEY-----` is both
  // valid PKCS#8 and a valid CRX signing key, and CRX is the engine that
  // can actually use it. With CRX off it falls through and the age
  // engine names it (`MSG_PKCS8`) instead.
  if (engines.crx && isRsaPrivatePem(text)) {
    return {
      keys: [crxSigningKey()],
      secrets: new Map([[PENDING_KEY_ID, text.trim()]]),
      unparseable: false,
    };
  }

  if (engines.ssh) {
    // Private first: an OpenSSH container carries the public half inside
    // its body, so checking the public form first would be checking the
    // wrong thing about the same file.
    const [sshPrivate] = splitSshPrivateKeyBlocks(text);
    if (sshPrivate) {
      return {
        keys: [sshPrivateKey()],
        secrets: new Map([[PENDING_KEY_ID, sshPrivate]]),
        unparseable: false,
      };
    }

    // Recognised but refused: PuTTY `.ppk`, PKCS#8, legacy encrypted PEM.
    // The engine has a specific message for each; asked here, before a
    // password is chosen, rather than at the protect step.
    if (looksLikeForeignSshPrivateKey(text)) {
      // `text` here can be a COMPLETE unencrypted private key file -- a
      // PKCS#8 `-----BEGIN PRIVATE KEY-----` reaches this branch whenever
      // the CRX engine is off. The bytes handed across the wasm boundary
      // are therefore held in a named binding and `.fill(0)`'d in a
      // `finally`, the same contract every other secret-bearing call site
      // in this app keeps (`lib/age/protect-flow.ts`,
      // `lib/protection/protect-runner.ts`). The Rust side owns and wipes
      // its own copy (`Zeroizing` in `ssh_private_key_format_rejection`);
      // this scrubs OURS, which nothing else would.
      //
      // Honestly: `text` is itself an immutable JS string and cannot be
      // zeroized, so this removes one additional plaintext copy from the
      // heap rather than eliminating the exposure. Taking bytes instead of
      // a string all the way into `prepareImport` is the only way to close
      // it, and that is a caller-wide refactor, not this call site.
      const keyFile = new TextEncoder().encode(text);
      let rejection: string | null;
      try {
        rejection = await sshPrivateKeyFormatRejection(keyFile);
      } finally {
        keyFile.fill(0);
      }
      if (rejection) {
        return {
          keys: [rejectedSshPrivateKey(rejection)],
          secrets: new Map(),
          unparseable: false,
        };
      }
    }

    const lines = splitSshPublicKeyLines(text);
    if (lines.length > 0) {
      const keys: IncomingKey[] = [];
      for (const line of lines) {
        try {
          // The wasm parse is what makes the line canonical; a line it
          // refuses is never stored as a recipient the engine would later
          // reject -- but it IS reported, with the engine's own reason.
          keys.push(sshPublicKey(await parseSshRecipient(line), stored.contacts));
        } catch (error) {
          keys.push(rejectedSshPublicKey(line, engineRejection(error)));
        }
      }
      // Same rule the OpenPGP path applies below: an unusable line
      // alongside usable ones is a stale entry in someone's
      // `authorized_keys`, not something to interrupt the import for.
      const usable = keys.filter((k) => k.status !== "rejected");
      return {
        keys: usable.length > 0 ? usable : keys,
        secrets: new Map(),
        unparseable: false,
      };
    }
  }

  let certs;
  try {
    certs = await parseKeys(text);
  } catch {
    return { keys: [], secrets: new Map(), unparseable: true };
  }
  if (certs.length === 0) {
    return { keys: [], secrets: new Map(), unparseable: true };
  }

  const secrets = new Map<string, string>();
  const classified: IncomingKey[] = [];

  for (const cert of certs) {
    // A private cert re-armors WITH its secret material, so the preview
    // never sees `cert.armored`: the public half is extracted for
    // display and comparison, and the secret half is parked in `secrets`
    // for the protect step alone.
    let publicArmored = cert.armored;
    if (cert.keyInfo.isPrivate) {
      try {
        publicArmored = await extractPublicKey(cert.armored);
      } catch {
        // Can't strip the secret half -- refuse to carry this cert
        // rather than risk private armor reaching the preview.
        continue;
      }
      secrets.set(cert.keyInfo.keyId, cert.armored);
    }
    classified.push(
      await classifyCert(
        cert.keyInfo,
        publicArmored,
        cert.keyInfo.isPrivate ? stored.own : stored.contacts,
      ),
    );
  }

  if (classified.length === 0) {
    return { keys: [], secrets, unparseable: true };
  }

  const usable = classified.filter((k) => k.status !== "rejected");
  return {
    // Rejects are kept only when there's nothing usable to show instead:
    // that's the case where the user needs to be told why.
    keys: usable.length > 0 ? usable : classified,
    secrets,
    unparseable: false,
  };
}

/** Nothing to do -- every key found is already stored, byte for byte.
 *  The panel is skipped in that case: the list just highlights what's
 *  already there. */
export function isNoOp(prepared: PreparedImport): boolean {
  return (
    prepared.keys.length > 0 &&
    prepared.keys.every((k) => k.status === "duplicate")
  );
}

/** The keys that actually write something when imported. */
export function importable(keys: IncomingKey[]): IncomingKey[] {
  return keys.filter((k) => k.status === "new" || k.status === "update");
}
