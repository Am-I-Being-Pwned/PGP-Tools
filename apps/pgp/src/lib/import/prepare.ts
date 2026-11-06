import {
  looksLikeForeignSshPrivateKey,
  splitSshPrivateKeyBlocks,
  splitSshPublicKeyCandidateLines,
} from "~/lib/armor-blocks";
import { t, tn } from "~/lib/i18n";
import { applyRevocation } from "~/lib/import-public-keys";
import {
  extractPublicKey,
  mergePublicKey,
  parseKeys,
  parseSshRecipient,
  sshPrivateKeyFormatRejection,
  type SshRecipientInfo,
} from "~/lib/pgp/wasm";
import { classifyCert, revocationForUnknownKey } from "./classify-pgp";
import {
  crxSigningKey,
  isRsaPrivatePem,
  rejectedSshPrivateKey,
  rejectedSshPublicKey,
  sharedComment,
  sshGroupKey,
  sshMember,
  sshPrivateKey,
  sshPublicKey,
} from "./classify-ssh";
import { withIdentityConflicts } from "./conflicts";
import type { StoredKeys } from "./stored-keys";
import { PENDING_KEY_ID, type IncomingKey } from "./types";

/** Turn pasted/dropped text into the objects the import UI previews. */

/** Which non-OpenPGP engines this import accepts. A disabled engine's key is
 *  not recognised at all (falls through to `unparseable`); the classifier is
 *  the one place that decides what text IS. */
export interface ImportEngines {
  /** RSA signing keys for Chrome extensions (.crx). */
  crx?: boolean;
  /** OpenSSH keys, used with age. */
  ssh?: boolean;
}

/** Placeholder headline; never stored (a blank name imports keys separately). */
function proposalLabel(count: number): string {
  return tn("import_group_proposal_label", count);
}

/** The engine's message (already user-facing prose), or a generic fallback.
 *  Shared with `github.ts` so one refusal has one wording. */
export function engineRejection(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.trim() || t("import_reject_ssh_generic");
}

export interface PreparedImport {
  keys: IncomingKey[];
  /** Private armor per fingerprint, for the protect step only. Deliberately
   *  NOT on IncomingKey, which reaches React state (SECURITY.md zeroization table). */
  secrets: Map<string, string>;
  /** The text carried no OpenPGP certificate at all. */
  unparseable: boolean;
  /**
   * The same keys offered as ONE contact under a user-supplied name. Present
   * only when several new SSH public keys did NOT auto-group: the import must
   * not decide they're one person, so both readings travel and the preview
   * asks. `group.label` is a placeholder replaced before storing.
   */
  groupProposal?: IncomingKey;
}

/**
 * Classify every cert in a blob of armor. When a block has a usable cert, its
 * unusable siblings are stale rotations and are dropped.
 *
 * The ONE place that decides what pasted text is: every engine returns an
 * IncomingKey here rather than short-circuiting the panel.
 */
export async function prepareImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines = {},
): Promise<PreparedImport> {
  const prepared = await classifyImport(text, stored, engines);
  return { ...prepared, keys: withIdentityConflicts(prepared.keys, stored) };
}

async function classifyImport(
  text: string,
  stored: StoredKeys,
  engines: ImportEngines,
): Promise<PreparedImport> {
  // Before the OpenPGP parse. The PEM is secret, so it travels in `secrets`.
  // Before the SSH branch too: a plain PKCS#8 `BEGIN PRIVATE KEY` is valid for
  // both, and CRX can use it; with CRX off the age engine names it (`MSG_PKCS8`).
  if (engines.crx && isRsaPrivatePem(text)) {
    return {
      keys: [crxSigningKey()],
      secrets: new Map([[PENDING_KEY_ID, text.trim()]]),
      unparseable: false,
    };
  }

  if (engines.ssh) {
    // Private first: an OpenSSH container embeds the public half.
    const [sshPrivate] = splitSshPrivateKeyBlocks(text);
    if (sshPrivate) {
      return {
        keys: [sshPrivateKey()],
        secrets: new Map([[PENDING_KEY_ID, sshPrivate]]),
        unparseable: false,
      };
    }

    // Refused formats get the engine's specific message here, before a
    // password is chosen.
    if (looksLikeForeignSshPrivateKey(text)) {
      // `text` may be a COMPLETE unencrypted private key (PKCS#8 with CRX off), so
      // our copy of the bytes is `.fill(0)`'d in `finally`, as at every other
      // secret-bearing call site. `text` itself is an immutable string and can't
      // be zeroized -- this only removes one extra heap copy.
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

    // The CANDIDATE splitter (any `<alg> AAAA<base64>` line), so ECDSA / `sk-*` /
    // `ssh-dss` reach the engine and get its refusal rather than `unparseable`.
    // Invariant: THE ENGINE DECIDES VALIDITY; EVERY LAYER ABOVE IT FORWARDS AND
    // DISPLAYS. `classify-action.ts` and `drop-routing.ts` share this splitter.
    const lines = splitSshPublicKeyCandidateLines(text);
    if (lines.length > 0) {
      const keys: IncomingKey[] = [];
      // Engine output per accepted line; groups are built from it.
      const parsed: SshRecipientInfo[] = [];
      for (const line of lines) {
        try {
          // A refused line is never stored, but IS reported with the engine's reason.
          const info = await parseSshRecipient(line);
          // Dedup on fingerprint: the same line twice is one key.
          if (parsed.some((p) => p.fingerprint === info.fingerprint)) continue;
          parsed.push(info);
          keys.push(sshPublicKey(info, stored));
        } catch (error) {
          keys.push(rejectedSshPublicKey(line, engineRejection(error)));
        }
      }
      // As in the OpenPGP path: an unusable line beside usable ones is stale.
      const usable = keys.filter((k) => k.status !== "rejected");

      if (usable.length > 1) {
        const members = parsed.map(sshMember);
        const shared = sharedComment(parsed);
        if (shared !== null) {
          return {
            keys: [sshGroupKey(shared, members, stored)],
            secrets: new Map(),
            unparseable: false,
          };
        }
        // Might be one person's -- only the user knows, so both readings travel.
        // Only when all are new, so both readings do the same amount of work.
        if (usable.every((k) => k.status === "new")) {
          return {
            keys: usable,
            groupProposal: sshGroupKey(
              proposalLabel(members.length),
              members,
              stored,
            ),
            secrets: new Map(),
            unparseable: false,
          };
        }
      }

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
    // Not a key -- but maybe a bare revocation certificate.
    const revoked = await applyRevocation(
      text,
      stored.contacts.map((c) => ({ keyId: c.keyId, armored: c.armored })),
    );
    if (revoked === "unknown") {
      return {
        keys: [revocationForUnknownKey()],
        secrets: new Map(),
        unparseable: false,
      };
    }
    if (revoked) {
      return {
        keys: [
          await classifyCert(revoked.keyInfo, revoked.armored, stored.contacts),
        ],
        secrets: new Map(),
        unparseable: false,
      };
    }
    return { keys: [], secrets: new Map(), unparseable: true };
  }
  if (certs.length === 0) {
    return { keys: [], secrets: new Map(), unparseable: true };
  }

  const secrets = new Map<string, string>();
  const classified: IncomingKey[] = [];

  for (const cert of certs) {
    // The preview never sees a private `cert.armored`: the public half is
    // extracted for display, the secret half parked in `secrets`.
    let publicArmored = cert.armored;
    if (cert.keyInfo.isPrivate) {
      try {
        publicArmored = await extractPublicKey(cert.armored);
      } catch {
        // Refuse rather than risk private armor reaching the preview.
        continue;
      }
      // First copy wins: a later private copy must not swap in its secret unseen.
      if (!secrets.has(cert.keyInfo.keyId))
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

  const merged = await mergeSameKey(classified, stored);
  const usable = merged.filter((k) => k.status !== "rejected");
  return {
    // Rejects are kept only when there's nothing usable, so the user learns why.
    keys: usable.length > 0 ? usable : merged,
    secrets,
    unparseable: false,
  };
}

/**
 * Several copies of ONE fingerprint in one import, as one row -- otherwise a
 * copy adding a User ID that claims someone else's address could hide behind
 * a harmless one. Public copies are MERGED through the engine and classified
 * once; a private copy keeps only the first (nothing to merge a secret with).
 * Public and private copies of one key stay apart.
 *
 * Exported for backup restore, which classifies a block at a time.
 */
export async function mergeSameKey(
  keys: IncomingKey[],
  stored: StoredKeys,
): Promise<IncomingKey[]> {
  const groupOf = (k: IncomingKey) =>
    k.kind === "pgp-public" || k.kind === "pgp-private"
      ? `${k.kind}:${k.keyId.toUpperCase()}`
      : null;
  const copies = new Map<string, IncomingKey[]>();
  for (const key of keys) {
    const group = groupOf(key);
    if (group === null || key.keyId === PENDING_KEY_ID) continue;
    copies.set(group, [...(copies.get(group) ?? []), key]);
  }
  const out: IncomingKey[] = [];
  const done = new Set<string>();
  for (const key of keys) {
    const group = groupOf(key);
    const same = group === null ? undefined : copies.get(group);
    if (group === null || !same || same.length < 2) {
      out.push(key);
      continue;
    }
    if (done.has(group)) continue;
    done.add(group);
    if (key.kind === "pgp-private") {
      out.push(key);
      continue;
    }
    out.push(await mergeCopies(same, stored));
  }
  return out;
}

/** A copy the engine won't merge is left out rather than failing the import. */
async function mergeCopies(
  copies: IncomingKey[],
  stored: StoredKeys,
): Promise<IncomingKey> {
  let armored = copies[0].publicArmored;
  for (const copy of copies.slice(1)) {
    try {
      armored = await mergePublicKey(armored, copy.publicArmored);
    } catch {
      // Keep what is merged so far.
    }
  }
  try {
    const cert = (await parseKeys(armored)).at(0);
    if (cert)
      return await classifyCert(cert.keyInfo, cert.armored, stored.contacts);
  } catch {
    // Fall through to the first copy as it was classified.
  }
  return copies[0];
}

/** Every key found is already stored byte for byte; the panel is skipped. */
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

export { classifyCert } from "./classify-pgp";
export { claimedIds, withIdentityConflicts } from "./conflicts";
export { storedKeysFrom, type StoredKey, type StoredKeys } from "./stored-keys";
