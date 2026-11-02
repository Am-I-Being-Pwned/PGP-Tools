import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyDetails, KeyInfo } from "~/lib/pgp/types";
import {
  extractPublicKey,
  mergePublicKey,
  parseKeyDetails,
  parseKeys,
  parseSshRecipient,
  revocationIssuers,
  sshPrivateKeyFormatRejection,
} from "~/lib/pgp/wasm";
import {
  classifyCert,
  importable,
  isNoOp,
  mergeSameKey,
  prepareImport,
  withIdentityConflicts,
  type ImportEngines,
  type StoredKey,
  type StoredKeys,
} from "./prepare";
import { defaultDecision } from "./review";
import { PENDING_KEY_ID, type IncomingKey } from "./types";

const AGE_RS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "gpg-wasm",
  "src",
  "age.rs",
);

/** A `const NAME: &str = "..."` from age.rs, matched on the declaration. */
function ageMessage(name: string): string {
  const src = readFileSync(AGE_RS, "utf8");
  const re = new RegExp(
    `\\bconst\\s+${name}\\s*:\\s*&(?:'static\\s+)?str\\s*=\\s*"((?:[^"\\\\]|\\\\.)*)"\\s*;`,
  );
  const match = re.exec(src);
  if (!match) throw new Error(`${name} not found in gpg-wasm/src/age.rs`);
  return JSON.parse(`"${match[1]}"`) as string;
}

/** The bit-count messages are `format!` builders; template read from the fn body. */
function ageBitsMessage(fn: string, bits: number): string {
  const src = readFileSync(AGE_RS, "utf8");
  const re = new RegExp(
    `fn\\s+${fn}\\s*\\([^)]*\\)\\s*->\\s*String\\s*\\{\\s*format!\\(\\s*"((?:[^"\\\\]|\\\\.)*)"`,
  );
  const match = re.exec(src);
  if (!match) throw new Error(`${fn} not found in gpg-wasm/src/age.rs`);
  return (JSON.parse(`"${match[1]}"`) as string).replace(
    /\{bits\}/g,
    String(bits),
  );
}

const rsaTooSmall = (bits: number) => ageBitsMessage("msg_rsa_too_small", bits);
const rsaTooLarge = (bits: number) => ageBitsMessage("msg_rsa_too_large", bits);

// WASM isn't available under vitest; parsing is covered by the Rust tests.
vi.mock("../pgp/wasm", () => ({
  parseKeys: vi.fn(),
  parseKeyDetails: vi.fn(),
  extractPublicKey: vi.fn(),
  parseSshRecipient: vi.fn(),
  sshPrivateKeyFormatRejection: vi.fn(),
  mergePublicKey: vi.fn(),
  revocationIssuers: vi.fn(),
}));

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 7, 23);
const FP = "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11";

function info(over: Partial<KeyInfo> = {}): KeyInfo {
  return {
    keyId: FP,
    userIds: ["Alice <alice@example.com>"],
    algorithm: "ed25519",
    createdAt: NOW - 400 * DAY,
    expiresAt: NOW + 400 * DAY,
    isPrivate: false,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  };
}

function details(fingerprints: string[]): KeyDetails {
  return {
    truncated: false,
    keys: fingerprints.map((fingerprint, i) => ({
      fingerprint,
      keyId: fingerprint.slice(-16),
      algorithm: "ed25519",
      createdAt: NOW - 400 * DAY,
      expiresAt: null,
      isPrimary: i === 0,
      canSign: true,
      canEncrypt: false,
      canCertify: true,
      canAuthenticate: false,
      status: "active" as const,
    })),
  };
}

function storedKey(over: Partial<StoredKey> = {}): StoredKey {
  return {
    keyId: FP,
    userIds: ["Alice <alice@example.com>"],
    armored: "ARMOR-A",
    addedAt: NOW - 30 * DAY,
    expiresAt: NOW + 400 * DAY,
    ...over,
  };
}

const noStores: StoredKeys = { own: [], contacts: [] };

beforeEach(() => {
  vi.mocked(parseKeys).mockReset();
  vi.mocked(extractPublicKey).mockReset();
  vi.mocked(parseKeyDetails).mockReset();
  vi.mocked(parseKeyDetails).mockResolvedValue(details([FP]));
  vi.mocked(mergePublicKey).mockReset();
  vi.mocked(mergePublicKey).mockImplementation((_stored, incoming) =>
    Promise.resolve(incoming),
  );
  vi.mocked(revocationIssuers).mockReset();
  vi.mocked(revocationIssuers).mockResolvedValue(null);
});

/** Stored armor parses as `stored`, the engine's merge result as `merged`. */
function parsesAs(stored: KeyInfo, merged: KeyInfo) {
  vi.mocked(mergePublicKey).mockResolvedValue("MERGED");
  vi.mocked(parseKeys).mockImplementation((armored) =>
    Promise.resolve([
      armored === "MERGED"
        ? { keyInfo: merged, armored: "MERGED" }
        : { keyInfo: stored, armored },
    ]),
  );
}

const revokedInfo = () =>
  info({ usableForEncryption: false, usableForSigning: false, revoked: true });

describe("classifyCert: a contact we already hold", () => {
  it("previews the MERGE of both copies, never the incoming one verbatim", async () => {
    parsesAs(info(), info());
    const result = await classifyCert(info(), "ARMOR-OLD-COPY", [storedKey()]);
    expect(mergePublicKey).toHaveBeenCalledWith("ARMOR-A", "ARMOR-OLD-COPY");
    expect(result.publicArmored).toBe("MERGED");
  });

  it("turns a revoked copy into an update that says so, not a rejection", async () => {
    // Rejecting it would leave the stale copy live, still verifying green.
    parsesAs(info(), revokedInfo());
    const result = await classifyCert(revokedInfo(), "ARMOR-REVOKED", [
      storedKey(),
    ]);
    expect(result.status).toBe("update");
    expect(result.changes).toContain("Revoked by its owner");
    expect(result.info?.revoked).toBe(true);
  });

  it("still rejects a revoked key nobody holds", async () => {
    const result = await classifyCert(revokedInfo(), "ARMOR-REVOKED", []);
    expect(result.status).toBe("rejected");
    expect(mergePublicKey).not.toHaveBeenCalled();
  });

  it("leaves own keys (private imports) out of the merge", async () => {
    await classifyCert(info({ isPrivate: true }), "ARMOR-PUB", [storedKey()]);
    expect(mergePublicKey).not.toHaveBeenCalled();
  });
});

describe("prepareImport: a bare revocation certificate", () => {
  it("revokes the stored contact it names", async () => {
    vi.mocked(revocationIssuers).mockResolvedValue([FP.slice(-16)]);
    parsesAs(info(), revokedInfo());
    vi.mocked(parseKeys).mockImplementation((armored) =>
      armored === "REVOCATION"
        ? Promise.reject(new Error("Unrecognized token Signature Packet"))
        : Promise.resolve([
            armored === "MERGED"
              ? { keyInfo: revokedInfo(), armored: "MERGED" }
              : { keyInfo: info(), armored },
          ]),
    );

    const prepared = await prepareImport("REVOCATION", {
      own: [],
      contacts: [storedKey()],
    });

    expect(prepared.unparseable).toBe(false);
    expect(prepared.keys[0]).toMatchObject({
      status: "update",
      publicArmored: "MERGED",
    });
    expect(prepared.keys[0].changes).toContain("Revoked by its owner");
  });

  it("says it names a key you don't have, rather than 'not a key'", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("Signature Packet"));
    vi.mocked(revocationIssuers).mockResolvedValue(["0123456789ABCDEF"]);

    const prepared = await prepareImport("REVOCATION", noStores);

    expect(prepared.keys[0].status).toBe("rejected");
    expect(prepared.keys[0].rejection).toMatch(/key you don't have/);
  });
});

describe("classifyCert", () => {
  it("marks an unknown fingerprint as new", async () => {
    const result = await classifyCert(info(), "ARMOR-A", []);
    expect(result.status).toBe("new");
    expect(result.kind).toBe("pgp-public");
    expect(result.changes).toEqual([]);
  });

  it("marks byte-identical armor as a duplicate, with the stored date", async () => {
    const result = await classifyCert(info(), "ARMOR-A", [storedKey()]);
    expect(result.status).toBe("duplicate");
    expect(result.existingAddedAt).toBe(NOW - 30 * DAY);
  });

  it("ignores line-ending and whitespace differences when deduping", async () => {
    const result = await classifyCert(info(), "ARMOR-A\r\n  ", [
      storedKey({ armored: "ARMOR-A\n" }),
    ]);
    expect(result.status).toBe("duplicate");
  });

  it("reports an extended expiry as an update", async () => {
    const result = await classifyCert(
      info({ expiresAt: NOW + 900 * DAY }),
      "ARMOR-B",
      [storedKey()],
    );
    expect(result.status).toBe("update");
    expect(result.changes.join(" ")).toMatch(/new expiry/i);
  });

  it("reports added user IDs as an update", async () => {
    const result = await classifyCert(
      info({
        userIds: ["Alice <alice@example.com>", "Alice <a@work.example>"],
      }),
      "ARMOR-B",
      [storedKey()],
    );
    expect(result.status).toBe("update");
    expect(result.changes.join(" ")).toMatch(/1 new user ID/);
  });

  it("reports added subkeys as an update", async () => {
    vi.mocked(parseKeyDetails)
      .mockResolvedValueOnce(details([FP, "SUB-1", "SUB-2"])) // incoming
      .mockResolvedValueOnce(details([FP, "SUB-1"])); // stored
    const result = await classifyCert(info(), "ARMOR-B", [storedKey()]);
    expect(result.status).toBe("update");
    expect(result.changes).toContain("1 new subkey");
  });

  it("still explains an update whose visible fields all match", async () => {
    const result = await classifyCert(info(), "ARMOR-B", [storedKey()]);
    expect(result.status).toBe("update");
    expect(result.changes).toEqual(["The key has been re-issued"]);
  });

  it("rejects a key that is neither encryption- nor signing-capable", async () => {
    const result = await classifyCert(
      info({ usableForEncryption: false, usableForSigning: false }),
      "ARMOR-A",
      [],
    );
    expect(result.status).toBe("rejected");
    expect(result.rejection).toBeTruthy();
  });

  it("explains an expired key with its date", async () => {
    const result = await classifyCert(
      info({
        expiresAt: NOW - 10 * DAY,
        usableForEncryption: false,
        usableForSigning: false,
      }),
      "ARMOR-A",
      [],
    );
    expect(result.status).toBe("rejected");
    expect(result.rejection).toMatch(/expired/i);
  });

  it("previews from KeyInfo alone when the breakdown fails to parse", async () => {
    vi.mocked(parseKeyDetails).mockRejectedValue(new Error("bad cert"));
    const result = await classifyCert(info(), "ARMOR-A", []);
    expect(result.status).toBe("new");
    expect(result.details).toBeNull();
    expect(result.info).not.toBeNull();
  });
});

describe("prepareImport", () => {
  it("flags text that carries no certificate", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("no cert"));
    const prepared = await prepareImport("hello", noStores);
    expect(prepared.unparseable).toBe(true);
    expect(prepared.keys).toEqual([]);
  });

  it("classifies every cert in a bundle", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
      { keyInfo: info({ keyId: "OTHER" }), armored: "ARMOR-C" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(prepared.keys.map((k) => k.status)).toEqual(["duplicate", "new"]);
  });

  it("drops stale rotations when a live cert is present", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      {
        keyInfo: info({
          keyId: "OLD",
          usableForEncryption: false,
          usableForSigning: false,
        }),
        armored: "ARMOR-OLD",
      },
      { keyInfo: info({ keyId: "LIVE" }), armored: "ARMOR-LIVE" },
    ]);
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].keyId).toBe("LIVE");
  });

  it("keeps the rejects when nothing in the blob is usable", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      {
        keyInfo: info({
          usableForEncryption: false,
          usableForSigning: false,
        }),
        armored: "ARMOR-OLD",
      },
    ]);
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys.map((k) => k.status)).toEqual(["rejected"]);
  });

  it("keeps private armor out of the preview and parks it in secrets", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("PUBLIC-ARMOR");

    const prepared = await prepareImport("blob", noStores);
    const key = prepared.keys[0];
    expect(key.kind).toBe("pgp-private");
    expect(key.publicArmored).toBe("PUBLIC-ARMOR");
    expect(JSON.stringify(key)).not.toContain("PRIVATE-ARMOR");
    expect(prepared.secrets.get(FP)).toBe("PRIVATE-ARMOR");
  });

  it("drops a private cert whose secret half cannot be stripped", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockRejectedValue(new Error("nope"));

    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toEqual([]);
    expect(prepared.unparseable).toBe(true);
  });

  it("matches a private import against the keyring, not contacts", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("ARMOR-A");

    const prepared = await prepareImport("blob", {
      own: [storedKey({ createdAt: NOW - 90 * DAY, addedAt: undefined })],
      contacts: [],
    });
    expect(prepared.keys[0].status).toBe("duplicate");
    expect(prepared.keys[0].existingAddedAt).toBe(NOW - 90 * DAY);
  });
});

describe("prepareImport: CRX signing keys", () => {
  const PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";

  it("classifies a raw RSA PEM without touching the OpenPGP parser", async () => {
    const prepared = await prepareImport(PEM, noStores, { crx: true });
    expect(prepared.unparseable).toBe(false);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].kind).toBe("crx");
    expect(prepared.keys[0].status).toBe("new");
    // Null, not "still loading".
    expect(prepared.keys[0].info).toBeNull();
    expect(prepared.keys[0].details).toBeNull();
    expect(parseKeys).not.toHaveBeenCalled();
  });

  it("keeps the PEM out of the previewed key and parks it in secrets", async () => {
    const prepared = await prepareImport(PEM, noStores, { crx: true });
    expect(JSON.stringify(prepared.keys[0])).not.toContain("MIIE");
    expect(prepared.secrets.get(PENDING_KEY_ID)).toBe(PEM.trim());
  });

  it("does not recognise a PEM at all when the engine is off", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("no cert"));
    const prepared = await prepareImport(PEM, noStores);
    expect(prepared.unparseable).toBe(true);
    expect(prepared.keys).toEqual([]);
  });

  it("leaves an OpenPGP private key to the OpenPGP parser", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("PUBLIC-ARMOR");

    const prepared = await prepareImport(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----",
      noStores,
      { crx: true },
    );
    expect(prepared.keys[0].kind).toBe("pgp-private");
  });
});

describe("isNoOp / importable", () => {
  it("is a no-op only when every key is already stored", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(isNoOp(prepared)).toBe(true);
    expect(importable(prepared.keys)).toEqual([]);
  });

  it("is not a no-op when one key of a bundle is new", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
      { keyInfo: info({ keyId: "OTHER" }), armored: "ARMOR-C" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(isNoOp(prepared)).toBe(false);
    expect(importable(prepared.keys)).toHaveLength(1);
  });

  it("an empty result is not a no-op", () => {
    expect(isNoOp({ keys: [], secrets: new Map(), unparseable: true })).toBe(
      false,
    );
  });
});

describe("no secret material reaches an IncomingKey", () => {
  /** Private key headers. Secret armor belongs only in `PreparedImport.secrets`,
   *  never on `IncomingKey` (React state / preview). */
  const PRIVATE_HEADERS = [
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
  ];

  function expectNoSecrets(keys: { publicArmored: string }[]) {
    for (const key of keys) {
      const serialized = JSON.stringify(key);
      for (const header of PRIVATE_HEADERS) {
        expect(serialized).not.toContain(header);
        expect(key.publicArmored).not.toContain(header);
      }
    }
  }

  it("holds for a mixed bundle of public and private OpenPGP certs", async () => {
    // Catches `extractPublicKey` returning its input: the private cert would
    // ride into the preview as `publicArmored`.
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\npub" },
      {
        keyInfo: info({ keyId: "OTHER", isPrivate: true }),
        armored: `${PRIVATE_HEADERS[0]}\nsecret`,
      },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue(
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nderived",
    );

    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(2);
    expectNoSecrets(prepared.keys);
    expect(prepared.secrets.get("OTHER")).toContain(PRIVATE_HEADERS[0]);
  });

  it("holds for a CRX PKCS#8 PEM, which has no public half at all", async () => {
    const pem = `${PRIVATE_HEADERS[1]}\nMIIEvQ\n-----END PRIVATE KEY-----\n`;
    const prepared = await prepareImport(pem, noStores, { crx: true });

    expectNoSecrets(prepared.keys);
    expect(prepared.keys[0].publicArmored).toBe("");
    expect(prepared.secrets.get(PENDING_KEY_ID)).toBe(pem.trim());
  });
});

/** The age engine is recognised here like any other; with `engines.ssh` off
 *  an SSH key isn't refused but unrecognised (`unparseable`). */
describe("prepareImport - SSH / age", () => {
  const ED25519_PUB =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com";
  const SSH_FP = "SHA256:6xN1hCbYYQnEo3sB1Wp2sTQnAo1cvxKcYLW9sQvfR0Q";
  const CANONICAL =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6";
  const OPENSSH_PRIVATE =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----";

  beforeEach(() => {
    vi.mocked(parseSshRecipient).mockReset();
    vi.mocked(sshPrivateKeyFormatRejection).mockReset();
    vi.mocked(sshPrivateKeyFormatRejection).mockResolvedValue(null);
    vi.mocked(parseSshRecipient).mockResolvedValue({
      recipient: CANONICAL,
      algorithm: "ssh-ed25519",
      fingerprint: SSH_FP,
      comment: "alice@example.com",
    });
  });

  it("classifies a .pub line as an ssh-public key named by its comment", async () => {
    const prepared = await prepareImport(ED25519_PUB, noStores, { ssh: true });

    expect(prepared.unparseable).toBe(false);
    expect(prepared.keys).toHaveLength(1);
    const [key] = prepared.keys;
    expect(key.kind).toBe("ssh-public");
    expect(key.status).toBe("new");
    expect(key.keyId).toBe(SSH_FP);
    expect(key.info).toBeNull();
    expect(key.details).toBeNull();
    expect(key.userIds).toEqual(["alice@example.com"]);
    // The canonical line, not the pasted one.
    expect(key.publicArmored).toBe(CANONICAL);
    // A public half never travels in `secrets`.
    expect(prepared.secrets.size).toBe(0);
  });

  it("names an SSH key with no comment without pretending it has one", async () => {
    vi.mocked(parseSshRecipient).mockResolvedValue({
      recipient: CANONICAL,
      algorithm: "ssh-ed25519",
      fingerprint: SSH_FP,
      comment: "",
    });
    const [key] = (await prepareImport(CANONICAL, noStores, { ssh: true }))
      .keys;
    expect(key.userIds).toEqual(["SSH key"]);
  });

  it("marks an already-stored fingerprint as a duplicate, never an update", async () => {
    // Same fingerprint is the same key: never an `update`.
    const prepared = await prepareImport(
      ED25519_PUB,
      { own: [], contacts: [storedKey({ keyId: SSH_FP, armored: CANONICAL })] },
      { ssh: true },
    );
    expect(prepared.keys[0].status).toBe("duplicate");
    expect(isNoOp(prepared)).toBe(true);
  });

  /**
   * Grouping several pasted `.pub` lines into ONE contact: AUTOMATIC only when
   * every line has a byte-identical comment (anything looser is a guess that
   * could fold two people into one); otherwise MANUAL -- both readings travel
   * and the preview asks.
   */
  describe("grouping several pasted keys", () => {
    function stubLines(comments: string[]) {
      const mock = vi.mocked(parseSshRecipient);
      mock.mockReset();
      for (const [i, comment] of comments.entries()) {
        mock.mockResolvedValueOnce({
          recipient: `ssh-ed25519 AAAAkey${i}`,
          algorithm: "ssh-ed25519",
          fingerprint: `SHA256:key${i}`,
          comment,
        });
      }
      return comments.map((_, i) => `ssh-ed25519 AAAAkey${i} c${i}`).join("\n");
    }

    it("files keys that agree on a comment as ONE contact, unasked", async () => {
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(text, noStores, { ssh: true });

      expect(prepared.keys).toHaveLength(1);
      const [key] = prepared.keys;
      expect(key.kind).toBe("ssh-public");
      expect(key.status).toBe("new");
      expect(key.userIds).toEqual(["alice@laptop"]);
      expect(key.group?.members.map((m) => m.keyId)).toEqual([
        "SHA256:key0",
        "SHA256:key1",
      ]);
      expect(key.keyId).toBe("SHA256:key0");
      expect(key.publicArmored).toBe("ssh-ed25519 AAAAkey0");
      expect(key.group?.source).toBeUndefined();
      expect(prepared.groupProposal).toBeUndefined();
    });

    it("counts a line pasted twice as one key", async () => {
      // No duplicate stanza; "N keys added" counts keys.
      const mock = vi.mocked(parseSshRecipient);
      mock.mockReset();
      for (const i of [0, 1, 0]) {
        mock.mockResolvedValueOnce({
          recipient: `ssh-ed25519 AAAAkey${i}`,
          algorithm: "ssh-ed25519",
          fingerprint: `SHA256:key${i}`,
          comment: "alice@laptop",
        });
      }
      const text = [0, 1, 0]
        .map((i) => `ssh-ed25519 AAAAkey${i} alice@laptop`)
        .join("\n");
      const prepared = await prepareImport(text, noStores, { ssh: true });
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].group?.members.map((m) => m.keyId)).toEqual([
        "SHA256:key0",
        "SHA256:key1",
      ]);

      // The same key twice and nothing else is one key, not a group.
      mock.mockReset();
      mock.mockResolvedValue({
        recipient: "ssh-ed25519 AAAAkey0",
        algorithm: "ssh-ed25519",
        fingerprint: "SHA256:key0",
        comment: "",
      });
      const twice = await prepareImport(
        "ssh-ed25519 AAAAkey0\nssh-ed25519 AAAAkey0",
        noStores,
        { ssh: true },
      );
      expect(twice.keys).toHaveLength(1);
      expect(twice.keys[0].group).toBeUndefined();
      expect(twice.groupProposal).toBeUndefined();
    });

    it("never groups keys whose comments disagree", async () => {
      const text = stubLines(["alice@laptop", "alice@desktop", ""]);
      const prepared = await prepareImport(text, noStores, { ssh: true });

      expect(prepared.keys).toHaveLength(3);
      expect(prepared.keys.every((k) => k.group === undefined)).toBe(true);
      expect(importable(prepared.keys)).toHaveLength(3);

      const proposal = prepared.groupProposal;
      expect(proposal?.group?.members.map((m) => m.keyId)).toEqual([
        "SHA256:key0",
        "SHA256:key1",
        "SHA256:key2",
      ]);
      expect(proposal?.status).toBe("new");
      expect(proposal?.group?.source).toBeUndefined();
    });

    it("does not treat two missing comments as agreement", async () => {
      // `user@host` twice is a statement; nothing twice is not one.
      const prepared = await prepareImport(stubLines(["", ""]), noStores, {
        ssh: true,
      });
      expect(prepared.keys).toHaveLength(2);
      expect(prepared.groupProposal).toBeDefined();
    });

    it("offers nothing for a single key", async () => {
      const prepared = await prepareImport(
        stubLines(["alice@laptop"]),
        noStores,
        {
          ssh: true,
        },
      );
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].group).toBeUndefined();
      expect(prepared.groupProposal).toBeUndefined();
    });

    it("offers nothing once one of the keys is already stored", async () => {
      const text = stubLines(["alice@laptop", "alice@desktop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            storedKey({
              keyId: "SHA256:key1",
              armored: "ssh-ed25519 AAAAkey1",
            }),
          ],
        },
        { ssh: true },
      );
      expect(prepared.groupProposal).toBeUndefined();
      expect(prepared.keys.map((k) => k.status)).toEqual(["new", "duplicate"]);
    });

    const alice = (over: Partial<StoredKey> = {}): StoredKey =>
      storedKey({
        keyId: "SHA256:key0",
        userIds: ["alice@laptop"],
        armored: "ssh-ed25519 AAAAkey0",
        ...over,
      });

    it("never files a group holding a contact's key as new over that contact", async () => {
      // Attack (a): Alice's real key plus Mallory's, both `alice@laptop`.
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(
        text,
        { own: [], contacts: [alice()] },
        { ssh: true },
      );
      const [key] = prepared.keys;
      expect(key.status).toBe("update");
      expect(key.keyId).toBe("SHA256:key0");
      expect(key.changes).toEqual(["1 key added"]);
      expect(key.conflict?.kind).toBe("key");
      expect(key.conflict?.holders.map((h) => h.keyId)).toEqual([
        "SHA256:key0",
      ]);
      expect(defaultDecision(key)).toBe("skip");
    });

    it("heads it with the contact's key whichever line came first", async () => {
      // Mallory's line first: still lands on Alice's record, still asks.
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(
        text,
        { own: [], contacts: [alice({ keyId: "SHA256:key1" })] },
        { ssh: true },
      );
      const [key] = prepared.keys;
      expect(key.status).toBe("update");
      expect(key.group?.members.map((m) => m.keyId)).toEqual([
        "SHA256:key1",
        "SHA256:key0",
      ]);
      expect(key.keyId).toBe("SHA256:key1");
      expect(defaultDecision(key)).toBe("skip");
    });

    it("never heads a group with the user's own key, and asks", async () => {
      // Attack (c): the user's own key plus an attacker's under one comment
      // must not hide "You" in the picker.
      const text = stubLines(["me@laptop", "me@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [storedKey({ keyId: "SHA256:key0", userIds: ["me@laptop"] })],
          contacts: [],
        },
        { ssh: true },
      );
      const [key] = prepared.keys;
      expect(key.status).toBe("new");
      expect(key.keyId).toBe("SHA256:key1");
      expect(key.conflict?.kind).toBe("key");
      expect(key.conflict?.holders[0].own).toBe(true);
      expect(defaultDecision(key)).toBe("skip");
    });

    it("saves nothing for a group made only of keys the user holds", async () => {
      const text = stubLines(["me@laptop", "me@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [storedKey({ keyId: "SHA256:key0" })],
          contacts: [alice({ keyId: "SHA256:key1" })],
        },
        { ssh: true },
      );
      expect(prepared.keys[0].status).toBe("duplicate");
      expect(importable(prepared.keys)).toEqual([]);
    });

    it("never heads a group with a key from a fetched contact", async () => {
      // A paste never lands on a fetched person: new record, headed by the key
      // nobody holds.
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            alice({
              source: { type: "github", user: "alice", fetchedAt: 1 },
            }),
          ],
        },
        { ssh: true },
      );
      const [key] = prepared.keys;
      expect(key.status).toBe("new");
      expect(key.keyId).toBe("SHA256:key1");
      expect(key.conflict?.kind).toBe("key");
    });

    it("sees a key held inside a contact's group, not only its head", async () => {
      const text = stubLines(["bob@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            storedKey({
              keyId: "SHA256:other",
              recipientIds: ["SHA256:other", "SHA256:key0"],
            }),
          ],
        },
        { ssh: true },
      );
      expect(prepared.keys[0].status).toBe("duplicate");
    });

    it("calls the user's own key pasted back in a duplicate", async () => {
      const prepared = await prepareImport(
        stubLines(["me@laptop"]),
        { own: [storedKey({ keyId: "SHA256:key0" })], contacts: [] },
        { ssh: true },
      );
      expect(prepared.keys[0].status).toBe("duplicate");
    });

    it("strips invisible characters from a comment before it names anyone", async () => {
      const prepared = await prepareImport(
        stubLines(["alice@corp\u200b.com\u202e"]),
        noStores,
        { ssh: true },
      );
      expect(prepared.keys[0].userIds).toEqual(["alice@corp.com"]);
    });

    it("calls a group of already-stored keys a duplicate, not an import", async () => {
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            storedKey({
              keyId: "SHA256:key0",
              armored: "ssh-ed25519 AAAAkey0",
            }),
            storedKey({
              keyId: "SHA256:key1",
              armored: "ssh-ed25519 AAAAkey1",
            }),
          ],
        },
        { ssh: true },
      );
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].status).toBe("duplicate");
      expect(importable(prepared.keys)).toEqual([]);
    });
  });

  it("classifies each line of an authorized_keys paste", async () => {
    vi.mocked(parseSshRecipient)
      .mockResolvedValueOnce({
        recipient: CANONICAL,
        algorithm: "ssh-ed25519",
        fingerprint: SSH_FP,
        comment: "alice@example.com",
      })
      .mockResolvedValueOnce({
        recipient: "ssh-rsa AAAAB3NzaC1yc2E",
        algorithm: "ssh-rsa",
        fingerprint: "SHA256:other",
        comment: "bob@host",
      });

    const prepared = await prepareImport(
      `${ED25519_PUB}\nssh-rsa AAAAB3NzaC1yc2E bob@host`,
      noStores,
      { ssh: true },
    );
    expect(prepared.keys.map((k) => k.keyId)).toEqual([SSH_FP, "SHA256:other"]);
  });

  it("reports a line the engine refuses instead of storing a bad recipient", async () => {
    vi.mocked(parseSshRecipient).mockRejectedValue(new Error("unsupported"));
    const prepared = await prepareImport(ED25519_PUB, noStores, { ssh: true });
    // Reported, not imported: `rejected` is never `importable`.
    expect(importable(prepared.keys)).toEqual([]);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].status).toBe("rejected");
    // It parsed fine; it is unusable, not "not a key".
    expect(prepared.unparseable).toBe(false);
  });

  it("keeps a usable line and drops its unusable siblings", async () => {
    // A stale entry beside a usable key doesn't interrupt the import.
    vi.mocked(parseSshRecipient)
      .mockRejectedValueOnce(new Error("ECDSA SSH keys can't be used"))
      .mockResolvedValueOnce({
        recipient: CANONICAL,
        algorithm: "ssh-ed25519",
        fingerprint: SSH_FP,
        comment: "alice@example.com",
      });

    const prepared = await prepareImport(
      `ssh-rsa AAAAB3NzaC1yc2E ec@host\n${ED25519_PUB}`,
      noStores,
      { ssh: true },
    );
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].status).toBe("new");
  });

  /** Whatever the engine's curated rejection says arrives verbatim on the
   *  IncomingKey (the wording itself is pinned by the Rust tests). */
  describe("surfaces the engine's rejection verbatim", () => {
    // Read from `gpg-wasm/src/age.rs`, not transcribed: the Rust is the single
    // source of truth, and these cases mock the wasm boundary so a stale copy
    // would never fail. Same technique as `lib/protection/aad-prefixes.test.ts`.
    const PUB_MESSAGES = {
      ECDSA: ageMessage("MSG_ECDSA"),
      FIDO: ageMessage("MSG_FIDO"),
      DSA: ageMessage("MSG_DSA"),
      RSA_SMALL: rsaTooSmall(1024),
      RSA_LARGE: rsaTooLarge(8192),
    };

    it.each(Object.entries(PUB_MESSAGES))(
      "%s, off a .pub line",
      async (_name, message) => {
        vi.mocked(parseSshRecipient).mockRejectedValue(new Error(message));
        const prepared = await prepareImport(ED25519_PUB, noStores, {
          ssh: true,
        });
        expect(prepared.keys[0].status).toBe("rejected");
        expect(prepared.keys[0].rejection).toBe(message);
        expect(prepared.unparseable).toBe(false);
      },
    );

    const PKCS8_MESSAGE = ageMessage("MSG_PKCS8");
    const PRIVATE_FILES: [string, string, string, ImportEngines][] = [
      // `crx` is off for the plain PKCS#8 forms only: CRX legitimately owns
      // them otherwise (see `isRsaPrivatePem`).
      [
        "PKCS8",
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
        PKCS8_MESSAGE,
        { ssh: true },
      ],
      [
        "PKCS8_ENCRYPTED",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
        PKCS8_MESSAGE,
        { ssh: true, crx: true },
      ],
      [
        "PPK",
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: k\n",
        ageMessage("MSG_PPK"),
        { ssh: true, crx: true },
      ],
      [
        // Also CRX-shaped, but must not be claimed by it.
        "LEGACY_PEM",
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,5C90\n\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
        ageMessage("MSG_LEGACY_PEM"),
        { ssh: true, crx: true },
      ],
    ];

    it.each(PRIVATE_FILES)(
      "%s, off a private key file",
      async (_name, file, message, engines) => {
        vi.mocked(sshPrivateKeyFormatRejection).mockResolvedValue(message);
        const prepared = await prepareImport(file, noStores, engines);
        expect(prepared.keys).toHaveLength(1);
        expect(prepared.keys[0].kind).toBe("ssh-private");
        expect(prepared.keys[0].status).toBe("rejected");
        expect(prepared.keys[0].rejection).toBe(message);
        // Rejected, not imported: nothing is carried to the protect step.
        expect(prepared.secrets.size).toBe(0);
        expect(importable(prepared.keys)).toEqual([]);
      },
    );

    it.each([
      [
        "PKCS#1",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n",
      ],
      [
        "PKCS#8",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----\n",
      ],
      ["a PGP block", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ==\n"],
    ])("does not steal %s from the engine that owns it", async (name, pem) => {
      vi.mocked(parseKeys).mockResolvedValue([]);
      const prepared = await prepareImport(pem, noStores, {
        ssh: true,
        crx: true,
      });
      expect(prepared.keys[0]?.kind ?? "none").toBe(
        name === "a PGP block" ? "none" : "crx",
      );
      expect(sshPrivateKeyFormatRejection).not.toHaveBeenCalled();
    });

    it("leaves a real OpenSSH container alone", async () => {
      const prepared = await prepareImport(OPENSSH_PRIVATE, noStores, {
        ssh: true,
      });
      expect(prepared.keys[0].status).toBe("new");
      expect(sshPrivateKeyFormatRejection).not.toHaveBeenCalled();
    });

    // The buffer crossing the wasm boundary is a COMPLETE private key file. The
    // mock retains the actual buffer: it must carry the key at call time and be
    // all-zero once `prepareImport` settles (behavioural proof of the scrub).
    describe("scrubs the key-file buffer handed to wasm", () => {
      const PKCS8 =
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
      let captured: Uint8Array | null = null;

      beforeEach(() => {
        captured = null;
      });

      /** Checking the buffer during the call keeps the zero check from passing vacuously. */
      function capture(outcome: () => string | null) {
        vi.mocked(sshPrivateKeyFormatRejection).mockImplementation(
          (keyFile: Uint8Array) => {
            captured = keyFile;
            expect(new TextDecoder().decode(keyFile)).toBe(PKCS8);
            return Promise.resolve(outcome());
          },
        );
      }

      function expectScrubbed() {
        const buffer: Uint8Array | null = captured;
        if (buffer === null) throw new Error("wasm was never called");
        expect(buffer.length).toBeGreaterThan(0);
        expect(buffer.every((byte) => byte === 0)).toBe(true);
      }

      it("when the engine names the format and the import is rejected", async () => {
        capture(() => PKCS8_MESSAGE);
        const prepared = await prepareImport(PKCS8, noStores, { ssh: true });
        expect(prepared.keys[0].status).toBe("rejected");
        expectScrubbed();
      });

      it("when the engine returns null and the text falls through", async () => {
        vi.mocked(parseKeys).mockResolvedValue([]);
        capture(() => null);
        const prepared = await prepareImport(PKCS8, noStores, { ssh: true });
        expect(prepared.unparseable).toBe(true);
        expectScrubbed();
      });

      it("when the wasm call throws", async () => {
        capture(() => {
          throw new Error("wasm exploded");
        });
        await expect(
          prepareImport(PKCS8, noStores, { ssh: true }),
        ).rejects.toThrow("wasm exploded");
        expectScrubbed();
      });
    });
  });

  it("routes an OpenSSH private key to the protect step, armor in `secrets`", async () => {
    const prepared = await prepareImport(OPENSSH_PRIVATE, noStores, {
      ssh: true,
    });

    expect(prepared.keys).toHaveLength(1);
    const [key] = prepared.keys;
    expect(key.kind).toBe("ssh-private");
    expect(key.keyId).toBe(PENDING_KEY_ID);
    // Fingerprint is only recovered at the protect step.
    expect(key.publicArmored).toBe("");
    expect(key.info).toBeNull();
    // The secret half never rides on the IncomingKey.
    expect(prepared.secrets.get(PENDING_KEY_ID)).toBe(OPENSSH_PRIVATE);
    expect(JSON.stringify(prepared.keys)).not.toContain("OPENSSH PRIVATE");
  });

  it("prefers the private container over the public half inside it", async () => {
    // Classifying it as a recipient would drop the secret half.
    const prepared = await prepareImport(
      `${OPENSSH_PRIVATE}\n${ED25519_PUB}`,
      noStores,
      { ssh: true },
    );
    expect(prepared.keys[0].kind).toBe("ssh-private");
  });

  it("does not recognise SSH at all when the engine is off", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("no cert"));
    const prepared = await prepareImport(ED25519_PUB, noStores);
    expect(prepared.unparseable).toBe(true);
    expect(parseSshRecipient).not.toHaveBeenCalled();
  });
});

/**
 * ECDSA, FIDO `sk-*` and DSA `.pub` lines must reach the engine and show its
 * refusal, not `unparseable`. Invariant: THE ENGINE DECIDES VALIDITY; EVERY
 * LAYER ABOVE IT FORWARDS AND DISPLAYS.
 */
describe("prepareImport - refused SSH algorithms reach the user", () => {
  const noStores: StoredKeys = { own: [], contacts: [] };

  beforeEach(() => {
    vi.mocked(parseSshRecipient).mockReset();
    vi.mocked(sshPrivateKeyFormatRejection).mockReset();
    vi.mocked(sshPrivateKeyFormatRejection).mockResolvedValue(null);
    vi.mocked(parseKeys).mockReset();
    vi.mocked(parseKeys).mockRejectedValue(new Error("no cert"));
  });

  const REFUSED: [string, string, string][] = [
    [
      "ECDSA",
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY= alice@host",
      "MSG_ECDSA",
    ],
    [
      "FIDO",
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t alice@host",
      "MSG_FIDO",
    ],
    ["DSA", "ssh-dss AAAAB3NzaC1kc3MAAACBAO0= alice@host", "MSG_DSA"],
  ];

  it.each(REFUSED)(
    "%s: the line is forwarded and the engine's words come back",
    async (_name, line, constant) => {
      const message = ageMessage(constant);
      vi.mocked(parseSshRecipient).mockRejectedValue(new Error(message));

      const prepared = await prepareImport(line, noStores, { ssh: true });

      expect(parseSshRecipient).toHaveBeenCalledWith(line);
      expect(prepared.unparseable).toBe(false);
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].kind).toBe("ssh-public");
      expect(prepared.keys[0].status).toBe("rejected");
      expect(prepared.keys[0].rejection).toBe(message);
      expect(prepared.keys[0].publicArmored).toBe(line);
      expect(prepared.secrets.size).toBe(0);
      expect(importable(prepared.keys)).toEqual([]);
    },
  );

  it("still drops a refused line when a usable one sits beside it", async () => {
    vi.mocked(parseSshRecipient)
      .mockRejectedValueOnce(new Error(ageMessage("MSG_ECDSA")))
      .mockResolvedValueOnce({
        recipient: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu",
        algorithm: "ssh-ed25519",
        fingerprint: "SHA256:zzz",
        comment: "alice@host",
      });
    const prepared = await prepareImport(
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo old@host\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu alice@host",
      noStores,
      { ssh: true },
    );
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].status).toBe("new");
  });

  // What must still NOT look like an SSH public line: each belongs to
  // another path.
  it.each([
    ["prose naming a key type", "my ssh-ed25519 key is on the other laptop"],
    ["prose about ECDSA", "we should probably move off ecdsa-sha2-nistp256"],
    ["HTML", "<p>ssh-ed25519 keys are listed below</p>"],
    ["bare base64", "AAAAB3NzaC1yc2EAAAADAQABAAABgQ=="],
    ["a colon-headed armor line", "Comment: AAAAB3NzaC1yc2EAAAADAQAB"],
  ])("does not mistake %s for a key", async (_name, text) => {
    const prepared = await prepareImport(text, noStores, { ssh: true });
    expect(parseSshRecipient).not.toHaveBeenCalled();
    expect(prepared.unparseable).toBe(true);
  });

  it("leaves an armored OpenPGP block to the OpenPGP path", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { armored: "ARMOR-A", keyInfo: info() },
    ]);
    vi.mocked(parseKeyDetails).mockResolvedValue(details([FP]));
    const prepared = await prepareImport(
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGabc\nAAAA+/abc=\n-----END PGP PUBLIC KEY BLOCK-----\n",
      noStores,
      { ssh: true },
    );
    expect(parseSshRecipient).not.toHaveBeenCalled();
    expect(prepared.keys[0].kind).toBe("pgp-public");
  });

  it("leaves a raw RSA PEM to the CRX path", async () => {
    const prepared = await prepareImport(
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA AAAAB3Nza\n-----END RSA PRIVATE KEY-----\n",
      noStores,
      { ssh: true, crx: true },
    );
    expect(parseSshRecipient).not.toHaveBeenCalled();
    expect(prepared.keys[0].kind).toBe("crx");
  });

  it("leaves an OpenSSH private container to the private-key flow", async () => {
    const prepared = await prepareImport(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n",
      noStores,
      { ssh: true },
    );
    expect(parseSshRecipient).not.toHaveBeenCalled();
    expect(prepared.keys[0].kind).toBe("ssh-private");
    expect(prepared.keys[0].status).toBe("new");
  });
});

/** A new public key is checked against held contacts and earlier keys in
 *  the same import; a match is marked so the Review asks. */
describe("prepareImport: a new key claiming someone's identity", () => {
  const NEW_FP = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";

  function bundle(...certs: { keyInfo: KeyInfo; armored: string }[]) {
    vi.mocked(parseKeys).mockImplementation((armored) =>
      Promise.resolve(
        armored === "blob" ? certs : [{ keyInfo: info(), armored }],
      ),
    );
  }

  const withAlice: StoredKeys = { own: [], contacts: [storedKey()] };

  it("marks the new key in the advisory's bundle, never the update", async () => {
    bundle(
      { keyInfo: info(), armored: "ARMOR-STRIPPED" },
      { keyInfo: info({ keyId: NEW_FP }), armored: "ARMOR-IMPOSTOR" },
    );

    const prepared = await prepareImport("blob", withAlice);

    const [update, impostor] = prepared.keys;
    expect(update.status).toBe("update");
    expect(update.conflict).toBeUndefined();
    expect(impostor.status).toBe("new");
    expect(impostor.conflict?.kind).toBe("address");
    expect(impostor.conflict?.holders[0].keyId).toBe(FP);
    expect(impostor.conflict?.holders.every((h) => h.keyId === FP)).toBe(true);
  });

  it("leaves the same name under a different address alone", async () => {
    // Shared plain names are fine; only a LOOKALIKE name is asked.
    bundle({
      keyInfo: info({
        keyId: NEW_FP,
        userIds: ["Alice <alice@elsewhere.example>"],
      }),
      armored: "ARMOR-B",
    });
    const prepared = await prepareImport("blob", withAlice);
    expect(prepared.keys[0].conflict).toBeUndefined();
  });

  it("marks a look-alike name (Cyrillic \u0410) as a name clash", async () => {
    bundle({
      keyInfo: info({
        keyId: NEW_FP,
        userIds: ["\u0410lice <alice@elsewhere.example>"],
      }),
      armored: "ARMOR-B",
    });
    const prepared = await prepareImport("blob", withAlice);
    expect(prepared.keys[0].conflict?.kind).toBe("name");
  });

  it("marks BOTH new keys in one bundle claiming one address", async () => {
    // An attacker picks the order, so the first must not default to Import.
    const OTHER_FP = "C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0";
    bundle(
      { keyInfo: info({ keyId: NEW_FP }), armored: "ARMOR-B" },
      { keyInfo: info({ keyId: OTHER_FP }), armored: "ARMOR-C" },
    );
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys[0].conflict).toMatchObject({
      kind: "address",
      holders: [{ keyId: OTHER_FP, incoming: true }],
    });
    expect(prepared.keys[1].conflict).toMatchObject({
      kind: "address",
      holders: [{ keyId: NEW_FP, incoming: true }],
    });
  });

  it("still asks about the address of a revoked contact, naming it", async () => {
    bundle({ keyInfo: info({ keyId: NEW_FP }), armored: "ARMOR-B" });
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey({ revoked: true })],
    });
    expect(prepared.keys[0].status).toBe("new");
    expect(prepared.keys[0].conflict).toMatchObject({
      kind: "address",
      holders: [{ keyId: FP, revoked: true }],
    });
  });

  it("leaves an unrelated new key alone", async () => {
    bundle({
      keyInfo: info({ keyId: NEW_FP, userIds: ["Bob <bob@example.com>"] }),
      armored: "ARMOR-B",
    });
    const prepared = await prepareImport("blob", withAlice);
    expect(prepared.keys[0].conflict).toBeUndefined();
  });
});

describe("withIdentityConflicts", () => {
  function incoming(over: Partial<IncomingKey> = {}): IncomingKey {
    return {
      keyId: "NEW",
      kind: "pgp-public",
      status: "new",
      info: null,
      details: null,
      userIds: ["Alice <alice@example.com>"],
      changes: [],
      publicArmored: "ARMOR-NEW",
      ...over,
    };
  }

  const withAlice: StoredKeys = { own: [], contacts: [storedKey()] };

  it("never marks a key that will not be saved, or one with no identity yet", () => {
    // Rejected keys aren't saved; OpenSSH private / CRX keys have only a headline.
    const keys = [
      incoming({ keyId: "REJ", status: "rejected" }),
      incoming({
        keyId: PENDING_KEY_ID,
        kind: "ssh-private",
        userIds: ["SSH private key"],
      }),
      incoming({
        keyId: PENDING_KEY_ID,
        kind: "crx",
        userIds: ["Chrome extension signing key"],
      }),
      incoming({ keyId: "PRIV", kind: "pgp-private", status: "duplicate" }),
    ];
    const out = withIdentityConflicts(keys, withAlice);
    expect(out.map((k) => k.conflict)).toEqual(keys.map(() => undefined));
  });

  describe("private and CRX keys", () => {
    it("marks a private key claiming a contact's address, and starts it on Skip", () => {
      const [key] = withIdentityConflicts(
        [incoming({ keyId: "PRIV", kind: "pgp-private" })],
        withAlice,
      );
      expect(key.conflict).toMatchObject({
        kind: "address",
        holders: [{ keyId: FP }],
      });
      expect(defaultDecision(key)).toBe("skip");
    });

    it("marks a private key with a contact's name and no address", () => {
      const [key] = withIdentityConflicts(
        [incoming({ keyId: "PRIV", kind: "pgp-private", userIds: ["Alice"] })],
        { own: [], contacts: [storedKey({ userIds: ["Alice <a@x.test>"] })] },
      );
      expect(key.conflict).toMatchObject({ kind: "name", sameName: true });
    });

    it("marks a backup's CRX key whose label is a contact's lookalike", () => {
      const [key] = withIdentityConflicts(
        [incoming({ keyId: "ext", kind: "crx", userIds: ["Аlice"] })],
        { own: [], contacts: [storedKey({ userIds: ["Alice <a@x.test>"] })] },
      );
      expect(key.conflict?.kind).toBe("name");
    });

    it("lets the user's next key share their own name and address", () => {
      const mine: StoredKeys = { own: [storedKey()], contacts: [] };
      const keys = [
        incoming({ keyId: "PRIV", kind: "pgp-private" }),
        incoming({ keyId: "PRIV2", kind: "pgp-private" }),
      ];
      expect(withIdentityConflicts(keys, mine).map((k) => k.conflict)).toEqual([
        undefined,
        undefined,
      ]);
    });

    it("still marks one that only LOOKS like the user's own", () => {
      const mine: StoredKeys = { own: [storedKey()], contacts: [] };
      const [key] = withIdentityConflicts(
        [
          incoming({
            keyId: "PRIV",
            kind: "pgp-private",
            userIds: ["Alice <alıce@example.com>"],
          }),
        ],
        mine,
      );
      expect(key.conflict).toMatchObject({
        kind: "address",
        lookalike: true,
        holders: [{ own: true }],
      });
    });

    it("holds a backup's private key against its contacts, too", () => {
      const out = withIdentityConflicts(
        [
          incoming({ keyId: "PRIV", kind: "pgp-private" }),
          incoming({ keyId: "PUB" }),
        ],
        noStores,
      );
      expect(out[1].conflict).toMatchObject({
        kind: "address",
        holders: [{ keyId: "PRIV", own: true }],
      });
    });
  });

  it("compares a contact's alias as one of its names", () => {
    const stored: StoredKeys = {
      own: [],
      contacts: [
        storedKey({ keyId: "SHA256:alice", userIds: [], alias: "Alice" }),
      ],
    };
    for (const comment of ["Alice", "Аlice"]) {
      const [key] = withIdentityConflicts(
        [
          incoming({
            keyId: "SHA256:x",
            kind: "ssh-public",
            userIds: [comment],
          }),
        ],
        stored,
      );
      expect(key.conflict?.kind, comment).toBe("name");
      expect(key.conflict?.holders[0].alias).toBe("Alice");
    }
  });

  it("checks an SSH key's comment like a User ID", () => {
    const [key] = withIdentityConflicts(
      [
        incoming({
          keyId: "SHA256:x",
          kind: "ssh-public",
          userIds: ["alice@example.com"],
        }),
      ],
      withAlice,
    );
    expect(key.conflict?.kind).toBe("address");
    expect(key.conflict?.holders[0].keyId).toBe(FP);
  });

  it("checks an SSH comment against SSH contacts and own keys too", () => {
    const stored: StoredKeys = {
      own: [storedKey({ keyId: "SHA256:me", userIds: ["Alice Smith"] })],
      contacts: [],
    };
    const [key] = withIdentityConflicts(
      [
        incoming({
          keyId: "SHA256:x",
          kind: "ssh-public",
          userIds: ["Аlice Smith"],
        }),
      ],
      stored,
    );
    expect(key.conflict?.kind).toBe("name");
    expect(key.conflict?.holders[0].own).toBe(true);
  });

  it("still marks a NEW key from the same lookup as the contact it would replace", () => {
    // Same source, different key: must still ask.
    const source = {
      type: "keyserver" as const,
      user: "alice@example.com",
      fetchedAt: 1,
    };
    const [key] = withIdentityConflicts([incoming({ source })], {
      own: [],
      contacts: [storedKey({ source })],
    });
    expect(key.conflict?.kind).toBe("address");
  });

  it("does not treat the 'SSH key' headline as a name two keys share", () => {
    const keys = [
      incoming({ keyId: "SHA256:a", kind: "ssh-public", userIds: ["SSH key"] }),
      incoming({ keyId: "SHA256:b", kind: "ssh-public", userIds: ["SSH key"] }),
    ];
    const out = withIdentityConflicts(keys, noStores);
    expect(out.map((k) => k.conflict)).toEqual([undefined, undefined]);
  });

  it("catches an address hidden behind an invisible character", () => {
    // Empty name, address with U+FE0F: the address check must hold.
    const [key] = withIdentityConflicts(
      [incoming({ userIds: ["<alice@example.com\ufe0f>"] })],
      withAlice,
    );
    expect(key.conflict?.kind).toBe("address");
  });

  it("marks a key claiming the user's OWN address, as an own holder", () => {
    const mine: StoredKeys = { own: [storedKey()], contacts: [] };
    const [key] = withIdentityConflicts([incoming()], mine);
    expect(key.conflict?.kind).toBe("address");
    expect(key.conflict?.holders[0].own).toBe(true);
  });

  it("holds against new keys only, not a rejected or updated one in the bundle", () => {
    const keys = [
      incoming({ keyId: "REJ", status: "rejected" }),
      incoming({ keyId: "UPD", status: "update" }),
      incoming(),
    ];
    const out = withIdentityConflicts(keys, { own: [], contacts: [] });
    expect(out[2].conflict).toBeUndefined();
  });

  it("marks an update only for the User IDs it adds", () => {
    const mallory: StoredKeys = {
      own: [],
      contacts: [
        storedKey(),
        storedKey({ keyId: "MAL", userIds: ["Mallory <m@example.com>"] }),
      ],
    };
    const [same] = withIdentityConflicts(
      [
        incoming({
          keyId: "MAL",
          status: "update",
          userIds: ["Mallory <m@example.com>"],
        }),
      ],
      mallory,
    );
    expect(same.conflict).toBeUndefined();
    const [grown] = withIdentityConflicts(
      [
        incoming({
          keyId: "MAL",
          status: "update",
          userIds: ["Mallory <m@example.com>", "Alice <alice@example.com>"],
        }),
      ],
      mallory,
    );
    expect(grown.conflict?.kind).toBe("address");
  });

  it.each([
    ["an address outside the brackets", "Alice alice@example.com"],
    ["a comment after the address", "Alice <alice@example.com> (work)"],
    ["an unclosed bracket", "Alice <alice@example.com"],
    ["a trailing dot", "Alice <alice@example.com.>"],
  ])("sees the address through %s", (_label, uid) => {
    const [key] = withIdentityConflicts(
      [incoming({ userIds: [uid] })],
      withAlice,
    );
    expect(key.conflict?.kind).toBe("address");
  });

  it.each([
    ["a capital I for an l", "Alice", "AIice"],
    ["a Hangul filler for a space", "Alice Lane", "Alice\u3164Lane"],
    ["a small capital L", "Alice", "A\u029Fice"],
    ["rn for m", "Mary", "Rnary"],
    ["a Cherokee capital A", "Alice", "\u13AAlice"],
    ["a stroked l", "Alice", "A\u0142ice"],
  ])("sees the name through %s", (_label, theirs, claimed) => {
    const stored: StoredKeys = {
      own: [],
      contacts: [storedKey({ userIds: [`${theirs} <them@example.com>`] })],
    };
    const [key] = withIdentityConflicts(
      [incoming({ userIds: [`${claimed} <x@evil.test>`] })],
      stored,
    );
    expect(key.conflict?.kind).toBe("name");
  });

  it.each([
    ["the very same name", "Alice Lane", "Alice Lane"],
    ["case", "Alice Lane", "ALICE lane"],
    ["spacing", "Alice Lane", "Alice   Lane"],
    ["quotes and a trailing dot", "Alice", '"Alice."'],
    ["accents", "Zoe Lane", "Zo\u00eb Lane"],
  ])(
    "lets two people share a name that differs only in %s",
    (_label, theirs, claimed) => {
      // Warning on every shared name would train users to click past the real one.
      const stored: StoredKeys = {
        own: [],
        contacts: [storedKey({ userIds: [`${theirs} <them@example.com>`] })],
      };
      const [key] = withIdentityConflicts(
        [incoming({ userIds: [`${claimed} <x@elsewhere.test>`] })],
        stored,
      );
      expect(key.conflict).toBeUndefined();
    },
  );

  it("returns an unmarked key unchanged", () => {
    const key = incoming({ userIds: ["Bob <bob@example.com>"] });
    expect(withIdentityConflicts([key], withAlice)[0]).toBe(key);
  });

  it("does not mutate the keys it is given", () => {
    const key = incoming();
    const [marked] = withIdentityConflicts([key], withAlice);
    expect(marked.conflict?.kind).toBe("address");
    expect(key.conflict).toBeUndefined();
  });
});

describe("prepareImport: two copies of one key", () => {
  const plain = { keyInfo: info(), armored: "COPY-1" };
  const grown = {
    keyInfo: info({
      userIds: ["Alice <alice@example.com>", "Bob <bob@example.com>"],
    }),
    armored: "COPY-2",
  };

  function copies(
    certs: { keyInfo: KeyInfo; armored: string }[],
    merged: KeyInfo,
  ) {
    vi.mocked(mergePublicKey).mockResolvedValue("MERGED");
    vi.mocked(parseKeys).mockImplementation((armored) =>
      Promise.resolve(
        armored === "blob" ? certs : [{ keyInfo: merged, armored }],
      ),
    );
  }

  it("is ONE row, the merge of both, so one decision covers one key", async () => {
    copies([plain, grown], grown.keyInfo);
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].publicArmored).toBe("MERGED");
    expect(prepared.keys[0].userIds).toEqual(grown.keyInfo.userIds);
    expect(vi.mocked(mergePublicKey)).toHaveBeenCalledWith("COPY-1", "COPY-2");
  });

  it("checks every User ID any copy carries against the contacts", async () => {
    copies([plain, grown], grown.keyInfo);
    const withBob: StoredKeys = {
      own: [],
      contacts: [
        storedKey({
          keyId: "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0",
          userIds: ["Bob <bob@example.com>"],
        }),
      ],
    };
    const prepared = await prepareImport("blob", withBob);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].conflict?.kind).toBe("address");
  });

  it("keeps the first copy when the engine will not merge them", async () => {
    copies([plain, grown], plain.keyInfo);
    vi.mocked(mergePublicKey).mockRejectedValue(new Error("different key"));
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].publicArmored).toBe("COPY-1");
  });

  it("keeps one private copy, and the first one's secret", async () => {
    const priv = (armored: string) => ({
      keyInfo: info({ isPrivate: true }),
      armored,
    });
    vi.mocked(parseKeys).mockResolvedValue([
      priv("SECRET-1"),
      priv("SECRET-2"),
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("PUBLIC");
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.secrets.get(FP)).toBe("SECRET-1");
  });

  it("leaves different keys alone", async () => {
    const other = {
      keyInfo: info({ keyId: "C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0" }),
      armored: "OTHER",
    };
    copies([plain, other], plain.keyInfo);
    const keys = await mergeSameKey(
      (await prepareImport("blob", noStores)).keys,
      noStores,
    );
    expect(keys).toHaveLength(2);
    expect(vi.mocked(mergePublicKey)).not.toHaveBeenCalled();
  });
});
