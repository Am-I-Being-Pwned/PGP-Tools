import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { ImportEngines, StoredKey, StoredKeys } from "./prepare";
import {
  extractPublicKey,
  parseKeyDetails,
  parseKeys,
  parseSshRecipient,
  sshPrivateKeyFormatRejection,
} from "../pgp/wasm";
import { classifyCert, importable, isNoOp, prepareImport } from "./prepare";
import { PENDING_KEY_ID } from "./types";

const AGE_RS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "gpg-wasm",
  "src",
  "age.rs",
);

/** A `const NAME: &str = "..."` from age.rs. Matched on the declaration,
 *  so reordering or reformatting the Rust doesn't break it. */
function ageMessage(name: string): string {
  const src = readFileSync(AGE_RS, "utf8");
  const re = new RegExp(
    `\\bconst\\s+${name}\\s*:\\s*&(?:'static\\s+)?str\\s*=\\s*"((?:[^"\\\\]|\\\\.)*)"\\s*;`,
  );
  const match = re.exec(src);
  if (!match) throw new Error(`${name} not found in gpg-wasm/src/age.rs`);
  return JSON.parse(`"${match[1]}"`) as string;
}

/** The bit-count messages are `format!` builders, not consts, so their
 *  template is read from the fn body and interpolated the same way. */
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

// The WASM engine is not available under vitest (see vitest.config.ts);
// parsing itself is covered by the Rust tests. These tests are about the
// classification built on top of it, so the parser is stubbed.
vi.mock("../pgp/wasm", () => ({
  parseKeys: vi.fn(),
  parseKeyDetails: vi.fn(),
  extractPublicKey: vi.fn(),
  parseSshRecipient: vi.fn(),
  sshPrivateKeyFormatRejection: vi.fn(),
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
    // Nothing parsed, so nothing to render as cert facts -- and the
    // preview must not read that as "still loading".
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
  /** Every header that opens a private key in the formats this flow
   *  accepts: OpenPGP armor, PKCS#8, PKCS#1. `IncomingKey` is handed to
   *  React state and serialized into the preview; secret armor belongs
   *  only in `PreparedImport.secrets`, which the panel parks in a ref. */
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
    // The public half of a private import is re-derived by
    // `extractPublicKey`; if that ever returned the input unchanged, the
    // whole private cert would ride into the preview under a field named
    // `publicArmored`. That is the failure this catches.
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

/**
 * The age engine's arrivals.
 *
 * Same rule as CRX: an engine is recognised HERE, in the one place that
 * decides what pasted text is, and returns an `IncomingKey` like anything
 * else -- so the panel routes an SSH key exactly as it routes a cert. An
 * engine bolted onto the panel instead would be a third flow to keep in
 * step.
 *
 * And the same gate: with `engines.ssh` off, an SSH key is not refused,
 * it is not RECOGNISED -- it falls through to the OpenPGP parse and comes
 * back `unparseable`, which is what the panel showed before the engine
 * existed.
 */
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
    // No certificate to parse: no user IDs, no dates, no subkeys.
    expect(key.info).toBeNull();
    expect(key.details).toBeNull();
    expect(key.userIds).toEqual(["alice@example.com"]);
    // The canonical line, not the pasted one -- that is what gets stored
    // and what the engine expects back as a recipient.
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
    const [key] = (await prepareImport(CANONICAL, noStores, { ssh: true })).keys;
    expect(key.userIds).toEqual(["SSH key"]);
  });

  it("marks an already-stored fingerprint as a duplicate, never an update", async () => {
    // The recipient line is canonical and carries nothing that can
    // change -- no expiry, no user ID, no subkey. Same fingerprint means
    // the same key.
    const prepared = await prepareImport(
      ED25519_PUB,
      { own: [], contacts: [storedKey({ keyId: SSH_FP, armored: CANONICAL })] },
      { ssh: true },
    );
    expect(prepared.keys[0].status).toBe("duplicate");
    expect(isNoOp(prepared)).toBe(true);
  });

  /**
   * Grouping several pasted `.pub` lines into ONE contact.
   *
   * A person is not a key: someone who self-hosts hands over three
   * `.pub` files, and a message has to reach all of them (see
   * `storage/contacts.ts`). But nothing in the text says three lines are
   * one person, so there are exactly two paths and the split between
   * them is the property under test:
   *
   *  - AUTOMATIC, only on unambiguous agreement -- every line commented,
   *    every comment byte-identical. Anything looser is a guess, and
   *    guessing folds `root@web01` and `root@db02` into one identity
   *    that is then encrypted to as one person.
   *  - MANUAL otherwise: both readings are carried out of here and the
   *    preview asks. Blank is still today's behaviour, N contacts.
   */
  describe("grouping several pasted keys", () => {
    /** `n` distinct keys, each with the given comment. */
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
      // The comment IS the name -- there is nothing to ask.
      expect(key.userIds).toEqual(["alice@laptop"]);
      expect(key.group?.members.map((m) => m.keyId)).toEqual([
        "SHA256:key0",
        "SHA256:key1",
      ]);
      // The head member's, so every path that reads an IncomingKey's
      // identity works on a group without knowing it is one.
      expect(key.keyId).toBe("SHA256:key0");
      expect(key.publicArmored).toBe("ssh-ed25519 AAAAkey0");
      // Hand-supplied: absent source, the same as on the stored record.
      expect(key.group?.source).toBeUndefined();
      // Nothing to ask, so nothing is offered.
      expect(prepared.groupProposal).toBeUndefined();
    });

    it("never groups keys whose comments disagree", async () => {
      const text = stubLines(["alice@laptop", "alice@desktop", ""]);
      const prepared = await prepareImport(text, noStores, { ssh: true });

      // Declining is the default, and it is exactly today's behaviour.
      expect(prepared.keys).toHaveLength(3);
      expect(prepared.keys.every((k) => k.group === undefined)).toBe(true);
      expect(importable(prepared.keys)).toHaveLength(3);

      // ...and the other reading travels alongside it.
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
      const prepared = await prepareImport(stubLines(["alice@laptop"]), noStores, {
        ssh: true,
      });
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].group).toBeUndefined();
      expect(prepared.groupProposal).toBeUndefined();
    });

    it("offers nothing once one of the keys is already stored", async () => {
      // "Import these separately" and "import these as one" would do
      // different amounts of work, so the question is not worth asking.
      const text = stubLines(["alice@laptop", "alice@desktop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            storedKey({ keyId: "SHA256:key1", armored: "ssh-ed25519 AAAAkey1" }),
          ],
        },
        { ssh: true },
      );
      expect(prepared.groupProposal).toBeUndefined();
      expect(prepared.keys.map((k) => k.status)).toEqual(["new", "duplicate"]);
    });

    it("calls a group of already-stored keys a duplicate, not an import", async () => {
      const text = stubLines(["alice@laptop", "alice@laptop"]);
      const prepared = await prepareImport(
        text,
        {
          own: [],
          contacts: [
            storedKey({ keyId: "SHA256:key0", armored: "ssh-ed25519 AAAAkey0" }),
            storedKey({ keyId: "SHA256:key1", armored: "ssh-ed25519 AAAAkey1" }),
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
    // NOT `unparseable` -- it parsed fine, it is simply unusable, and
    // "that doesn't look like a key" is the one thing that isn't true.
    expect(prepared.unparseable).toBe(false);
  });

  it("keeps a usable line and drops its unusable siblings", async () => {
    // A stale ECDSA entry in someone's authorized_keys is not worth
    // interrupting the import of the key they actually pasted for --
    // the same rule the OpenPGP path applies to rotated certs.
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

  /**
   * The property that matters for `gpg-wasm/src/age.rs`'s eight curated
   * rejection messages: not that the engine can produce them, but that
   * the user would see them. Each names the key type and the exact
   * `ssh-keygen` command that fixes it; all eight used to be replaced --
   * five by the swallowing `catch { continue }` below, three because the
   * format was not recognised as SSH's at all -- with the panel's generic
   * "that doesn't look like a key".
   *
   * The engine's own wording is pinned by the Rust tests; what is pinned
   * here is that whatever it says arrives verbatim on the IncomingKey.
   */
  describe("surfaces the engine's rejection verbatim", () => {
    // Read from `gpg-wasm/src/age.rs` rather than transcribed here.
    //
    // Transcribing them was tried and was wrong within the hour: two of
    // these carry an em dash that this repo's lint bans from source
    // literals, so the copies got reworded, and the file a reader would
    // consult to learn what the user sees started describing prose the
    // engine does not emit. Because these cases mock the wasm boundary,
    // nothing failed -- a divergence that tests cannot catch is exactly
    // the kind that has to be designed out instead.
    //
    // Reading the constants makes the Rust the single source of truth
    // and sidesteps the lint entirely, since the text is never a literal
    // here. Same technique, and the same reason, as
    // `lib/protection/aad-prefixes.test.ts`.
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
      // `crx` is off for the two plain PKCS#8 forms and only for them: an
      // unencrypted PKCS#8 key is ALSO a valid CRX signing key, and CRX --
      // checked first, because it is the engine that can actually use it --
      // legitimately owns it. See `isRsaPrivatePem`.
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
        // Matches the CRX signing-key shape too, and must not be claimed
        // by it: `parse_rsa_private_pem` cannot read an encrypted PEM
        // either, so claiming it only swapped this message for a generic
        // CRX parse failure.
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
      ["PKCS#1", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"],
      ["PKCS#8", "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----\n"],
      // Its own label, but the same `AAAA`-prefixed base64 body shape --
      // it must not be mistaken for either the CRX or SSH signing key.
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

    // The bytes handed across the wasm boundary here are a plaintext copy
    // of a COMPLETE private key file (an unencrypted PKCS#8 key reaches
    // this branch whenever the CRX engine is off). `prepareImport` drops
    // its reference before returning, so -- as in history.test.ts -- the
    // mock retains the ACTUAL buffer that crossed the boundary: it is
    // asserted to still carry the key bytes at call time, and to be
    // all-zero once `prepareImport` settles. Behavioural proof of the
    // `finally` scrub, not inspection.
    describe("scrubs the key-file buffer handed to wasm", () => {
      const PKCS8 =
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
      let captured: Uint8Array | null = null;

      beforeEach(() => {
        captured = null;
      });

      /** Arm the mock with `outcome`, capturing its argument. Asserting
       *  the buffer was non-empty and correct *during* the call is what
       *  stops the all-zero check afterwards from passing vacuously. */
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
    // Its fingerprint is only recovered inside the protect step, so
    // there is no public half to preview -- the CRX precedent.
    expect(key.publicArmored).toBe("");
    expect(key.info).toBeNull();
    // The secret half never rides on the IncomingKey.
    expect(prepared.secrets.get(PENDING_KEY_ID)).toBe(OPENSSH_PRIVATE);
    expect(JSON.stringify(prepared.keys)).not.toContain("OPENSSH PRIVATE");
  });

  it("prefers the private container over the public half inside it", async () => {
    // An OpenSSH container embeds the public key; classifying it as a
    // recipient would drop the secret half on the floor.
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
 * The three refusals that could not reach the user at all on the paste
 * path -- ECDSA, FIDO `sk-*`, DSA.
 *
 * `parseSshRecipient` has always had a curated message for each. What it
 * never had was a line to be given: `splitSshPublicKeyLines` matched
 * `ssh-ed25519|ssh-rsa` only, so a pasted `.pub` of any other algorithm
 * was not split out, fell through to the OpenPGP parse, and came back
 * `unparseable` -- the panel's "that doesn't look like a key" standing in
 * for the one sentence that names the problem and the fix.
 *
 * Fourth instance of one pattern (`catch { continue }` here,
 * `github/response.ts`'s filter, then this). The invariant these tests
 * pin: THE ENGINE DECIDES VALIDITY; EVERY LAYER ABOVE IT FORWARDS AND
 * DISPLAYS. Shape is all `prepareImport` checks.
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

      // Forwarded at all -- the half of this that used to be missing.
      expect(parseSshRecipient).toHaveBeenCalledWith(line);
      // Reported as a key we refuse, NOT as text that isn't a key.
      expect(prepared.unparseable).toBe(false);
      expect(prepared.keys).toHaveLength(1);
      expect(prepared.keys[0].kind).toBe("ssh-public");
      expect(prepared.keys[0].status).toBe("rejected");
      // Verbatim: the engine names the type and the `ssh-keygen` fix.
      expect(prepared.keys[0].rejection).toBe(message);
      // Shown, never stored, and nothing to import.
      expect(prepared.keys[0].publicArmored).toBe(line);
      expect(prepared.secrets.size).toBe(0);
      expect(importable(prepared.keys)).toEqual([]);
    },
  );

  it("still drops a refused line when a usable one sits beside it", async () => {
    // An `authorized_keys` with a stale ECDSA entry is not worth
    // interrupting the import of the key that does work.
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

  // The other half of widening the shape: what must still NOT look like
  // an SSH public line. Each of these is owned by another path, and a
  // candidate matcher that claimed one would have moved the bug rather
  // than fixed it.
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
