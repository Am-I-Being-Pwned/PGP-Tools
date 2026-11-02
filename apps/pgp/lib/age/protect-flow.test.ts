/**
 * SSH protect flow: the stored blob's exact field set (it goes on users'
 * disks) and that the key file is scrubbed on every exit, each throwing
 * path tested separately.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { SshProtectFlowResult } from "../pgp/wasm";

const wasm = vi.hoisted(() => ({
  protectSshIdentityWithPassword: vi.fn(),
  protectSshIdentityWithPrf: vi.fn(),
  unlockSshIdentityWithPassword: vi.fn(),
  unlockSshIdentityWithPrf: vi.fn(),
  dropSshIdentity: vi.fn(),
  hasContactsSession: vi.fn(() => Promise.resolve(true)),
  // Must be the REAL sentence, or the tagging test passes vacuously.
  sshPassphraseRequiredMessage: vi.fn(() =>
    Promise.resolve(PASSPHRASE_REQUIRED),
  ),
}));

/** Verbatim `MSG_PASSPHRASE_REQUIRED` from `gpg-wasm/src/age.rs`. */
const PASSPHRASE_REQUIRED =
  "This SSH key is passphrase-protected. Enter its passphrase to import it.";

vi.mock("../pgp/wasm", () => wasm);

const webauthn = await vi.hoisted(async () =>
  (await import("../protection/fake-webauthn")).fakeWebauthnPrf(),
);

vi.mock("../protection/webauthn-prf", () => webauthn);

import { AppError } from "../errors/app-error";
import {
  closeSshIdentity,
  groupContact,
  importSshIdentity,
  openSshIdentity,
  sshContact,
  sshUserIds,
} from "./protect-flow";

const PASSWORD = "correct horse battery";
const FINGERPRINT = "SHA256:6xN1hCbYYQnEo3sB1Wp2sTQnAo1cvxKcYLW9sQvfR0Q";
const RECIPIENT =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6";
const COMMENT = "alice@example.com";

/** `[16 salt][12 iv][ct]` with per-section markers. */
function passwordPacked(): Uint8Array {
  const out = new Uint8Array(16 + 12 + 8);
  out.fill(0xa1, 0, 16);
  out.fill(0xb2, 16, 28);
  out.fill(0xc3, 28);
  return out;
}

function prfPacked(): Uint8Array {
  const out = new Uint8Array(12 + 8);
  out.fill(0xd4, 0, 12);
  out.fill(0xe5, 12);
  return out;
}

function result(blob: Uint8Array, comment = COMMENT): SshProtectFlowResult {
  return {
    meta: {
      fingerprint: FINGERPRINT,
      recipient: RECIPIENT,
      algorithm: "ssh-ed25519",
      comment,
    },
    blob,
  };
}

function keyFile(): Uint8Array {
  return new TextEncoder().encode(
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n",
  );
}

beforeEach(() => {
  vi.resetAllMocks();
  wasm.protectSshIdentityWithPassword.mockResolvedValue(
    result(passwordPacked()),
  );
  wasm.protectSshIdentityWithPrf.mockResolvedValue(result(prfPacked()));
  webauthn.registerPasskey.mockResolvedValue({
    credentialId: "cred-id",
    prfEnabled: true,
  });
  webauthn.generatePrfSalt.mockReturnValue(new Uint8Array(32).buffer);
  webauthn.generateStoredSecret.mockReturnValue(new Uint8Array(32).buffer);
  webauthn.authenticateAndGetPrf.mockResolvedValue({
    prfOutput: new Uint8Array(32).fill(7),
  });
});

describe("importSshIdentity - the stored blob", () => {
  it("keys the blob by fingerprint and stores the recipient line as its armor", async () => {
    const { blob } = await importSshIdentity(keyFile(), null, {
      method: "password",
      password: PASSWORD,
    });

    expect(Object.keys(blob).sort()).toEqual([
      "algorithm",
      "createdAt",
      "encryptedPrivateKey",
      "iv",
      "keyId",
      "kind",
      "lastUsedAt",
      "protection",
      "publicKeyArmored",
      "userIds",
      "version",
    ]);
    expect(blob.kind).toBe("ssh");
    expect(blob.keyId).toBe(FINGERPRINT);
    expect(blob.publicKeyArmored).toBe(RECIPIENT);
    expect(blob.algorithm).toBe("ssh-ed25519");
    expect(blob.userIds).toEqual([COMMENT]);
    expect(blob.protection).toEqual({
      method: "password",
      kdfSalt: btoa("\xa1".repeat(16)),
    });
  });

  it("names the key by its comment, and by nothing when it has none", async () => {
    wasm.protectSshIdentityWithPassword.mockResolvedValue(
      result(passwordPacked(), "  "),
    );
    const { blob } = await importSshIdentity(keyFile(), null, {
      method: "password",
      password: PASSWORD,
    });
    expect(blob.userIds).toEqual([]);
    expect(sshUserIds(" alice@host ")).toEqual(["alice@host"]);
  });

  it("stores a passkey-protected identity with its PRF material", async () => {
    const { blob } = await importSshIdentity(
      keyFile(),
      null,
      { method: "passkey" },
      { userIdHint: "alice@example.com" },
    );
    expect(blob.kind).toBe("ssh");
    expect(blob.protection.method).toBe("passkey");
    expect(blob.protection).toHaveProperty("credentialId", "cred-id");
  });

  it("hands the source passphrase to wasm as bytes, never a string", async () => {
    await importSshIdentity(keyFile(), "the key's own passphrase", {
      method: "password",
      password: PASSWORD,
    });
    const [, sourcePassphrase, password] = wasm
      .protectSshIdentityWithPassword.mock.calls[0] as unknown[];
    expect(sourcePassphrase).toBeInstanceOf(Uint8Array);
    expect(password).toBeInstanceOf(Uint8Array);
  });

  it("chains a real unlock for cache: true, so the store entry comes from an unlock", async () => {
    wasm.unlockSshIdentityWithPassword.mockResolvedValue(42);
    const { handle } = await importSshIdentity(keyFile(), null, {
      method: "password",
      password: PASSWORD,
      cache: true,
    });

    expect(handle).toBe(42);
    const [ct, iv, salt, fingerprint] = wasm.unlockSshIdentityWithPassword
      .mock.calls[0] as unknown[];
    expect([...(salt as Uint8Array)]).toEqual(Array(16).fill(0xa1));
    expect([...(iv as Uint8Array)]).toEqual(Array(12).fill(0xb2));
    expect([...(ct as Uint8Array)]).toEqual(Array(8).fill(0xc3));
    expect(fingerprint).toBe(FINGERPRINT);
  });
});

describe("importSshIdentity - zeroization", () => {
  it("wipes the key file after a successful import", async () => {
    const file = keyFile();
    await importSshIdentity(file, null, {
      method: "password",
      password: PASSWORD,
    });
    expect([...file]).toEqual(Array(file.length).fill(0));
  });

  it("wipes the key file when the weak-password gate throws", async () => {
    // The gate throws before wasm is reached.
    const file = keyFile();
    await expect(
      importSshIdentity(file, null, { method: "password", password: "short" }),
    ).rejects.toThrow(/at least 8 characters/);
    expect([...file]).toEqual(Array(file.length).fill(0));
    expect(wasm.protectSshIdentityWithPassword).not.toHaveBeenCalled();
  });

  it("wipes the key file when the WebAuthn ceremony is cancelled", async () => {
    const file = keyFile();
    webauthn.registerPasskey.mockRejectedValue(new Error("cancelled"));
    await expect(
      importSshIdentity(file, null, { method: "passkey" }),
    ).rejects.toThrow(/cancelled/);
    expect([...file]).toEqual(Array(file.length).fill(0));
  });

  it("wipes the key file when wasm itself rejects the key", async () => {
    const file = keyFile();
    wasm.protectSshIdentityWithPassword.mockRejectedValue(
      new Error("Wrong passphrase for this SSH key"),
    );
    await expect(
      importSshIdentity(file, "wrong", {
        method: "password",
        password: PASSWORD,
      }),
    ).rejects.toThrow(/Wrong passphrase/);
    expect([...file]).toEqual(Array(file.length).fill(0));
  });
});

describe("openSshIdentity / closeSshIdentity", () => {
  const blob = {
    version: 1 as const,
    kind: "ssh" as const,
    keyId: FINGERPRINT,
    userIds: [COMMENT],
    algorithm: "ssh-ed25519",
    publicKeyArmored: RECIPIENT,
    protection: { method: "password" as const, kdfSalt: "c2FsdA==" },
    encryptedPrivateKey: "Y3Q=",
    iv: "aXY=",
    createdAt: 1,
    lastUsedAt: 1,
  };

  it("unlocks against the blob's own fingerprint (the seal's AAD)", async () => {
    wasm.unlockSshIdentityWithPassword.mockResolvedValue(9);
    expect(await openSshIdentity(blob, PASSWORD)).toBe(9);
    const [, , , fingerprint, password] = wasm.unlockSshIdentityWithPassword
      .mock.calls[0] as unknown[];
    expect(fingerprint).toBe(FINGERPRINT);
    expect(password).toBeInstanceOf(Uint8Array);
  });

  it("refuses to unlock a password-protected key with no password", async () => {
    await expect(openSshIdentity(blob)).rejects.toThrow(/Password required/);
    expect(wasm.unlockSshIdentityWithPassword).not.toHaveBeenCalled();
  });

  it("runs the passkey ceremony for a passkey-protected key", async () => {
    wasm.unlockSshIdentityWithPrf.mockResolvedValue(11);
    const handle = await openSshIdentity({
      ...blob,
      protection: {
        method: "passkey",
        credentialId: "cred-id",
        prfSalt: "c2FsdA==",
        storedSecret: "c2VjcmV0",
      },
    });
    expect(handle).toBe(11);
    expect(webauthn.authenticateAndGetPrf).toHaveBeenCalled();
  });

  it("drops the handle through the wasm store, not by forgetting it", async () => {
    await closeSshIdentity(5);
    expect(wasm.dropSshIdentity).toHaveBeenCalledWith(5);
  });
});

describe("sshContact", () => {
  it("stores the recipient line as the contact's armor, flagged ssh", () => {
    const contact = sshContact(
      {
        recipient: RECIPIENT,
        algorithm: "ssh-ed25519",
        fingerprint: FINGERPRINT,
        comment: COMMENT,
      },
      1234,
    );
    expect(contact).toEqual({
      kind: "ssh",
      keyId: FINGERPRINT,
      userIds: [COMMENT],
      algorithm: "ssh-ed25519",
      armoredPublicKey: RECIPIENT,
      addedAt: 1234,
      lastUsedAt: 1234,
      usableForEncryption: true,
    });
  });
});

describe("groupContact", () => {
  const SECOND = {
    keyId: "SHA256:secondsecondsecondsecondsecondsecondsecond",
    armored: "ssh-ed25519 AAAAsecond",
    algorithm: "ssh-ed25519",
  };
  const head = {
    keyId: FINGERPRINT,
    armored: RECIPIENT,
    algorithm: "ssh-ed25519",
  };
  const source = { type: "github" as const, user: "octocat", fetchedAt: 99 };

  it("writes no `recipients` field for a user with exactly one key", () => {
    // A one-key group serialises as the plain single-key record.
    const contact = groupContact(
      { label: "octocat (GitHub)", source, members: [head], rejected: [] },
      1234,
    );
    expect(contact).toEqual({
      kind: "ssh",
      keyId: FINGERPRINT,
      userIds: ["octocat (GitHub)"],
      algorithm: "ssh-ed25519",
      armoredPublicKey: RECIPIENT,
      addedAt: 1234,
      lastUsedAt: 1234,
      usableForEncryption: true,
      // Explicit null: `undefined` would trigger the PGP backfill.
      expiresAt: null,
      source,
    });
    expect("recipients" in contact).toBe(false);
    const pasted = sshContact(
      {
        recipient: RECIPIENT,
        algorithm: "ssh-ed25519",
        fingerprint: FINGERPRINT,
        comment: COMMENT,
      },
      1234,
    );
    expect(contact.keyId).toBe(pasted.keyId);
    expect(contact.armoredPublicKey).toBe(pasted.armoredPublicKey);
    expect(contact.kind).toBe(pasted.kind);
  });

  it("keeps the head in agreement with the record id for several keys", () => {
    // Head agreement, enforced by `isValidContact` on load.
    const contact = groupContact(
      {
        label: "octocat (GitHub)",
        source,
        members: [head, SECOND],
        rejected: [],
      },
      1234,
    );
    expect(contact.recipients).toEqual([head, SECOND]);
    expect(contact.recipients?.[0].keyId).toBe(contact.keyId);
    expect(contact.recipients?.[0].armored).toBe(contact.armoredPublicKey);
  });

  /** A hand-grouped contact: same constructor, indistinguishable from a
   *  fetched one except it has no source. */
  it("builds a hand-grouped contact the same way, minus the source", () => {
    const THIRD = {
      keyId: "SHA256:thirdthirdthirdthirdthirdthirdthirdthirdth",
      armored: "ssh-ed25519 AAAAthird",
      algorithm: "ssh-ed25519",
    };
    const contact = groupContact(
      {
        label: "Alice (all machines)",
        members: [head, SECOND, THIRD],
        rejected: [],
      },
      1234,
    );
    expect(contact.userIds).toEqual(["Alice (all machines)"]);
    expect(contact.recipients).toHaveLength(3);
    expect(contact.recipients?.[0].keyId).toBe(contact.keyId);
    expect("source" in contact).toBe(false);
    const fetched = groupContact(
      {
        label: "Alice (all machines)",
        source,
        members: [head, SECOND, THIRD],
        rejected: [],
      },
      1234,
    );
    const { source: _dropped, ...rest } = fetched;
    expect(JSON.stringify(contact)).toBe(JSON.stringify(rest));
  });

  it("refuses a group with no usable key rather than writing a headless record", () => {
    expect(() =>
      groupContact({
        label: "octocat (GitHub)",
        source,
        members: [],
        rejected: [{ line: "ecdsa-sha2-nistp256 AAAA", reason: "no" }],
      }),
    ).toThrow();
  });
});

describe("importSshIdentity - passphrase tagging", () => {
  /** The import step reveals its passphrase field on this code alone. */
  it("tags the engine's passphrase-required error with a code", async () => {
    // A BARE STRING, not an Error: what wasm-bindgen throws for a Rust
    // `Err(String)`. An Error here would hide an `instanceof` gate.
    wasm.protectSshIdentityWithPassword.mockRejectedValueOnce(
      PASSPHRASE_REQUIRED,
    );
    const file = new TextEncoder().encode("ssh key bytes");
    const err = await importSshIdentity(file, null, {
      method: "password",
      password: PASSWORD,
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(AppError);
    expect((err as AppError).code).toBe("ssh-passphrase-required");
    expect((err as AppError).message).toBe(PASSPHRASE_REQUIRED);
    // Still wiped: tagging happens on the way out, not instead of it.
    expect([...file]).toEqual(Array(file.length).fill(0));
  });

  it("leaves every other engine error untagged", async () => {
    wasm.protectSshIdentityWithPassword.mockRejectedValueOnce(
      "Wrong passphrase for this SSH key.",
    );
    const err = await importSshIdentity(
      new TextEncoder().encode("ssh key bytes"),
      "nope",
      { method: "password", password: PASSWORD },
    ).catch((e: unknown) => e);

    // Untagged and unchanged: still the bare string the engine threw.
    expect(err).not.toBeInstanceOf(AppError);
    expect(err).toBe("Wrong passphrase for this SSH key.");
  });
});
