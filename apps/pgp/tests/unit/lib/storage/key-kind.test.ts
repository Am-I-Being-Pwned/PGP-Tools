/**
 * The `kind` migration rules. READ: absent means "pgp" (break it and every
 * existing key vanishes). WRITE: only "ssh" is persisted (break it and
 * older builds read new PGP records as a foreign engine).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  isPgpRecord,
  isSshRecord,
  kindField,
  storedKeyKind,
  type KindDiscriminated,
} from "~/lib/storage/key-kind";
import { blobFromEncrypted } from "~/lib/storage/keyring";

const SEAL = {
  method: "password" as const,
  ciphertext: "Y3Q=",
  iv: "aXY=",
  salt: "c2FsdA==",
};

describe("storedKeyKind (the read rule)", () => {
  it("reads a record with NO kind field as pgp", () => {
    expect(storedKeyKind({})).toBe("pgp");
    expect(isPgpRecord({})).toBe(true);
    expect(isSshRecord({})).toBe(false);
  });

  it("reads an explicit kind when one is present", () => {
    expect(storedKeyKind({ kind: "pgp" })).toBe("pgp");
    expect(storedKeyKind({ kind: "ssh" })).toBe("ssh");
    expect(isSshRecord({ kind: "ssh" })).toBe(true);
    expect(isPgpRecord({ kind: "ssh" })).toBe(false);
  });

  it("treats an absent kind and an explicit pgp identically", () => {
    const legacy: KindDiscriminated = {};
    const explicit: KindDiscriminated = { kind: "pgp" };
    expect(storedKeyKind(legacy)).toBe(storedKeyKind(explicit));
    expect(isPgpRecord(legacy)).toBe(isPgpRecord(explicit));
  });

  it("partitions every record into exactly one engine", () => {
    for (const record of [
      {},
      { kind: "pgp" as const },
      { kind: "ssh" as const },
    ]) {
      expect(isPgpRecord(record)).toBe(!isSshRecord(record));
    }
  });
});

describe("kindField (the write rule)", () => {
  it("writes nothing at all for pgp", () => {
    // The field must not appear at all.
    expect(kindField("pgp")).toEqual({});
    expect("kind" in kindField("pgp")).toBe(false);
  });

  it("writes the discriminant only for ssh", () => {
    expect(kindField("ssh")).toEqual({ kind: "ssh" });
  });
});

describe("blobFromEncrypted", () => {
  // Pin Date.now() so blobs differ only in kind.
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("omits kind entirely from a PGP blob, including by default", () => {
    const implicit = blobFromEncrypted("FP", ["a@b"], "ed25519", "ARMOR", SEAL);
    const explicit = blobFromEncrypted(
      "FP",
      ["a@b"],
      "ed25519",
      "ARMOR",
      SEAL,
      "pgp",
    );
    expect("kind" in implicit).toBe(false);
    expect(implicit).toEqual(explicit);
    // Serialization is what actually reaches the disk.
    expect(JSON.stringify(implicit)).not.toContain("kind");
  });

  it("stamps an SSH blob, keyed by its fingerprint and recipient line", () => {
    const line = "ssh-ed25519 AAAAC3Nza";
    const blob = blobFromEncrypted(
      "SHA256:abc",
      ["alice@host"],
      "ssh-ed25519",
      line,
      SEAL,
      "ssh",
    );
    expect(blob.kind).toBe("ssh");
    expect(storedKeyKind(blob)).toBe("ssh");
    expect(blob.keyId).toBe("SHA256:abc");
    expect(blob.publicKeyArmored).toBe(line);
  });
});
