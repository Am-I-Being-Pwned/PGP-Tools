/**
 * The migration property, stated as tests.
 *
 * Every protected key blob and every contact already on a user's disk was
 * written before the `kind` field existed. There is no version marker on
 * those records, no migration pass, and no way to tell a pre-`kind` blob
 * from a post-`kind` PGP one -- by design, because they are the same
 * thing. The whole scheme therefore rests on two rules, and nothing else:
 *
 *   READ:  absent means "pgp". Nothing may compare `.kind` directly.
 *   WRITE: `kind` is only ever persisted as "ssh". A PGP record is
 *          written with the field absent, exactly as before.
 *
 * Break the read rule and every existing key vanishes from the UI.
 * Break the write rule and today's builds start emitting records that an
 * older build (or a restored backup) reads as a foreign engine.
 */

import { describe, expect, it } from "vitest";

import type { KindDiscriminated } from "./key-kind";
import {
  isPgpRecord,
  isSshRecord,
  kindField,
  storedKeyKind,
} from "./key-kind";
import { blobFromEncrypted } from "./keyring";

const SEAL = {
  method: "password" as const,
  ciphertext: "Y3Q=",
  iv: "aXY=",
  salt: "c2FsdA==",
};

describe("storedKeyKind (the read rule)", () => {
  it("reads a record with NO kind field as pgp", () => {
    // The legacy record: every blob written before SSH support.
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
    // These two records must be indistinguishable to every consumer:
    // one was written last year, the other could be written today.
    const legacy: KindDiscriminated = {};
    const explicit: KindDiscriminated = { kind: "pgp" };
    expect(storedKeyKind(legacy)).toBe(storedKeyKind(explicit));
    expect(isPgpRecord(legacy)).toBe(isPgpRecord(explicit));
  });

  it("partitions every record into exactly one engine", () => {
    for (const record of [{}, { kind: "pgp" as const }, { kind: "ssh" as const }]) {
      expect(isPgpRecord(record)).toBe(!isSshRecord(record));
    }
  });
});

describe("kindField (the write rule)", () => {
  it("writes nothing at all for pgp", () => {
    // Not `{ kind: "pgp" }` -- the field must not appear, so a PGP blob
    // written today is byte-identical to one written before SSH existed.
    expect(kindField("pgp")).toEqual({});
    expect("kind" in kindField("pgp")).toBe(false);
  });

  it("writes the discriminant only for ssh", () => {
    expect(kindField("ssh")).toEqual({ kind: "ssh" });
  });
});

describe("blobFromEncrypted", () => {
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
    // An SSH identity's two stand-ins for the fields every stored key
    // needs: the OpenSSH fingerprint, and the canonical recipient line
    // in place of public armor.
    expect(blob.keyId).toBe("SHA256:abc");
    expect(blob.publicKeyArmored).toBe(line);
  });
});
