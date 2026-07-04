import { describe, expect, it } from "vitest";

import type { CrxSigningKeyBlob } from "./types";
import {
  crxBlobIdentityMatches,
  extensionIdFromPublicKeyDer,
  isCrxSigningKeyBlob,
  publicKeyDerToPem,
} from "./types";

function validBlob(): CrxSigningKeyBlob {
  return {
    version: 1,
    extensionId: "abcdefghijklmnopabcdefghijklmnop",
    label: "My Extension",
    publicKeyDerB64: "TUlJQg==",
    algorithm: "rsa2048",
    protection: { method: "password", kdfSalt: "c2FsdA==" },
    encryptedPrivateKey: "Y2lwaGVydGV4dA==",
    iv: "aXZpdml2aXY=",
    createdAt: 1_700_000_000_000,
    lastUsedAt: 1_700_000_000_001,
  };
}

describe("isCrxSigningKeyBlob", () => {
  it("accepts a well-formed password-protected blob", () => {
    expect(isCrxSigningKeyBlob(validBlob())).toBe(true);
  });

  it("accepts a well-formed passkey-protected blob", () => {
    const blob: CrxSigningKeyBlob = {
      ...validBlob(),
      protection: {
        method: "passkey",
        credentialId: "Y3JlZA==",
        prfSalt: "cHJm",
        storedSecret: "c2VjcmV0",
      },
    };
    expect(isCrxSigningKeyBlob(blob)).toBe(true);
  });

  it("rejects non-objects and null", () => {
    expect(isCrxSigningKeyBlob(null)).toBe(false);
    expect(isCrxSigningKeyBlob(undefined)).toBe(false);
    expect(isCrxSigningKeyBlob("blob")).toBe(false);
    expect(isCrxSigningKeyBlob(42)).toBe(false);
    // An array is a non-null object but lacks the required fields.
    expect(isCrxSigningKeyBlob([])).toBe(false);
  });

  it("rejects blobs missing a required string field", () => {
    for (const field of [
      "extensionId",
      "publicKeyDerB64",
      "encryptedPrivateKey",
      "iv",
    ] as const) {
      const blob = validBlob();
      delete (blob as unknown as Record<string, unknown>)[field];
      expect(isCrxSigningKeyBlob(blob)).toBe(false);
    }
  });

  it("rejects blobs whose required fields have the wrong type", () => {
    expect(
      isCrxSigningKeyBlob({ ...validBlob(), extensionId: 123 }),
    ).toBe(false);
    expect(isCrxSigningKeyBlob({ ...validBlob(), iv: null })).toBe(false);
    expect(
      isCrxSigningKeyBlob({ ...validBlob(), publicKeyDerB64: {} }),
    ).toBe(false);
  });

  it("rejects blobs with null protection", () => {
    expect(isCrxSigningKeyBlob({ ...validBlob(), protection: null })).toBe(
      false,
    );
  });

  it("rejects blobs whose protection is not an object", () => {
    expect(
      isCrxSigningKeyBlob({ ...validBlob(), protection: "password" }),
    ).toBe(false);
  });

  it("rejects protection without a string method", () => {
    expect(
      isCrxSigningKeyBlob({ ...validBlob(), protection: {} }),
    ).toBe(false);
    expect(
      isCrxSigningKeyBlob({ ...validBlob(), protection: { method: 1 } }),
    ).toBe(false);
  });
});

describe("publicKeyDerToPem", () => {
  const BEGIN = "-----BEGIN PUBLIC KEY-----";
  const END = "-----END PUBLIC KEY-----";

  it("wraps a short body in BEGIN/END markers on a single line", () => {
    const body = "TUlJQg==";
    expect(publicKeyDerToPem(body)).toBe(`${BEGIN}\n${body}\n${END}\n`);
  });

  it("emits the correct markers and a trailing newline", () => {
    const pem = publicKeyDerToPem("A".repeat(130));
    expect(pem.startsWith(`${BEGIN}\n`)).toBe(true);
    expect(pem.endsWith(`\n${END}\n`)).toBe(true);
  });

  it("wraps the base64 body at 64 characters per line", () => {
    const body = "A".repeat(130);
    const pem = publicKeyDerToPem(body);
    const lines = pem
      .replace(`${BEGIN}\n`, "")
      .replace(`\n${END}\n`, "")
      .split("\n");
    // 130 chars -> 64 + 64 + 2.
    expect(lines).toHaveLength(3);
    expect(lines[0]).toHaveLength(64);
    expect(lines[1]).toHaveLength(64);
    expect(lines[2]).toHaveLength(2);
    expect(lines.every((l) => l.length <= 64)).toBe(true);
  });

  it("round-trips the base64 body (stripping markers and newlines)", () => {
    const body =
      "TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE=";
    const pem = publicKeyDerToPem(body);
    const recovered = pem
      .replace(`${BEGIN}\n`, "")
      .replace(`\n${END}\n`, "")
      .replace(/\n/g, "");
    expect(recovered).toBe(body);
  });
});

describe("extensionIdFromPublicKeyDer", () => {
  // Vector computed independently (node:crypto): SHA-256 over the raw DER
  // bytes, first 16 bytes, nibbles mapped a..p.
  const DER_B64 = "dGVzdC1zcGtpLWRlci1ieXRlcy1mb3ItdmVjdG9y";
  const EXPECTED = "dkokjnapmngocbgnkkafenmclkmnihio";

  it("derives Chrome's a..p extension id from the SPKI DER", async () => {
    await expect(extensionIdFromPublicKeyDer(DER_B64)).resolves.toBe(EXPECTED);
  });

  it("always yields 32 chars in a..p", async () => {
    const id = await extensionIdFromPublicKeyDer("TUlJQg==");
    expect(id).toHaveLength(32);
    expect([...id].every((c) => c >= "a" && c <= "p")).toBe(true);
  });
});

describe("crxBlobIdentityMatches", () => {
  const DER_B64 = "dGVzdC1zcGtpLWRlci1ieXRlcy1mb3ItdmVjdG9y";
  const MATCHING_ID = "dkokjnapmngocbgnkkafenmclkmnihio";

  it("accepts a blob whose public key hashes to its extension id", async () => {
    const blob = {
      ...validBlob(),
      publicKeyDerB64: DER_B64,
      extensionId: MATCHING_ID,
    };
    await expect(crxBlobIdentityMatches(blob)).resolves.toBe(true);
  });

  it("rejects a blob whose public key was swapped (id mismatch)", async () => {
    const blob = { ...validBlob(), publicKeyDerB64: DER_B64 };
    await expect(crxBlobIdentityMatches(blob)).resolves.toBe(false);
  });
});
