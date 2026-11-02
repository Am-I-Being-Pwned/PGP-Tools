/**
 * Pins handle ownership: PGP must NOT release the session's handle; CRX
 * must drop its transient one. Also that passphrase bytes are zeroed.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { serializeCrxKeyBlocks } from "~/lib/crx/backup";
import {
  closeCrxKey,
  exportCrxPrivateKeyPem,
  openCrxKey,
  resealCrxKeyUnderPassword,
} from "~/lib/crx/operations";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { crxKeyExporter, pgpKeyExporter } from "~/lib/keys/exporters";
import { encryptKeyForExportWithHandle, getKeyArmored } from "~/lib/pgp/wasm";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";

vi.mock("~/lib/pgp/wasm", () => ({
  encryptKeyForExportWithHandle: vi.fn(() => Promise.resolve("ENCRYPTED")),
  getKeyArmored: vi.fn(() => Promise.resolve("PLAINTEXT")),
}));

vi.mock("~/lib/crx/operations", () => ({
  openCrxKey: vi.fn(() => Promise.resolve(7)),
  closeCrxKey: vi.fn(() => Promise.resolve()),
  exportCrxPrivateKeyPem: vi.fn(() => Promise.resolve("PEM")),
  resealCrxKeyUnderPassword: vi.fn(() => Promise.resolve({ sealed: true })),
}));

vi.mock("~/lib/crx/backup", () => ({
  serializeCrxKeyBlocks: vi.fn(() => "CRX-BLOCKS"),
}));

afterEach(() => {
  vi.clearAllMocks();
});

function pgpBlob(
  method: "password" | "passkey" = "password",
): ProtectedKeyBlob {
  return {
    keyId: "FPR1",
    protection:
      method === "passkey"
        ? {
            method: "passkey",
            credentialId: "c",
            prfSalt: "s",
            storedSecret: "x",
          }
        : { method: "password", kdfSalt: "s" },
  } as ProtectedKeyBlob;
}

function crxBlob(
  method: "password" | "passkey" = "password",
): CrxSigningKeyBlob {
  return {
    label: "My extension",
    protection: { method },
  } as CrxSigningKeyBlob;
}

describe("pgpKeyExporter", () => {
  it("needs no unlock, because the session already holds the key", () => {
    expect(pgpKeyExporter(pgpBlob(), () => 3).needsUnlock).toBe(false);
  });

  it("reports whether the key is passkey-protected", () => {
    expect(pgpKeyExporter(pgpBlob("passkey"), () => 3).isPasskey).toBe(true);
    expect(pgpKeyExporter(pgpBlob("password"), () => 3).isPasskey).toBe(false);
  });

  it("acquires the live session handle for its own key id", async () => {
    const getHandle = vi.fn(() => 42);
    await expect(pgpKeyExporter(pgpBlob(), getHandle).acquire()).resolves.toBe(
      42,
    );
    expect(getHandle).toHaveBeenCalledWith("FPR1");
  });

  it("rejects with key-locked when the key has since locked", async () => {
    await expect(
      pgpKeyExporter(pgpBlob(), () => null).acquire(),
    ).rejects.toMatchObject({ code: "key-locked" });
  });

  it("re-reads the handle on every acquire rather than capturing it", async () => {
    // The key can lock between opening the dialog and pressing export.
    let handle: number | null = 42;
    const exporter = pgpKeyExporter(pgpBlob(), () => handle);

    await expect(exporter.acquire()).resolves.toBe(42);
    handle = null;
    await expect(exporter.acquire()).rejects.toMatchObject({
      code: "key-locked",
    });
  });

  it("does NOT drop the handle on release", () => {
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);
    expect(() => exporter.release(42)).not.toThrow();
    expect(closeCrxKey).not.toHaveBeenCalled();
  });

  it("encrypts the export with the passphrase as bytes", async () => {
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);
    await expect(exporter.exportEncrypted(42, "hunter2")).resolves.toBe(
      "ENCRYPTED",
    );

    const [handle, bytes] = vi.mocked(encryptKeyForExportWithHandle).mock
      .calls[0];
    expect(handle).toBe(42);
    expect(bytes).toBeInstanceOf(Uint8Array);
  });

  it("zeroes the passphrase bytes after use", async () => {
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);
    await exporter.exportEncrypted(42, "hunter2");

    const [, bytes] = vi.mocked(encryptKeyForExportWithHandle).mock.calls[0];
    expect(bytes).toEqual(new Uint8Array(7));
  });

  it("zeroes the passphrase bytes even when the export throws", async () => {
    vi.mocked(encryptKeyForExportWithHandle).mockRejectedValueOnce(
      new Error("wasm blew up"),
    );
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);

    await expect(exporter.exportEncrypted(42, "hunter2")).rejects.toThrow();

    const [, bytes] = vi.mocked(encryptKeyForExportWithHandle).mock.calls[0];
    expect(bytes).toEqual(new Uint8Array(7));
  });

  it("exports plaintext through the armored path", async () => {
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);
    await expect(exporter.exportPlaintext(42)).resolves.toBe("PLAINTEXT");
    expect(getKeyArmored).toHaveBeenCalledWith(42);
  });

  it("warns about clipboard exposure on the unsafe path", () => {
    const exporter = pgpKeyExporter(pgpBlob(), () => 42);
    expect(exporter.plaintextBlurb).toMatch(/clipboard/i);
    expect(exporter.plaintextButton).toMatch(/unsafe/i);
  });
});

describe("crxKeyExporter", () => {
  it("requires an unlock, because a CRX key is sealed at rest", () => {
    expect(crxKeyExporter(crxBlob()).needsUnlock).toBe(true);
  });

  it("opens a transient handle from the blob and the password", async () => {
    const blob = crxBlob();
    await expect(crxKeyExporter(blob).acquire("pw")).resolves.toBe(7);
    expect(openCrxKey).toHaveBeenCalledWith(blob, "pw");
  });

  it("drops the handle on release", () => {
    crxKeyExporter(crxBlob()).release(7);
    expect(closeCrxKey).toHaveBeenCalledWith(7);
  });

  it("reseals under the passphrase and serialises the result", async () => {
    // Re-importable, so serialised blocks, not a bare sealed object.
    const exporter = crxKeyExporter(crxBlob());
    await expect(exporter.exportEncrypted(7, "hunter2")).resolves.toBe(
      "CRX-BLOCKS",
    );

    expect(resealCrxKeyUnderPassword).toHaveBeenCalledWith(
      7,
      "hunter2",
      "My extension",
    );
    expect(serializeCrxKeyBlocks).toHaveBeenCalledWith([{ sealed: true }]);
  });

  it("exports plaintext as a raw PEM", async () => {
    const exporter = crxKeyExporter(crxBlob());
    await expect(exporter.exportPlaintext(7)).resolves.toBe("PEM");
    expect(exportCrxPrivateKeyPem).toHaveBeenCalledWith(7);
  });

  it("tailors the unlock copy to the protection method", () => {
    expect(crxKeyExporter(crxBlob("passkey")).unlockBlurb).toMatch(/passkey/i);
    expect(crxKeyExporter(crxBlob("password")).unlockBlurb).toMatch(
      /password/i,
    );
  });

  it("warns that the plaintext export is a full signing capability", () => {
    const exporter = crxKeyExporter(crxBlob());
    expect(exporter.plaintextBlurb).toMatch(/PKCS#8|clipboard/i);
    expect(exporter.plaintextButton).toMatch(/unsafe/i);
  });
});
