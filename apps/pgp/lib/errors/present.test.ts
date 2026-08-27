import { describe, expect, it } from "vitest";

import { AppError } from "./app-error";
import { presentError } from "./present";

const FALLBACK = "The operation failed. Try again.";

describe("presentError", () => {
  // wasm-bindgen surfaces Rust `Err(String)` as a thrown JS *string*, so
  // every wasm fixture is exercised both as a bare string and wrapped in
  // an Error (some call sites re-throw with `new Error(msg)`).
  // The raw strings are verbatim from gpg-wasm/src/{lib,crx}.rs.
  const wasmCases: {
    name: string;
    raw: string;
    expectMessage: RegExp;
    expectRemedy?: string;
  }[] = [
    {
      name: "wrong passphrase (Sequoia S2K)",
      raw: "Incorrect passphrase",
      expectMessage: /wrong password/i,
      expectRemedy: "retry",
    },
    {
      name: "wrong credentials on AES-GCM unlock",
      raw: "Decryption failed - wrong credentials or corrupted data",
      expectMessage: /wrong password/i,
      expectRemedy: "retry",
    },
    {
      name: "no matching secret key",
      raw: "No suitable decryption key found",
      expectMessage: /encrypted to a key you don't hold/i,
      expectRemedy: "import-key",
    },
    {
      name: "not a key / not armored",
      raw: "No OpenPGP certificate found",
      expectMessage: /doesn't look like PGP data/i,
    },
    {
      name: "malformed message",
      raw: "Malformed Message: Malformed OpenPGP message",
      expectMessage: /doesn't look like PGP data/i,
    },
    {
      name: "corrupted packet data",
      raw: "Malformed packet: Truncated packet body",
      expectMessage: /corrupted or was cut off/i,
      expectRemedy: "retry",
    },
    {
      name: "expired key",
      raw: "Primary key is not live: expired at 2024-01-01T00:00:00Z",
      expectMessage: /has expired/i,
      expectRemedy: "check-recipient",
    },
    {
      name: "revoked key",
      raw: "This key has been revoked by its owner (key compromised)",
      expectMessage: /revoked by its owner/i,
      expectRemedy: "check-recipient",
    },
    {
      name: "policy-rejected key",
      raw: "Key rejected by security policy: SHA1 is not considered secure",
      expectMessage: /no longer considered secure/i,
    },
    {
      name: "not a CRX file",
      raw: "Not a CRX file (missing Cr24 magic)",
      expectMessage: /isn't a Chrome extension package/i,
    },
    {
      name: "CRX signature mismatch",
      raw: "No valid signature: the CRX is unsigned by this key or was tampered with",
      expectMessage: /signature doesn't match/i,
    },
  ];

  for (const c of wasmCases) {
    it(`classifies ${c.name} (thrown as string)`, () => {
      const presented = presentError(c.raw, FALLBACK);
      expect(presented.message).toMatch(c.expectMessage);
      expect(presented.remedy?.action).toBe(c.expectRemedy);
      expect(presented.detail).toBe(c.raw);
    });

    it(`classifies ${c.name} (thrown as Error)`, () => {
      const presented = presentError(new Error(c.raw), FALLBACK);
      expect(presented.message).toMatch(c.expectMessage);
      expect(presented.remedy?.action).toBe(c.expectRemedy);
    });

    it(`never echoes the raw input as the message for ${c.name}`, () => {
      const presented = presentError(c.raw, FALLBACK);
      expect(presented.message).not.toBe(c.raw);
      expect(presented.message).not.toBe(FALLBACK);
    });
  }

  it("extracts the recipient key ID when the error carries one", () => {
    const raw =
      "No suitable decryption key found (message is keyed to 4F25E3B6C8D90A12)";
    const presented = presentError(raw, FALLBACK);
    expect(presented.message).toContain("4F25E3B6C8D90A12");
    expect(presented.remedy?.action).toBe("import-key");
  });

  it("omits the key ID when the error has none", () => {
    const presented = presentError(
      "No suitable decryption key found",
      FALLBACK,
    );
    expect(presented.message).not.toMatch(/key ID/);
  });

  it("keeps the curated tamper copy for bad signatures", () => {
    const raw =
      "Signature verification FAILED - this message may have been tampered with";
    const presented = presentError(new Error(raw), FALLBACK);
    expect(presented.message).toMatch(/tampered/i);
    expect(presented.message).not.toBe(raw);
  });

  describe("WebAuthn", () => {
    it("treats NotAllowedError as a user cancel, not a failure", () => {
      const e = new DOMException(
        "The operation was aborted",
        "NotAllowedError",
      );
      const presented = presentError(e, FALLBACK);
      expect(presented.message).toMatch(/dismissed/i);
      expect(presented.remedy?.action).toBe("retry");
    });

    it("classifies a generic passkey failure as a failure", () => {
      const e = new AppError("passkey-failed", "Passkey authentication failed");
      const presented = presentError(e, FALLBACK);
      expect(presented.message).toMatch(/passkey didn't complete/i);
      expect(presented.remedy?.action).toBe("retry");
    });

    it("classifies the legacy string form of a passkey failure", () => {
      const presented = presentError("Passkey registration failed", FALLBACK);
      expect(presented.message).toMatch(/passkey didn't complete/i);
    });
  });

  describe("AppError codes", () => {
    it("key-not-found offers an import remedy", () => {
      const e = new AppError(
        "key-not-found",
        "Key not found - the certificate was not saved.",
      );
      const presented = presentError(e, FALLBACK);
      expect(presented.message).toMatch(/no longer in your keyring/i);
      expect(presented.remedy?.action).toBe("import-key");
      expect(presented.detail).toBe(e.message);
    });

    it("key-locked offers an unlock remedy", () => {
      const e = new AppError("key-locked", "Key is not unlocked.");
      const presented = presentError(e, FALLBACK);
      expect(presented.remedy?.action).toBe("unlock");
      expect(presented.message).not.toBe(e.message);
    });

    it("vault-locked offers an unlock remedy", () => {
      const e = new AppError(
        "vault-locked",
        "Cannot save CRX keys: the vault is locked",
      );
      const presented = presentError(e, FALLBACK);
      expect(presented.message).toMatch(/vault is locked/i);
      expect(presented.remedy?.action).toBe("unlock");
    });

    it("weak-password states the requirement", () => {
      const e = new AppError(
        "weak-password",
        "Password must be at least 8 characters",
      );
      const presented = presentError(e, FALLBACK);
      expect(presented.message).toMatch(/at least 8 characters/i);
      expect(presented.message).not.toBe(e.message);
    });
  });

  it("classifies locked-session errors thrown as plain strings", () => {
    const presented = presentError(
      "Cannot save contacts: the vault is locked",
      FALLBACK,
    );
    expect(presented.remedy?.action).toBe("unlock");
  });

  it("classifies chrome.storage quota errors", () => {
    const e = new Error("Resource::kQuotaBytesPerItem quota exceeded");
    const presented = presentError(e, FALLBACK);
    expect(presented.message).toMatch(/storage is full/i);
    expect(presented.detail).toBe(e.message);
  });

  it("falls back for unknown errors, preserving the raw text as detail", () => {
    const presented = presentError(new Error("ENOENT: whatever"), FALLBACK);
    expect(presented.message).toBe(FALLBACK);
    expect(presented.detail).toBe("ENOENT: whatever");
    expect(presented.remedy).toBeUndefined();
  });

  it("falls back with no detail for empty errors", () => {
    expect(presentError(undefined, FALLBACK)).toEqual({
      message: FALLBACK,
      detail: undefined,
    });
    expect(presentError("", FALLBACK)).toEqual({
      message: FALLBACK,
      detail: undefined,
    });
  });
});

describe("symmetric (password) decryption", () => {
  it("tells the user their password didn't work, not that the data is corrupt", () => {
    // THE ORDERING TEST. The engine's string carries the underlying
    // Sequoia error along with it, and for a v4 message that error is an
    // MDC failure -- which the corrupt/malformed rule matches. If that
    // rule wins, a user with a mistyped password is told to go and get a
    // fresh copy of a message that was never damaged.
    const raw =
      "Wrong password, or this message is damaged: Malformed MDC packet";
    const p = presentError(raw, FALLBACK);
    expect(p.message).toContain("That password didn't open this message");
    expect(p.message).not.toContain("corrupted");
    expect(p.detail).toBe(raw);
    expect(p.remedy?.action).toBe("retry");
  });

  it("does not blame the password for a format it cannot read", () => {
    // No password opens an OCB message here, so "check it and try again"
    // is advice that leads nowhere. This must NOT fall into the rule
    // above.
    const raw =
      "This message uses the older AEAD (OCB) encrypted-data format, which this app cannot read. Ask the sender to re-encrypt it without --force-ocb.";
    const p = presentError(raw, FALLBACK);
    expect(p.message).toContain("older AEAD (OCB) format");
    expect(p.message).not.toContain("Check it and try again");
    // Nothing to retry: the remedy slot stays empty rather than offering
    // an action that cannot help.
    expect(p.remedy).toBeUndefined();
  });
});
