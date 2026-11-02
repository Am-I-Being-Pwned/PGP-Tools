import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { AppError } from "~/lib/errors/app-error";
import {
  decodeEngineError,
  ENGINE_ERROR_CODES,
  EngineError,
  withEngineErrors,
  type EngineErrorCode,
} from "~/lib/errors/engine-error";
import { presentError } from "~/lib/errors/present";
import { errorMessage } from "~/lib/utils/errors";

const FALLBACK = "The operation failed. Try again.";

/** What the engine puts on the wire for a coded error. */
const wire = (code: string, text: string) => `\u001f${code}\u001f${text}`;

/** A coded error as the wasm boundary hands it to callers. */
function thrownByEngine(code: EngineErrorCode, text: string): unknown {
  const mod = withEngineErrors({
    run: () => {
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- wasm-bindgen throws a bare string
      throw wire(code, text);
    },
  });
  try {
    mod.run();
  } catch (e) {
    return e;
  }
  throw new Error("did not throw");
}

describe("engine error codes", () => {
  it("match the Rust ErrorCode list exactly", () => {
    const rust = readFileSync(
      new URL("../../../../gpg-wasm/src/error_code.rs", import.meta.url),
      "utf8",
    );
    const names = [...rust.matchAll(/=> "([a-z-]+)",/g)].map((m) => m[1]);
    expect([...names].sort()).toEqual([...ENGINE_ERROR_CODES].sort());
  });

  it("decodes a known leading code into an EngineError", () => {
    const e = decodeEngineError(
      wire("wrong-passphrase", "Incorrect passphrase"),
    );
    expect(e).toBeInstanceOf(EngineError);
    expect(e).toMatchObject({
      code: "wrong-passphrase",
      message: "Incorrect passphrase",
    });
  });

  it("leaves an uncoded string untouched", () => {
    expect(decodeEngineError("Malformed packet: x")).toBe(
      "Malformed packet: x",
    );
  });

  it("strips an unknown code but does not classify on it", () => {
    expect(decodeEngineError(wire("no-such-code", "text"))).toBe("text");
  });

  it("only honours a leading code", () => {
    const quoted = `Failed: ${wire("wrong-passphrase", "x")}`;
    expect(decodeEngineError(quoted)).toBe(quoted);
  });

  it("is not an Error, so `instanceof Error` sites keep their generic copy", () => {
    const e = thrownByEngine("wrong-passphrase", "Incorrect passphrase");
    expect(e).not.toBeInstanceOf(Error);
    expect(String(e)).toBe("Incorrect passphrase");
    expect(`${e as string}`).toBe("Incorrect passphrase");
    expect(errorMessage(e, "fb")).toBe("Incorrect passphrase");
  });

  describe("withEngineErrors", () => {
    it("passes arguments and return values straight through", () => {
      const mod = withEngineErrors({
        add: (a: number, b: number) => a + b,
        version: "1",
      });
      expect(mod.add(2, 3)).toBe(5);
      expect(mod.version).toBe("1");
    });

    it("rethrows an uncoded string as the same string", () => {
      const sentinel = "This message is too large to open automatically.";
      const mod = withEngineErrors({
        run: () => {
          // eslint-disable-next-line @typescript-eslint/only-throw-error -- wasm-bindgen throws a bare string
          throw sentinel;
        },
      });
      expect(() => mod.run()).toThrow(sentinel);
      try {
        mod.run();
      } catch (e) {
        expect(e).toBe(sentinel);
      }
    });

    it("rethrows non-string throws untouched", () => {
      const boom = new RangeError("unreachable");
      const mod = withEngineErrors({
        run: () => {
          throw boom;
        },
      });
      expect(() => mod.run()).toThrow(boom);
    });
  });
});

describe("presentError: engine codes", () => {
  // Raw texts are verbatim from gpg-wasm/src/{lib,crx}.rs.
  const cases: {
    code: EngineErrorCode;
    raw: string;
    expectMessage: RegExp;
    expectRemedy?: string;
  }[] = [
    {
      code: "wrong-passphrase",
      raw: "Incorrect passphrase",
      expectMessage: /wrong password/i,
      expectRemedy: "retry",
    },
    {
      code: "wrong-passphrase",
      raw: "Decryption failed - wrong credentials or corrupted data",
      expectMessage: /wrong password/i,
      expectRemedy: "retry",
    },
    {
      code: "not-encrypted",
      raw: "This message is not encrypted. It may be signed, but it was readable on the way and anyone could have sent this copy.",
      expectMessage: /not encrypted/i,
    },
    {
      code: "too-large",
      raw: "This message is too large to open here.",
      expectMessage: /too large to open here.*size/i,
    },
    {
      code: "too-large",
      raw: "This signed message is too large to verify here (limit 24 MiB).",
      expectMessage: /too large to open here/i,
    },
    {
      code: "symmetric-wrong-password",
      raw: "Wrong password, or this message is damaged: Malformed MDC packet",
      expectMessage: /That password didn't open this message/,
      expectRemedy: "retry",
    },
    {
      code: "ocb-unsupported",
      raw: "This message uses the older AEAD (OCB) encrypted-data format, which this app cannot read. Ask the sender to re-encrypt it without --force-ocb.",
      expectMessage: /older AEAD \(OCB\) format/,
    },
    {
      code: "no-decryption-key",
      raw: "No suitable decryption key found",
      expectMessage: /encrypted to a key you don't hold/i,
      expectRemedy: "import-key",
    },
    {
      code: "not-crx",
      raw: "Not a CRX file (missing Cr24 magic)",
      expectMessage: /isn't a Chrome extension package/i,
    },
    {
      code: "crx-unsigned",
      raw: "No valid signature: the CRX is unsigned by this key or was tampered with",
      expectMessage: /signature doesn't match/i,
    },
    {
      code: "text-outside-signature",
      raw: "This message has text outside the signed part, which the signature does not cover",
      expectMessage: /only the signed message/i,
    },
    {
      code: "key-expired",
      raw: "Can't encrypt to Alice: the key has expired. Ask them for a renewed key.",
      expectMessage: /has expired/i,
      expectRemedy: "check-recipient",
    },
    {
      code: "key-revoked",
      raw: "Can't encrypt to Alice: the key has been revoked by its owner (key compromised). Ask them for their current key.",
      expectMessage: /revoked by its owner/i,
      expectRemedy: "check-recipient",
    },
    {
      code: "not-pgp-data",
      raw: "No OpenPGP certificate found",
      expectMessage: /doesn't look like PGP data/i,
    },
  ];

  it("covers every code", () => {
    expect(new Set(cases.map((c) => c.code))).toEqual(
      new Set(ENGINE_ERROR_CODES),
    );
  });

  for (const c of cases) {
    it(`${c.code}: ${c.raw.slice(0, 40)}`, () => {
      const p = presentError(thrownByEngine(c.code, c.raw), FALLBACK);
      expect(p.message).toMatch(c.expectMessage);
      expect(p.remedy?.action).toBe(c.expectRemedy);
      // The engine's text is the detail, never the message.
      expect(p.detail).toBe(c.raw);
      expect(p.message).not.toBe(c.raw);
    });

    it(`${c.code}: classifies on the code, not the wording`, () => {
      const reworded = presentError(
        thrownByEngine(c.code, "Something else entirely."),
        FALLBACK,
      );
      const original = presentError(thrownByEngine(c.code, c.raw), FALLBACK);
      if (c.code === "no-decryption-key") {
        expect(reworded.remedy).toEqual(original.remedy);
        return;
      }
      expect(reworded.message).toBe(original.message);
      expect(reworded.remedy).toEqual(original.remedy);
    });
  }

  it("our own engine text without its code is not classified", () => {
    // Rewording safety cuts both ways: the UI no longer reads our prose.
    for (const raw of [
      "Incorrect passphrase",
      "This message is too large to open here.",
      "No suitable decryption key found",
    ]) {
      expect(presentError(raw, FALLBACK).message).toBe(FALLBACK);
    }
  });

  it("symmetric failure never reads as corruption, whatever Sequoia says", () => {
    // The Sequoia text riding along would match the corrupt rule.
    const raw =
      "Wrong password, or this message is damaged: Malformed MDC packet";
    const p = presentError(
      thrownByEngine("symmetric-wrong-password", raw),
      FALLBACK,
    );
    expect(p.message).not.toContain("corrupted");
  });

  it("OCB offers no remedy: no password opens it", () => {
    const p = presentError(
      thrownByEngine("ocb-unsupported", "older AEAD (OCB)"),
      FALLBACK,
    );
    expect(p.message).not.toContain("Check it and try again");
    expect(p.remedy).toBeUndefined();
  });

  it("names the recipient key ID when the engine text carries one", () => {
    const p = presentError(
      thrownByEngine(
        "no-decryption-key",
        "No suitable decryption key found (message is keyed to 4F25E3B6C8D90A12)",
      ),
      FALLBACK,
    );
    expect(p.message).toContain("4F25E3B6C8D90A12");
    expect(p.remedy?.action).toBe("import-key");
  });

  it("omits the key ID when the engine text has none", () => {
    const p = presentError(
      thrownByEngine("no-decryption-key", "No suitable decryption key found"),
      FALLBACK,
    );
    expect(p.message).not.toMatch(/key ID/);
  });
});

describe("presentError: uncoded (Sequoia / std / app) text", () => {
  const cases: {
    name: string;
    raw: string;
    expectMessage: RegExp;
    expectRemedy?: string;
  }[] = [
    {
      name: "malformed message",
      raw: "Malformed Message: Malformed OpenPGP message",
      expectMessage: /doesn't look like PGP data/i,
    },
    {
      name: "unexpected EOF",
      raw: "unexpected EOF",
      expectMessage: /doesn't look like PGP data/i,
    },
    {
      name: "corrupted packet data",
      raw: "Malformed packet: Truncated packet body",
      expectMessage: /corrupted or was cut off/i,
      expectRemedy: "retry",
    },
    {
      name: "Sequoia expiry",
      raw: "Expired on 2024-01-01T00:00:00Z",
      expectMessage: /has expired/i,
      expectRemedy: "check-recipient",
    },
  ];

  for (const c of cases) {
    it(`classifies ${c.name} (string and Error)`, () => {
      for (const e of [c.raw, new Error(c.raw)]) {
        const p = presentError(e, FALLBACK);
        expect(p.message).toMatch(c.expectMessage);
        expect(p.remedy?.action).toBe(c.expectRemedy);
        expect(p.detail).toBe(c.raw);
      }
    });
  }

  it("keeps the curated tamper copy for bad signatures", () => {
    const raw =
      "Signature verification FAILED - this message may have been tampered with";
    const p = presentError(new Error(raw), FALLBACK);
    expect(p.message).toMatch(/tampered/i);
    expect(p.message).not.toBe(raw);
  });

  it("classifies chrome.storage quota errors", () => {
    const e = new Error("Resource::kQuotaBytesPerItem quota exceeded");
    const p = presentError(e, FALLBACK);
    expect(p.message).toMatch(/storage is full/i);
    expect(p.detail).toBe(e.message);
  });

  it("falls back for unknown errors, preserving the raw text as detail", () => {
    const p = presentError(new Error("ENOENT: whatever"), FALLBACK);
    expect(p.message).toBe(FALLBACK);
    expect(p.detail).toBe("ENOENT: whatever");
    expect(p.remedy).toBeUndefined();
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

describe("presentError: WebAuthn", () => {
  it("treats NotAllowedError as a user cancel, not a failure", () => {
    const e = new DOMException("The operation was aborted", "NotAllowedError");
    const p = presentError(e, FALLBACK);
    expect(p.message).toMatch(/dismissed/i);
    expect(p.remedy?.action).toBe("retry");
  });
});

// For AppErrors the REMEDY matters most: it renders as the button, so an
// unlock failure offering "Try again" sends the user in a circle.
describe("presentError: AppError codes", () => {
  it("key-not-found offers an import remedy", () => {
    const e = new AppError(
      "key-not-found",
      "Key not found - the certificate was not saved.",
    );
    const p = presentError(e, FALLBACK);
    expect(p.message).toMatch(/no longer in your keyring/i);
    expect(p.remedy?.action).toBe("import-key");
    expect(p.detail).toBe(e.message);
  });

  it("key-locked offers an unlock remedy", () => {
    const e = new AppError("key-locked", "Key is not unlocked.");
    const p = presentError(e, FALLBACK);
    expect(p.remedy?.action).toBe("unlock");
    expect(p.message).not.toBe(e.message);
  });

  it("vault-locked offers an unlock remedy", () => {
    const e = new AppError(
      "vault-locked",
      "Cannot save CRX keys: the vault is locked",
    );
    const p = presentError(e, FALLBACK);
    expect(p.message).toMatch(/vault is locked/i);
    expect(p.remedy?.action).toBe("unlock");
  });

  it("weak-password names the requirement, with nowhere to navigate", () => {
    const p = presentError(
      new AppError("weak-password", "too short"),
      FALLBACK,
    );
    expect(p.message).toMatch(/at least 8 characters/i);
    expect(p.remedy).toBeUndefined();
  });

  it("password-required offers Unlock, not Try again", () => {
    const p = presentError(
      new AppError("password-required", "needs password"),
      FALLBACK,
    );
    expect(p.message).toMatch(/key password/i);
    expect(p.remedy).toEqual({ label: "Unlock", action: "unlock" });
    expect(p.detail).toBe("needs password");
  });

  it("passkey-failed offers Try again", () => {
    const p = presentError(
      new AppError("passkey-failed", "ceremony aborted"),
      FALLBACK,
    );
    expect(p.message).toMatch(/passkey didn't complete/i);
    expect(p.remedy).toEqual({ label: "Try again", action: "retry" });
  });

  it("ssh-passphrase-required passes the engine's sentence through unrewritten", () => {
    const message = "This SSH key is passphrase-protected.";
    const p = presentError(
      new AppError("ssh-passphrase-required", message),
      FALLBACK,
    );
    expect(p.message).toBe(message);
    expect(p.remedy).toBeUndefined();
    expect(p.detail).toBeUndefined();
  });
});

describe("presentError: PrfNotSupportedError", () => {
  it("passes its curated platform-specific copy straight through", () => {
    const e = new Error("macOS requires 15+ with iCloud Keychain.");
    e.name = "PrfNotSupportedError";
    expect(presentError(e, FALLBACK).message).toBe(
      "macOS requires 15+ with iCloud Keychain.",
    );
  });

  it("is matched by name, not by class identity", () => {
    const e = new Error("no PRF here");
    e.name = "PrfNotSupportedError";
    expect(presentError(e, FALLBACK).message).toBe("no PRF here");
  });
});
