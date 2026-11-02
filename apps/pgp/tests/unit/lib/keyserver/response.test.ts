import { describe, expect, it } from "vitest";

import {
  MAX_BODY_BYTES,
  parseKeyserverKeyResponse,
} from "~/lib/keyserver/response";

const PGP_CT = "application/pgp-keys";

const CERT = [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----",
  "",
  "mDMEZaBcDRYJKwYBBAHaRw8BAQdA0000000000000000000000000000000000000",
  "=abcd",
  "-----END PGP PUBLIC KEY BLOCK-----",
].join("\n");

function raw(over: Partial<Parameters<typeof parseKeyserverKeyResponse>[0]>) {
  return { status: 200, contentType: PGP_CT, body: CERT, ...over };
}

describe("parseKeyserverKeyResponse", () => {
  it("forwards the armor from a measured answer", () => {
    expect(parseKeyserverKeyResponse(raw({}))).toEqual({
      ok: true,
      armored: CERT,
      omitted: 0,
    });
  });

  it("reports 404 as not-found, never as an error", () => {
    // The real 404 is text/html quoting the query; prose must not render.
    expect(
      parseKeyserverKeyResponse(
        raw({
          status: 404,
          contentType: "text/html; charset=utf-8",
          body: "No key found for email address <script>alert(1)</script>",
        }),
      ),
    ).toEqual({ ok: false, error: "not-found" });
  });

  it("reads retry-after on a 429", () => {
    const now = 1_700_000_000_000;
    expect(
      parseKeyserverKeyResponse(raw({ status: 429, retryAfter: "300" }), now),
    ).toEqual({ ok: false, error: "rate-limited", retryAt: now + 300_000 });
  });

  it("drops a retry-after that is absurd, malformed, or a date", () => {
    const now = 1_700_000_000_000;
    for (const header of [
      "1e300",
      "999999999",
      "-5",
      "soon",
      "Wed, 21 Oct 2026 07:28:00 GMT",
      "",
    ]) {
      expect(
        parseKeyserverKeyResponse(
          raw({ status: 429, retryAfter: header }),
          now,
        ),
      ).toEqual({ ok: false, error: "rate-limited" });
    }
  });

  it("maps every other status to server-error", () => {
    for (const status of [301, 400, 403, 500, 502, 503]) {
      expect(parseKeyserverKeyResponse(raw({ status }))).toEqual({
        ok: false,
        error: "server-error",
      });
    }
  });

  it("refuses a 200 that is not application/pgp-keys", () => {
    for (const ct of [
      null,
      "text/html",
      "text/plain",
      "application/json",
      "application/pgp-keys-x",
    ]) {
      expect(parseKeyserverKeyResponse(raw({ contentType: ct }))).toEqual({
        ok: false,
        error: "server-error",
      });
    }
  });

  it("accepts the content type with parameters and odd casing", () => {
    expect(
      parseKeyserverKeyResponse(
        raw({ contentType: "Application/PGP-Keys; charset=utf-8" }),
      ).ok,
    ).toBe(true);
  });

  it("refuses a body over the cap, measured in BYTES", () => {
    // Astral chars: 4 bytes, 2 code units.
    const astral = "\u{1F600}".repeat(MAX_BODY_BYTES / 2);
    expect(astral.length).toBeLessThanOrEqual(MAX_BODY_BYTES);
    expect(parseKeyserverKeyResponse(raw({ body: astral }))).toEqual({
      ok: false,
      error: "server-error",
    });
  });

  it("refuses a 200 with no public key armor in it", () => {
    for (const body of [
      "",
      "not a key",
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nno end marker",
      // A PRIVATE block can never be forwarded as a contact.
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----",
    ]) {
      expect(parseKeyserverKeyResponse(raw({ body }))).toEqual({
        ok: false,
        error: "server-error",
      });
    }
  });

  it("forwards the first block and counts the rest", () => {
    // Counted, not silently truncated.
    const second = CERT.replace("mDMEZ", "mDMEY");
    const result = parseKeyserverKeyResponse(
      raw({ body: `${CERT}\n\n${second}` }),
    );
    expect(result).toEqual({ ok: true, armored: CERT, omitted: 1 });
  });

  it("ignores whatever surrounds the armor", () => {
    const result = parseKeyserverKeyResponse(
      raw({ body: `junk before\n${CERT}\njunk after` }),
    );
    expect(result.ok && result.armored).toBe(CERT);
  });
});
