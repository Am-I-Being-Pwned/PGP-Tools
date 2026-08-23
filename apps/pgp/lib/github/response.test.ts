import { describe, expect, it } from "vitest";

import type { GithubKeysRawResponse } from "./response";
import {
  MAX_BODY_BYTES,
  MAX_KEY_CHARS,
  MAX_KEYS,
  parseGithubKeysResponse,
} from "./response";

const JSON_CT = "application/json; charset=utf-8";

/** Measured shape: bare `ssh-ed25519 AAAA<base64>`, comments/emails
 *  already stripped by GitHub. */
const ED25519 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdummykeymaterialforunittests01";
const RSA = `ssh-rsa AAAAB3NzaC1yc2E${"A".repeat(60)}`;
/** Published, real, and unusable by the age engine. The worker must
 *  still forward all three -- `parseSshRecipient` owns the refusal. */
const ECDSA = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY${"A".repeat(40)}`;
const FIDO = `sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t${"A".repeat(30)}`;
const DSA = `ssh-dss AAAAB3NzaC1kc3MAAACB${"A".repeat(80)}`;

function entry(key: string, id = 1) {
  return { id, key, created_at: "2024-01-01T00:00:00.000Z", last_used: null };
}

function raw(over: Partial<GithubKeysRawResponse>): GithubKeysRawResponse {
  return { status: 200, contentType: JSON_CT, body: "[]", ...over };
}

describe("parseGithubKeysResponse status mapping", () => {
  const CASES: [string, GithubKeysRawResponse, string][] = [
    [
      "404 not found",
      raw({ status: 404, body: JSON.stringify({ message: "Not Found" }) }),
      "not-found",
    ],
    ["200 with empty array", raw({ body: "[]" }), "no-keys"],
    [
      "403 rate limited",
      raw({ status: 403, rateLimitRemaining: "0" }),
      "rate-limited",
    ],
    ["429 rate limited", raw({ status: 429 }), "rate-limited"],
    ["500", raw({ status: 500 }), "server-error"],
    ["502", raw({ status: 502 }), "server-error"],
    ["301 redirect leaked through", raw({ status: 301 }), "server-error"],
    ["204", raw({ status: 204 }), "server-error"],
  ];

  it.each(CASES)("%s -> %s", (_label, input, expected) => {
    const result = parseGithubKeysResponse(input);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error).toBe(expected);
  });

  it("distinguishes 200 [] from 404", () => {
    const empty = parseGithubKeysResponse(raw({ body: "[]" }));
    const missing = parseGithubKeysResponse(raw({ status: 404 }));
    expect(empty.ok === false && empty.error).toBe("no-keys");
    expect(missing.ok === false && missing.error).toBe("not-found");
  });
});

describe("parseGithubKeysResponse rate limit reset", () => {
  it("carries resetAt as ms when the header is present", () => {
    const result = parseGithubKeysResponse(
      raw({
        status: 403,
        rateLimitRemaining: "0",
        rateLimitReset: "1750000000",
      }),
    );
    expect(result).toEqual({
      ok: false,
      error: "rate-limited",
      resetAt: 1_750_000_000_000,
    });
  });

  it.each([undefined, null, "", "soon", "-5", "0", "NaN"])(
    "omits resetAt for header %s",
    (header) => {
      const result = parseGithubKeysResponse(
        raw({ status: 403, rateLimitReset: header }),
      );
      expect(result.ok === false && result.resetAt).toBeUndefined();
    },
  );
});

describe("parseGithubKeysResponse body handling", () => {
  it("returns the key lines for a measured 200", () => {
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(ED25519, 1), entry(RSA, 2)]) }),
    );
    expect(result).toEqual({ ok: true, lines: [ED25519, RSA], omitted: 0 });
  });

  it.each([
    ["html body", "<!doctype html><html><body>nope</body></html>", JSON_CT],
    ["truncated json", '[{"key":"ssh-ed25519 AAAA', JSON_CT],
    ["json object not array", '{"message":"ok"}', JSON_CT],
    ["json string", '"ssh-ed25519 AAAA"', JSON_CT],
    ["json null", "null", JSON_CT],
    ["empty body", "", JSON_CT],
  ])("%s -> server-error", (_label, body, contentType) => {
    const result = parseGithubKeysResponse(raw({ body, contentType }));
    expect(result.ok === false && result.error).toBe("server-error");
  });

  it.each([
    ["text/html", "text/html; charset=utf-8"],
    ["text/plain", "text/plain"],
    ["missing", null],
  ])("rejects a 200 with content-type %s", (_label, contentType) => {
    const result = parseGithubKeysResponse(
      raw({ contentType, body: JSON.stringify([entry(ED25519)]) }),
    );
    expect(result.ok === false && result.error).toBe("server-error");
  });

  it("accepts application/vnd.github+json", () => {
    const result = parseGithubKeysResponse(
      raw({
        contentType: "application/vnd.github+json",
        body: JSON.stringify([entry(ED25519)]),
      }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a 128 KiB body without parsing it", () => {
    const body = `[${`"${"x".repeat(1024)}",`.repeat(128)}]`.padEnd(
      128 * 1024,
      " ",
    );
    expect(body.length).toBeGreaterThan(64 * 1024);
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok === false && result.error).toBe("server-error");
  });
});

describe("parseGithubKeysResponse shape validation", () => {
  it("caps at 20 keys when the account has 40, and says how many it held back", () => {
    const body = JSON.stringify(
      Array.from({ length: 40 }, (_v, i) => entry(`${ED25519}${i % 10}`, i)),
    );
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok).toBe(true);
    expect(result.ok === true && result.lines).toHaveLength(MAX_KEYS);
    // The truncation is not allowed to be silent: the preview says
    // "encrypted to every key listed above" over this list.
    expect(result.ok === true && result.omitted).toBe(40 - MAX_KEYS);
  });

  it.each([
    ["non-string key", [{ id: 1, key: 12345 }]],
    ["null key", [{ id: 1, key: null }]],
    ["missing key", [{ id: 1 }]],
    ["blank key", [{ id: 1, key: "   " }]],
    ["null entry", [null]],
    ["string entry", ["ssh-ed25519 AAAA"]],
    ["pgp block", [{ id: 1, key: "-----BEGIN PGP PUBLIC KEY BLOCK-----" }]],
    ["javascript url", [{ id: 1, key: "javascript:alert(1)" }]],
  ])("drops %s and reports no-keys", (_label, body) => {
    const result = parseGithubKeysResponse(raw({ body: JSON.stringify(body) }));
    expect(result.ok === false && result.error).toBe("no-keys");
  });

  it("ignores every field other than key", () => {
    const body = JSON.stringify([
      { id: 1, key: ED25519, created_at: "x", last_used: "y", evil: "z" },
    ]);
    expect(parseGithubKeysResponse(raw({ body }))).toEqual({
      ok: true,
      lines: [ED25519],
      omitted: 0,
    });
  });

  it("keeps only the well-shaped line out of a multi-line key field", () => {
    const body = JSON.stringify([
      { id: 1, key: `not a key\n${ED25519}\nalso not a key` },
    ]);
    expect(parseGithubKeysResponse(raw({ body }))).toEqual({
      ok: true,
      lines: [ED25519],
      omitted: 0,
    });
  });

  it("does not let prose from the network escape as a line", () => {
    const body = JSON.stringify([{ id: 1, key: "Your account is suspended." }]);
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok === false && result.error).toBe("no-keys");
  });
});

describe("parseGithubKeysResponse unsupported key types", () => {
  // The regression this suite exists for: the worker used to run every
  // key through a matcher that named `ssh-ed25519|ssh-rsa`, so a
  // published ECDSA/FIDO/DSA key never crossed the message boundary and
  // the engine's curated refusal for it could never be shown.
  it.each([
    ["ecdsa", ECDSA],
    ["fido sk-ssh-ed25519", FIDO],
    ["ssh-dss", DSA],
  ])("forwards a published %s key instead of dropping it", (_label, key) => {
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(key)]) }),
    );
    // NOT no-keys: the account published one, and only the engine gets
    // to say it is unusable.
    expect(result).toEqual({ ok: true, lines: [key], omitted: 0 });
  });

  it("does not report an ECDSA-only account as having published no keys", () => {
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(ECDSA)]) }),
    );
    expect(result.ok === false && result.error).not.toBe("no-keys");
  });

  it("forwards the unsupported key alongside the usable ones", () => {
    const body = JSON.stringify([
      entry(ED25519, 1),
      entry(`${ED25519}9`, 2),
      entry(ECDSA, 3),
    ]);
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok === true && result.lines).toEqual([
      ED25519,
      `${ED25519}9`,
      ECDSA,
    ]);
  });

  it.each([
    ["prose", "Your account is suspended."],
    ["html", "<!doctype html><p>ssh-ed25519 is a key type</p>"],
    ["a type token with spaces", "not a key AAAAB3NzaC1yc2E"],
    ["base64 with no type", "AAAAB3NzaC1yc2EAAAADAQABAAABgQ"],
    ["a javascript url", "javascript:alert(1)"],
  ])("still refuses to forward %s", (_label, key) => {
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(key)]) }),
    );
    expect(result.ok).toBe(false);
  });
});

describe("parseGithubKeysResponse per-key cap", () => {
  it("skips a key string over MAX_KEY_CHARS and counts it", () => {
    const huge = `ssh-rsa AAAAB3NzaC1yc2E${"A".repeat(MAX_KEY_CHARS)}`;
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(ED25519, 1), entry(huge, 2)]) }),
    );
    expect(result).toEqual({ ok: true, lines: [ED25519], omitted: 1 });
  });

  it("does not call an account with only over-long keys empty", () => {
    const huge = `ssh-rsa AAAAB3NzaC1yc2E${"A".repeat(MAX_KEY_CHARS)}`;
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(huge)]) }),
    );
    expect(result).toEqual({ ok: true, lines: [], omitted: 1 });
  });

  it("accepts an RSA-4096 sized line", () => {
    const rsa4096 = `ssh-rsa AAAAB3NzaC1yc2E${"A".repeat(700)}`;
    const result = parseGithubKeysResponse(
      raw({ body: JSON.stringify([entry(rsa4096)]) }),
    );
    expect(result).toEqual({ ok: true, lines: [rsa4096], omitted: 0 });
  });
});

describe("parseGithubKeysResponse body size is measured in bytes", () => {
  // Each emoji is 2 UTF-16 code units and 4 UTF-8 bytes, so a body can
  // sit under the cap by `.length` while being three times over it on
  // the wire -- which is what the cap was being compared against.
  const filler = "\u{1F600}".repeat(30_000);

  it("rejects a body under the cap in code units but over it in bytes", () => {
    const body = `[{"id":1,"key":"${ED25519}","note":"${filler}"}]`;
    expect(body.length).toBeLessThan(MAX_BODY_BYTES);
    expect(new TextEncoder().encode(body).length).toBeGreaterThan(
      MAX_BODY_BYTES,
    );
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok === false && result.error).toBe("server-error");
  });

  it("still accepts a body that is under the cap in both", () => {
    const body = JSON.stringify([entry(ED25519)]);
    expect(new TextEncoder().encode(body).length).toBeLessThan(
      MAX_BODY_BYTES,
    );
    expect(parseGithubKeysResponse(raw({ body })).ok).toBe(true);
  });
});

describe("parseGithubKeysResponse rate limit reset bounds", () => {
  const NOW = 1_800_000_000_000;

  it("keeps a reset inside the next day", () => {
    const result = parseGithubKeysResponse(
      raw({ status: 403, rateLimitReset: String(NOW / 1000 + 3600) }),
      NOW,
    );
    expect(result.ok === false && result.resetAt).toBe(NOW + 3_600_000);
  });

  it.each([
    ["1e300", "1e300"],
    ["year 3000", "32503680000"],
    ["two days out", String(1_800_000_000 + 2 * 86_400)],
  ])("ignores an absurd reset header (%s)", (_label, header) => {
    const result = parseGithubKeysResponse(
      raw({ status: 403, rateLimitReset: header }),
      NOW,
    );
    // Rendering this would produce "try again in about 2.7e+296 hours".
    expect(result.ok === false && result.resetAt).toBeUndefined();
  });
});
