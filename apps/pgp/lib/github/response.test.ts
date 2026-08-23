import { describe, expect, it } from "vitest";

import type { GithubKeysRawResponse } from "./response";
import { MAX_KEYS, parseGithubKeysResponse } from "./response";

const JSON_CT = "application/json; charset=utf-8";

/** Measured shape: bare `ssh-ed25519 AAAA<base64>`, comments/emails
 *  already stripped by GitHub. */
const ED25519 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdummykeymaterialforunittests01";
const RSA = `ssh-rsa AAAAB3NzaC1yc2E${"A".repeat(60)}`;

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
    expect(result).toEqual({ ok: true, lines: [ED25519, RSA] });
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
  it("caps at 20 keys when the account has 40", () => {
    const body = JSON.stringify(
      Array.from({ length: 40 }, (_v, i) => entry(`${ED25519}${i % 10}`, i)),
    );
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok).toBe(true);
    expect(result.ok === true && result.lines).toHaveLength(MAX_KEYS);
  });

  it.each([
    ["non-string key", [{ id: 1, key: 12345 }]],
    ["null key", [{ id: 1, key: null }]],
    ["missing key", [{ id: 1 }]],
    ["blank key", [{ id: 1, key: "   " }]],
    ["null entry", [null]],
    ["string entry", ["ssh-ed25519 AAAA"]],
    ["unsupported ssh-dss", [{ id: 1, key: "ssh-dss AAAAB3NzaC1kc3MAAACB" }]],
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
    });
  });

  it("keeps only the well-shaped line out of a multi-line key field", () => {
    const body = JSON.stringify([
      { id: 1, key: `not a key\n${ED25519}\nalso not a key` },
    ]);
    expect(parseGithubKeysResponse(raw({ body }))).toEqual({
      ok: true,
      lines: [ED25519],
    });
  });

  it("does not let prose from the network escape as a line", () => {
    const body = JSON.stringify([{ id: 1, key: "Your account is suspended." }]);
    const result = parseGithubKeysResponse(raw({ body }));
    expect(result.ok === false && result.error).toBe("no-keys");
  });
});
