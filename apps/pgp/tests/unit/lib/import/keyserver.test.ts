/**
 * The keyserver import's decisions. Pins: identity is the QUERY, not the
 * fingerprint; "no key" is a NOTICE; nothing the keyserver wrote reaches
 * the copy.
 */
import { describe, expect, it, vi } from "vitest";

import {
  answersQuery,
  KEYSERVER_HOST,
  keyserverFailureCopy,
  keyserverSource,
  prepareKeyserverImport,
} from "~/lib/import/keyserver";
import type * as PrepareModule from "~/lib/import/prepare";
import { prepareImport } from "~/lib/import/prepare";
import type { IncomingKey } from "~/lib/import/types";
import type { KeyserverQuery } from "~/lib/keyserver/query";

vi.mock("~/lib/import/prepare", async (importOriginal) => ({
  ...(await importOriginal<typeof PrepareModule>()),
  prepareImport: vi.fn(),
}));

const EMAIL: KeyserverQuery = { kind: "email", value: "alice@example.com" };
const FP: KeyserverQuery = {
  kind: "fingerprint",
  value: "D477040C70C2156A5C298549BB7E9101495E6BF7",
};

describe("keyserverSource", () => {
  it("keys on the query, not the key", () => {
    expect(keyserverSource(EMAIL, 1234)).toEqual({
      type: "keyserver",
      user: "alice@example.com",
      fetchedAt: 1234,
    });
  });

  it("tags the type so it cannot collide with a GitHub user", () => {
    // A keyserver query and a same-named GitHub account are two people.
    expect(keyserverSource(FP, 0).type).toBe("keyserver");
  });
});

describe("prepareKeyserverImport", () => {
  it("stamps the provenance on what prepareImport returned", async () => {
    vi.mocked(prepareImport).mockResolvedValue({
      keys: [
        {
          keyId: "AAAA",
          userIds: ["Alice <alice@example.com>"],
          publicArmored: "armor",
        } as never,
      ],
      secrets: new Map(),
      unparseable: false,
    });

    const prepared = await prepareKeyserverImport(
      EMAIL,
      "armor",
      { own: [], contacts: [] },
      { now: 99 },
    );
    expect(prepared.keys[0].source).toEqual({
      type: "keyserver",
      user: "alice@example.com",
      fetchedAt: 99,
    });
  });

  it("hands the armor to prepareImport with no extra engines on", async () => {
    // SSH/CRX engines off: they would only widen what a hostile response
    // could be classified as.
    vi.mocked(prepareImport).mockResolvedValue({
      keys: [],
      secrets: new Map(),
      unparseable: true,
    });

    await prepareKeyserverImport(FP, "armor", { own: [], contacts: [] });
    expect(vi.mocked(prepareImport).mock.calls.at(-1)?.[2]).toBeUndefined();
  });
});

describe("keyserverFailureCopy", () => {
  it("treats a missing key as a notice, not an error", () => {
    const copy = keyserverFailureCopy("not-found", EMAIL);
    expect(copy.tone).toBe("notice");
    expect(copy.message).toContain("confirmed");
    expect(copy.message).toContain("alice@example.com");
  });

  it("tells a fingerprint miss apart from an address miss", () => {
    const copy = keyserverFailureCopy("not-found", FP);
    expect(copy.tone).toBe("notice");
    expect(copy.message).toContain("D477 040C 70C2");
    expect(copy.message).not.toContain("confirmed");
  });

  it("puts everything else in the destructive slot", () => {
    for (const failure of [
      "invalid-query",
      "offline",
      "rate-limited",
      "server-error",
    ] as const) {
      expect(keyserverFailureCopy(failure, EMAIL).tone).toBe("error");
    }
  });

  it("says roughly when a rate limit lifts, and nothing when it cannot", () => {
    const now = 1_700_000_000_000;
    expect(
      keyserverFailureCopy("rate-limited", EMAIL, now + 300_000, now).message,
    ).toContain("about 5 minutes");
    expect(
      keyserverFailureCopy("rate-limited", EMAIL, undefined, now).message,
    ).not.toContain("Try again in");
  });

  it("names the host it is talking about", () => {
    for (const failure of ["offline", "server-error", "not-found"] as const) {
      expect(keyserverFailureCopy(failure, EMAIL).message).toContain(
        KEYSERVER_HOST,
      );
    }
  });

  it("never renders text that came off the network", () => {
    // Structural: no parameter a response body could travel in.
    expect(keyserverFailureCopy.length).toBeLessThanOrEqual(4);
  });
});

describe("answersQuery: the keyserver's answer is checked, not assumed", () => {
  const key = (over: Partial<IncomingKey>) =>
    ({
      keyId: FP.value,
      userIds: ["Alice <alice@example.com>"],
      details: null,
      ...over,
    }) as IncomingKey;

  it("needs the exact fingerprint for a fingerprint query", () => {
    expect(answersQuery(key({}), FP)).toBe(true);
    expect(answersQuery(key({ keyId: "0".repeat(40) }), FP)).toBe(false);
  });

  const SUB = `${"F".repeat(24)}1234567890ABCDEF`;
  const sub = (over: Record<string, unknown>) =>
    key({
      details: {
        truncated: false,
        keys: [
          {
            fingerprint: SUB,
            isPrimary: false,
            status: "active",
            canSign: false,
            ...over,
          } as never,
        ],
      },
    });
  const KEYID: KeyserverQuery = { kind: "keyid", value: "1234567890ABCDEF" };

  it("accepts a key-ID query naming the primary key or a back-signed signing subkey", () => {
    expect(
      answersQuery(key({ keyId: `${"0".repeat(24)}1234567890ABCDEF` }), KEYID),
    ).toBe(true);
    expect(answersQuery(sub({ canSign: true }), KEYID)).toBe(true);
    // Retired signing subkeys still answer: old messages were signed by them.
    expect(answersQuery(sub({ canSign: true, status: "expired" }), KEYID)).toBe(
      true,
    );
    expect(answersQuery(sub({ canSign: true, status: "revoked" }), KEYID)).toBe(
      true,
    );
    expect(answersQuery(key({}), KEYID)).toBe(false);
  });

  it("does not count an unbound subkey appended to someone else's cert", () => {
    // The engine lists it (status "invalid"), but it is not the cert's.
    expect(answersQuery(sub({ status: "invalid" }), KEYID)).toBe(false);
    expect(answersQuery(sub({ status: "invalid", canSign: true }), KEYID)).toBe(
      false,
    );
  });

  it("does not count someone's key grafted on as a flagless or encryption subkey", () => {
    // Non-signing subkeys need no back-signature: Mallory can bind Alice's key.
    expect(answersQuery(sub({}), KEYID)).toBe(false);
    expect(answersQuery(sub({ canEncrypt: true }), KEYID)).toBe(false);
    expect(answersQuery(sub({ canAuthenticate: true }), KEYID)).toBe(false);
    expect(answersQuery(sub({}), { kind: "fingerprint", value: SUB })).toBe(
      false,
    );
  });

  it("accepts a fingerprint query naming a back-signed signing subkey exactly", () => {
    // "Look up signer" queries the issuer, usually a signing SUBKEY.
    const query: KeyserverQuery = { kind: "fingerprint", value: SUB };
    expect(answersQuery(sub({ canSign: true }), query)).toBe(true);
    expect(
      answersQuery(
        sub({ canSign: true, fingerprint: SUB.toLowerCase() }),
        query,
      ),
    ).toBe(true);
    // Exact match, not a suffix.
    expect(
      answersQuery(
        sub({ canSign: true, fingerprint: `0${SUB.slice(1)}` }),
        query,
      ),
    ).toBe(false);
    expect(answersQuery(sub({ canSign: true, isPrimary: true }), query)).toBe(
      false,
    );
  });

  it("needs a User ID carrying the address for an address query", () => {
    expect(answersQuery(key({}), EMAIL)).toBe(true);
    expect(answersQuery(key({ userIds: ["ALICE@EXAMPLE.COM"] }), EMAIL)).toBe(
      true,
    );
    expect(
      answersQuery(key({ userIds: ["Mallory <mallory@evil.test>"] }), EMAIL),
    ).toBe(false);
    // Not fooled by Unicode case folding: "ı".toUpperCase() is "I".
    expect(
      answersQuery(key({ userIds: ["Al <al\u0131ce@example.com>"] }), EMAIL),
    ).toBe(false);
    // Not fooled by the address appearing as a name.
    expect(
      answersQuery(
        key({ userIds: ["alice@example.com <mallory@evil.test>"] }),
        EMAIL,
      ),
    ).toBe(false);
  });
});

describe("prepareKeyserverImport: what the preview is told", () => {
  it("rejects a key that is not the one asked for", async () => {
    vi.mocked(prepareImport).mockResolvedValue({
      keys: [
        {
          keyId: "BBBB",
          status: "new",
          userIds: ["Mallory <mallory@evil.test>"],
          publicArmored: "armor",
        } as never,
      ],
      secrets: new Map(),
      unparseable: false,
    });
    const prepared = await prepareKeyserverImport(EMAIL, "armor", {
      own: [],
      contacts: [],
    });
    expect(prepared.keys[0].status).toBe("rejected");
    expect(prepared.keys[0].rejection).toContain(KEYSERVER_HOST);
  });

  it("says a re-fetch with a new fingerprint replaces the stored key", async () => {
    vi.mocked(prepareImport).mockResolvedValue({
      keys: [
        {
          keyId: "NEWFPR",
          status: "new",
          userIds: ["Alice <alice@example.com>"],
          publicArmored: "armor",
        } as never,
      ],
      secrets: new Map(),
      unparseable: false,
    });
    const prepared = await prepareKeyserverImport(EMAIL, "armor", {
      own: [],
      contacts: [
        {
          keyId: "OLDFPR",
          userIds: ["Alice Old <alice@example.com>"],
          armored: "old",
          source: {
            type: "keyserver",
            user: "alice@example.com",
            fetchedAt: 1,
          },
        },
      ],
    });
    expect(prepared.keys[0].replaces).toBe("Alice Old <alice@example.com>");
  });
});
