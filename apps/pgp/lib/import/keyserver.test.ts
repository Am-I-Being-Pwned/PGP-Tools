/**
 * The keyserver import's decisions. Deliberately short, because the
 * import itself is deliberately thin: a VKS answer is armor, so
 * `prepareImport` does the classification and this module only decides
 * the provenance stamp and the copy.
 *
 * What IS worth pinning here:
 *
 *  1. The contact's identity is the QUERY, not the fingerprint. Alice
 *     rotating her key is exactly the case where the fingerprint changes
 *     and the person does not -- a fingerprint-keyed source would file
 *     her twice.
 *  2. "No key for that address" is a NOTICE, not an error. Nothing
 *     failed and the user has nothing to fix; painting it red teaches
 *     people to distrust a correct answer.
 *  3. Nothing the keyserver wrote reaches the copy. Its 404 body quotes
 *     the query back in `text/html`.
 */
import { describe, expect, it, vi } from "vitest";

import type { KeyserverQuery } from "../keyserver/query";
import {
  KEYSERVER_HOST,
  keyserverFailureCopy,
  keyserverSource,
  prepareKeyserverImport,
} from "./keyserver";
import { prepareImport } from "./prepare";

vi.mock("./prepare", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./prepare")>()),
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
    // `sameSource` composites `type` with `user`; a keyserver query and
    // an account name that happen to read the same are two people.
    expect(keyserverSource(FP, 0).type).toBe("keyserver");
  });
});

describe("prepareKeyserverImport", () => {
  it("stamps the provenance on what prepareImport returned", async () => {
    vi.mocked(prepareImport).mockResolvedValue({
      keys: [{ keyId: "AAAA", publicArmored: "armor" } as never],
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
    // A VKS answer is an OpenPGP certificate by content type and by armor
    // header. Turning on the SSH or CRX engines would only widen what a
    // hostile response could be classified as.
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
    // Names the actual reason: the service only publishes an address its
    // owner has confirmed, so "no key" usually means unverified.
    expect(copy.message).toContain("confirmed");
    expect(copy.message).toContain("alice@example.com");
  });

  it("tells a fingerprint miss apart from an address miss", () => {
    const copy = keyserverFailureCopy("not-found", FP);
    expect(copy.tone).toBe("notice");
    // Grouped the way every other tool prints one, so it can be compared
    // against the fingerprint the user was given.
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
    // Structural: the copy is a pure function of a tagged code and the
    // query WE canonicalised. There is no parameter a response body
    // could travel in, and this is the test that would fail if one were
    // added.
    expect(keyserverFailureCopy.length).toBeLessThanOrEqual(4);
  });
});
