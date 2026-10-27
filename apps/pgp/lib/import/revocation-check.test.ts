import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyserverKeyResponse } from "../messages";
import { mergePublicKey, parseKeys } from "../pgp/wasm";
import { checkRevocation } from "./revocation-check";

vi.mock("../pgp/wasm", () => ({
  parseKeys: vi.fn(),
  mergePublicKey: vi.fn(),
}));

const FPR = "D477040C70C2156A5C298549BB7E9101495E6BF7";
const contact = { keyId: FPR, armored: "STORED" };

const info = (over: Record<string, unknown> = {}) =>
  ({ keyId: FPR, userIds: ["Sam <sam@example.com>"], ...over }) as never;

const answer = (r: KeyserverKeyResponse | undefined) =>
  vi.fn(() => Promise.resolve(r));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(mergePublicKey).mockResolvedValue("MERGED");
});

describe("checkRevocation", () => {
  it("asks by fingerprint, the query that can't return someone else", async () => {
    const send = answer({ ok: false, error: "not-found" });
    await checkRevocation(contact, send);
    expect(send).toHaveBeenCalledWith({
      type: "KEYSERVER_KEY_REQUEST",
      query: { kind: "fingerprint", value: FPR },
    });
  });

  it("merges the answer into the stored cert and reports a revocation", async () => {
    vi.mocked(parseKeys).mockImplementation((armored) =>
      Promise.resolve([
        armored === "MERGED"
          ? { keyInfo: info({ revoked: true }), armored: "MERGED" }
          : { keyInfo: info(), armored: "FETCHED" },
      ]),
    );
    const result = await checkRevocation(
      contact,
      answer({
        ok: true,
        query: { kind: "fingerprint", value: FPR },
        armored: "FETCHED",
      }),
    );
    expect(mergePublicKey).toHaveBeenCalledWith("STORED", "FETCHED");
    expect(result).toMatchObject({
      kind: "revoked",
      merged: { armored: "MERGED" },
    });
  });

  it("reports a clean key as current", async () => {
    vi.mocked(parseKeys).mockResolvedValue([{ keyInfo: info(), armored: "X" }]);
    const result = await checkRevocation(
      contact,
      answer({
        ok: true,
        query: { kind: "fingerprint", value: FPR },
        armored: "X",
      }),
    );
    expect(result.kind).toBe("current");
  });

  it("refuses an answer that is a different key, without merging", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ keyId: "0".repeat(40) }), armored: "OTHER" },
    ]);
    const result = await checkRevocation(
      contact,
      answer({
        ok: true,
        query: { kind: "fingerprint", value: FPR },
        armored: "OTHER",
      }),
    );
    expect(result.kind).toBe("wrong-key");
    expect(mergePublicKey).not.toHaveBeenCalled();
  });

  it("treats an answer the engine can't parse as the wrong key", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("not a cert"));
    const result = await checkRevocation(
      contact,
      answer({
        ok: true,
        query: { kind: "fingerprint", value: FPR },
        armored: "junk",
      }),
    );
    expect(result.kind).toBe("wrong-key");
  });

  it("tells 'not published' apart from a failed lookup", async () => {
    expect(
      (
        await checkRevocation(
          contact,
          answer({ ok: false, error: "not-found" }),
        )
      ).kind,
    ).toBe("not-published");
    expect(
      await checkRevocation(
        contact,
        answer({ ok: false, error: "rate-limited", retryAt: 5 }),
      ),
    ).toEqual({ kind: "failed", error: "rate-limited", retryAt: 5 });
    expect(await checkRevocation(contact, answer(undefined))).toEqual({
      kind: "failed",
      error: "unreachable",
    });
  });

  it("never asks about an id that isn't a fingerprint", async () => {
    const send = answer({ ok: false, error: "not-found" });
    const result = await checkRevocation(
      { keyId: "SHA256:abc", armored: "" },
      send,
    );
    expect(result.kind).toBe("failed");
    expect(send).not.toHaveBeenCalled();
  });
});
