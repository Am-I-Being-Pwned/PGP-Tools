import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyserverKeyResponse } from "../messages";
import type { MergeIntoContact } from "./revocation-check";
import { parseKeys } from "../pgp/wasm";
import { checkRevocation } from "./revocation-check";

vi.mock("../pgp/wasm", () => ({ parseKeys: vi.fn() }));

const FPR = "D477040C70C2156A5C298549BB7E9101495E6BF7";
const contact = { keyId: FPR, armored: "STORED" };

const info = (over: Record<string, unknown> = {}) =>
  ({ keyId: FPR, userIds: ["Sam <sam@example.com>"], ...over }) as never;

const answer = (r: KeyserverKeyResponse | undefined) =>
  vi.fn(() => Promise.resolve(r));
const found = (armored: string) =>
  answer({ ok: true, query: { kind: "fingerprint", value: FPR }, armored });

/** The store's merge, as the check sees it. */
const mergeTo = (keyInfo: object | null) =>
  vi.fn<MergeIntoContact>(() =>
    Promise.resolve(keyInfo ? { keyInfo: keyInfo as never } : undefined),
  );

beforeEach(() => {
  vi.resetAllMocks();
});

describe("checkRevocation", () => {
  it("asks by fingerprint, the query that can't return someone else", async () => {
    const send = answer({ ok: false, error: "not-found" });
    await checkRevocation(contact, mergeTo(info()), send);
    expect(send).toHaveBeenCalledWith({
      type: "KEYSERVER_KEY_REQUEST",
      query: { kind: "fingerprint", value: FPR },
    });
  });

  it("hands the fetched cert to the store's merge, never a copy of its own", async () => {
    // The merge runs on the contact as it is when the answer arrives:
    // the check passes the keyserver's cert, not a stored-plus-fetched
    // record it built from the copy it started with.
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "FETCHED" },
    ]);
    const merge = mergeTo(info({ revoked: true }));
    const result = await checkRevocation(contact, merge, found("FETCHED"));
    expect(merge).toHaveBeenCalledWith(FPR, "FETCHED");
    expect(result).toEqual({ kind: "revoked" });
  });

  it("reports a clean key as current", async () => {
    vi.mocked(parseKeys).mockResolvedValue([{ keyInfo: info(), armored: "X" }]);
    const result = await checkRevocation(contact, mergeTo(info()), found("X"));
    expect(result).toEqual({ kind: "current" });
  });

  it("sends a copy that adds User IDs to the Review instead of saving it", async () => {
    // The store's merge wrote nothing (it never binds a new User ID
    // without the Review); the check hands back the keyserver's copy.
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "FETCHED" },
    ]);
    const merge = vi.fn<MergeIntoContact>(() =>
      Promise.resolve({ keyInfo: info(), needsReview: true as const }),
    );
    const result = await checkRevocation(contact, merge, found("FETCHED"));
    expect(result).toEqual({ kind: "needs-review", armored: "FETCHED" });
  });

  it("writes nothing for a contact deleted while it ran", async () => {
    vi.mocked(parseKeys).mockResolvedValue([{ keyInfo: info(), armored: "X" }]);
    const result = await checkRevocation(contact, mergeTo(null), found("X"));
    expect(result).toEqual({ kind: "gone" });
  });

  it("refuses an answer that is a different key, without merging", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ keyId: "0".repeat(40) }), armored: "OTHER" },
    ]);
    const merge = mergeTo(info());
    const result = await checkRevocation(contact, merge, found("OTHER"));
    expect(result.kind).toBe("wrong-key");
    expect(merge).not.toHaveBeenCalled();
  });

  it("treats an answer the engine can't parse as the wrong key", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("not a cert"));
    const result = await checkRevocation(
      contact,
      mergeTo(info()),
      found("junk"),
    );
    expect(result.kind).toBe("wrong-key");
  });

  it("tells 'not published' apart from a failed lookup", async () => {
    const merge = mergeTo(info());
    expect(
      (
        await checkRevocation(
          contact,
          merge,
          answer({ ok: false, error: "not-found" }),
        )
      ).kind,
    ).toBe("not-published");
    expect(
      await checkRevocation(
        contact,
        merge,
        answer({ ok: false, error: "rate-limited", retryAt: 5 }),
      ),
    ).toEqual({ kind: "failed", error: "rate-limited", retryAt: 5 });
    expect(await checkRevocation(contact, merge, answer(undefined))).toEqual({
      kind: "failed",
      error: "unreachable",
    });
  });

  it("never asks about an id that isn't a fingerprint", async () => {
    const send = answer({ ok: false, error: "not-found" });
    const result = await checkRevocation(
      { keyId: "SHA256:abc", armored: "" },
      mergeTo(info()),
      send,
    );
    expect(result.kind).toBe("failed");
    expect(send).not.toHaveBeenCalled();
  });
});
