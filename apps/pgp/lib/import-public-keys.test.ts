/**
 * Importing armored public-key blocks as contacts.
 *
 * The subtle requirement, and the reason this function exists rather
 * than a loop at each call site: ONE armored block can bundle SEVERAL
 * certs -- a publisher's yearly-rotated keys, typically with the oldest
 * first. Storing the whole blob against one contact means encrypting to
 * whichever cert the engine picks first, which is usually the expired
 * one. So each cert is stored against its OWN armor, and the block's
 * dead siblings are dropped silently rather than counted as failures:
 * a rotation is not an error the user needs to see.
 *
 * The counters are the other half. They drive the summary copy the user
 * reads after an import, and added/updated is the distinction that tells
 * someone whether a re-fetch actually refreshed anything.
 *
 * `parseKeys` is mocked -- parsing certificates is the WASM engine's job
 * and is covered by the Rust tests. What is tested here is the routing
 * decision made on top of whatever it returns.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { KeyInfo } from "./pgp/types";
import type { PublicContactKey } from "./storage/contacts";
import {
  importPublicKeyBlocks,
  importRejectionMessage,
  isUsableContact,
} from "./import-public-keys";
import { parseKeys } from "./pgp/wasm";

vi.mock("./pgp/wasm", () => ({ parseKeys: vi.fn() }));

const parse = vi.mocked(parseKeys);

function keyInfo(over: Partial<KeyInfo> = {}): KeyInfo {
  return {
    keyId: "FPR1",
    userIds: ["Alice <a@b.test>"],
    algorithm: "ed25519",
    expiresAt: null,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  } as KeyInfo;
}

/** One parsed cert as `parseKeys` returns it. */
function cert(over: Partial<KeyInfo> = {}, armored = "ARMOR-1") {
  return { keyInfo: keyInfo(over), armored };
}

/** Collect what the importer asked to be written. */
function collector() {
  const written: PublicContactKey[] = [];
  return {
    written,
    onImport: (c: PublicContactKey) => {
      written.push(c);
      return Promise.resolve();
    },
  };
}

afterEach(() => {
  vi.resetAllMocks();
});

describe("isUsableContact", () => {
  it.each([
    [
      "encryption only",
      { usableForEncryption: true, usableForSigning: false },
      true,
    ],
    // Sign-only keys are perfectly good contacts -- you just can't
    // encrypt to them.
    [
      "signing only",
      { usableForEncryption: false, usableForSigning: true },
      true,
    ],
    ["both", { usableForEncryption: true, usableForSigning: true }, true],
    ["neither", { usableForEncryption: false, usableForSigning: false }, false],
  ])("accepts a cert usable for %s", (_label, flags, expected) => {
    expect(isUsableContact(keyInfo(flags))).toBe(expected);
  });
});

describe("importRejectionMessage", () => {
  it("explains an absent cert", () => {
    expect(importRejectionMessage(undefined)).toMatch(/no usable public key/);
  });

  it("names the expiry date, because expiry is the common case", () => {
    const expiresAt = new Date("2020-03-04T00:00:00Z").getTime();
    const message = importRejectionMessage(keyInfo({ expiresAt }));
    expect(message).toMatch(/expired on/);
    expect(message).toMatch(/2020/);
    expect(message).toMatch(/current key/);
  });

  it("prefers the expiry message over a policy error", () => {
    const expiresAt = Date.now() - 1000;
    expect(
      importRejectionMessage(keyInfo({ expiresAt, policyError: "weak hash" })),
    ).toMatch(/expired on/);
  });

  it("passes through a policy error for a live key", () => {
    expect(
      importRejectionMessage(keyInfo({ policyError: "SHA-1 is rejected" })),
    ).toBe("SHA-1 is rejected");
  });

  it("does not treat a future expiry as expired", () => {
    const expiresAt = Date.now() + 86_400_000;
    expect(importRejectionMessage(keyInfo({ expiresAt }))).not.toMatch(
      /expired/,
    );
  });

  it("falls back to the generic reason", () => {
    expect(importRejectionMessage(keyInfo())).toMatch(
      /no usable encryption or signing key/,
    );
  });
});

describe("importPublicKeyBlocks", () => {
  it("imports a usable cert and counts it as added", async () => {
    parse.mockResolvedValue([cert()]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary).toMatchObject({
      added: 1,
      updated: 0,
      failed: 0,
      flagged: 0,
    });
    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject({
      keyId: "FPR1",
      armoredPublicKey: "ARMOR-1",
      usableForEncryption: true,
    });
  });

  it("counts a known fingerprint as updated, not added", async () => {
    // The distinction the summary copy depends on: a contact who extended
    // their expiry has been refreshed, not newly added.
    parse.mockResolvedValue([cert()]);
    const { onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], ["FPR1"], onImport);

    expect(summary).toMatchObject({ added: 0, updated: 1 });
  });

  it("stores each cert in a bundled block against its OWN armor", async () => {
    // The bug this prevents: storing the whole blob means encrypting to
    // whichever cert the engine reaches first -- usually the expired one.
    parse.mockResolvedValue([
      cert({ keyId: "OLD" }, "ARMOR-OLD"),
      cert({ keyId: "NEW" }, "ARMOR-NEW"),
    ]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary.added).toBe(2);
    expect(written.map((c) => [c.keyId, c.armoredPublicKey])).toEqual([
      ["OLD", "ARMOR-OLD"],
      ["NEW", "ARMOR-NEW"],
    ]);
  });

  it("drops dead siblings silently when the block has a live cert", async () => {
    // A yearly rotation should read as one import, not "1 added, 1 failed".
    parse.mockResolvedValue([
      cert({
        keyId: "EXPIRED",
        usableForEncryption: false,
        usableForSigning: false,
      }),
      cert({ keyId: "LIVE" }, "ARMOR-LIVE"),
    ]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary).toMatchObject({ added: 1, failed: 0 });
    expect(summary.rejectionReasons).toEqual([]);
    expect(written.map((c) => c.keyId)).toEqual(["LIVE"]);
  });

  it("reports a block whose certs are all unusable", async () => {
    parse.mockResolvedValue([
      cert({
        usableForEncryption: false,
        usableForSigning: false,
        policyError: "revoked",
      }),
    ]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary).toMatchObject({ added: 0, failed: 1 });
    expect(summary.rejectionReasons).toEqual(["revoked"]);
    expect(written).toHaveLength(0);
  });

  it("surfaces the FIRST cert's reason for a multi-cert dead block", async () => {
    parse.mockResolvedValue([
      cert({
        usableForEncryption: false,
        usableForSigning: false,
        policyError: "first",
      }),
      cert({
        usableForEncryption: false,
        usableForSigning: false,
        policyError: "second",
      }),
    ]);
    const { onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary.rejectionReasons).toEqual(["first"]);
  });

  it("reports a block that parses to nothing at all", async () => {
    parse.mockResolvedValue([]);
    const { onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary).toMatchObject({ failed: 1 });
    expect(summary.rejectionReasons).toEqual([
      "This block contains no usable public key.",
    ]);
  });

  it("counts a parse failure without aborting the rest of the import", async () => {
    // One malformed block in a pasted dump must not lose the good ones.
    parse
      .mockRejectedValueOnce(new Error("armor error"))
      .mockResolvedValueOnce([cert({ keyId: "GOOD" })]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BAD", "GOOD"], [], onImport);

    expect(summary).toMatchObject({ added: 1, failed: 1 });
    expect(written.map((c) => c.keyId)).toEqual(["GOOD"]);
  });

  it("does not add a rejection reason for a parse failure", async () => {
    // There is no keyInfo to explain it with; a bare failure count is
    // honest, an invented reason is not.
    parse.mockRejectedValue(new Error("armor error"));
    const { onImport } = collector();

    const summary = await importPublicKeyBlocks(["BAD"], [], onImport);

    expect(summary.rejectionReasons).toEqual([]);
  });

  it("flags a cert carrying a security warning while still importing it", async () => {
    parse.mockResolvedValue([cert({ securityWarning: "SHA-1 binding" })]);
    const { written, onImport } = collector();

    const summary = await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(summary).toMatchObject({ added: 1, flagged: 1 });
    expect(written[0].securityWarning).toBe("SHA-1 binding");
  });

  it("records sign-only keys as not encryption-capable", async () => {
    // The UI uses this to keep them out of the recipient picker while
    // still trusting them for verification.
    parse.mockResolvedValue([
      cert({ usableForEncryption: false, usableForSigning: true }),
    ]);
    const { written, onImport } = collector();

    await importPublicKeyBlocks(["BLOCK"], [], onImport);

    expect(written[0].usableForEncryption).toBe(false);
  });

  it("returns an all-zero summary for no blocks", async () => {
    const { onImport } = collector();
    await expect(importPublicKeyBlocks([], [], onImport)).resolves.toEqual({
      added: 0,
      updated: 0,
      failed: 0,
      flagged: 0,
      rejectionReasons: [],
    });
    expect(parse).not.toHaveBeenCalled();
  });

  it("accumulates across several blocks", async () => {
    parse
      .mockResolvedValueOnce([cert({ keyId: "A" })])
      .mockResolvedValueOnce([cert({ keyId: "B" })])
      .mockResolvedValueOnce([
        cert({
          keyId: "C",
          usableForEncryption: false,
          usableForSigning: false,
        }),
      ]);
    const { onImport } = collector();

    const summary = await importPublicKeyBlocks(
      ["A", "B", "C"],
      ["B"],
      onImport,
    );

    expect(summary).toMatchObject({ added: 1, updated: 1, failed: 1 });
  });
});
