import { describe, expect, it } from "vitest";

import type { SignedResult } from "./signature-summary";
import {
  mixedBatchNote,
  notAddressed,
  signatureNote,
  signedForOthers,
  summariseBatch,
} from "./signature-summary";

const ALICE = "A".repeat(40);
const BOB = "B".repeat(40);

function sig(over: Partial<SignedResult> = {}): SignedResult {
  return {
    signatureStatus: "valid",
    signerKeyId: ALICE,
    signedAt: null,
    signerKeyCurrent: true,
    otherSignerKeyIds: [],
    unverifiedSignatures: 0,
    intendedRecipients: [],
    ...over,
  };
}

const names = (keyId: string) =>
  ({ [ALICE]: "Alice", [BOB]: "Bob" })[keyId] ?? keyId.slice(-16);

describe("signatureNote", () => {
  it("says nothing extra for a plain current signature", () => {
    expect(signatureNote(sig(), names)).toBeNull();
  });

  it("says when the signature claims it was made", () => {
    const note = signatureNote(sig({ signedAt: Date.UTC(2026, 2, 12) }), names);
    expect(note).toMatch(/^Signed /);
    expect(note).toMatch(/2026/);
  });

  it("says when the signing key has been retired since", () => {
    expect(signatureNote(sig({ signerKeyCurrent: false }), names)).toMatch(
      /since expired or been revoked/,
    );
  });

  it("names every other good signer and counts the unchecked ones", () => {
    const note = signatureNote(
      sig({ otherSignerKeyIds: [BOB], unverifiedSignatures: 2 }),
      names,
    );
    expect(note).toMatch(/also signed by Bob/);
    expect(note).toMatch(/2 more signatures from keys you don't have/);
  });
});

describe("signedForOthers", () => {
  it("is false when the signature names no recipients", () => {
    expect(signedForOthers(sig(), [ALICE])).toBe(false);
  });

  it("is false when one of the named recipients is the user", () => {
    expect(
      signedForOthers(sig({ intendedRecipients: [BOB, ALICE.toLowerCase()] }), [
        ALICE,
      ]),
    ).toBe(false);
  });

  it("is true for a message signed for someone else and passed on", () => {
    // Alice signed for Bob; Bob re-wrapped it under a password for us.
    expect(signedForOthers(sig({ intendedRecipients: [BOB] }), [ALICE])).toBe(
      true,
    );
  });

  it("says who it was for in the note", () => {
    expect(
      signatureNote(sig({ intendedRecipients: [BOB] }), names, true),
    ).toMatch(/signed for Bob, not for you/);
  });
});

describe("summariseBatch", () => {
  it("shows no card when nothing in the batch is signed", () => {
    expect(
      summariseBatch([
        {
          name: "a",
          result: sig({ signatureStatus: "unsigned", signerKeyId: null }),
        },
        {
          name: "b",
          result: sig({ signatureStatus: "unsigned", signerKeyId: null }),
        },
      ]),
    ).toEqual({ kind: "unsigned" });
  });

  it("gives the signer's card only when EVERY file is signed by the same key", () => {
    const summary = summariseBatch([
      { name: "a", result: sig() },
      { name: "b", result: sig() },
    ]);
    expect(summary).toMatchObject({
      kind: "same",
      result: { signerKeyId: ALICE },
    });
  });

  it("does not let one signed file vouch for an unsigned one beside it", () => {
    // The attack: a genuine signed file from Alice next to an unsigned
    // one the attacker wrote, decrypted together.
    const summary = summariseBatch([
      { name: "notes.gpg", result: sig() },
      {
        name: "invoice.gpg",
        result: sig({ signatureStatus: "unsigned", signerKeyId: null }),
      },
    ]);
    expect(summary.kind).toBe("mixed");
  });

  it("treats two different signers as mixed", () => {
    expect(
      summariseBatch([
        { name: "a", result: sig() },
        { name: "b", result: sig({ signerKeyId: BOB }) },
      ]).kind,
    ).toBe("mixed");
  });

  it("treats an unknown signer as mixed", () => {
    expect(
      summariseBatch([
        { name: "a", result: sig() },
        { name: "b", result: sig({ signatureStatus: "unknown_key" }) },
      ]).kind,
    ).toBe("mixed");
  });

  it("is amber if any file's key was retired, and drops a single date", () => {
    const summary = summariseBatch([
      { name: "a", result: sig({ signedAt: 1 }) },
      { name: "b", result: sig({ signedAt: 2, signerKeyCurrent: false }) },
    ]);
    expect(summary).toMatchObject({
      kind: "same",
      result: { signerKeyCurrent: false, signedAt: null },
    });
  });

  it("judges 'signed for someone else' per file, not over a merged list", () => {
    // File A was signed for {me, Bob}; file B for Bob alone. Merged, the
    // list contains me and B would read as addressed to me.
    const summary = summariseBatch(
      [
        {
          name: "group.gpg",
          result: sig({ intendedRecipients: [ALICE, BOB] }),
        },
        { name: "private.gpg", result: sig({ intendedRecipients: [BOB] }) },
      ],
      [ALICE],
    );
    expect(summary.kind).toBe("same");
    if (summary.kind === "same") {
      expect(signedForOthers(summary.result, [ALICE])).toBe(true);
    }
  });

  it("keeps co-signers from every file", () => {
    const summary = summariseBatch([
      { name: "a", result: sig({ otherSignerKeyIds: [BOB] }) },
      { name: "b", result: sig({ unverifiedSignatures: 1 }) },
    ]);
    expect(summary).toMatchObject({
      kind: "same",
      result: { otherSignerKeyIds: [BOB], unverifiedSignatures: 1 },
    });
  });
});

describe("mixedBatchNote", () => {
  it("says, file by file, who signed what", () => {
    expect(
      mixedBatchNote(
        [
          { name: "notes.gpg", result: sig() },
          {
            name: "invoice.gpg",
            result: sig({ signatureStatus: "unsigned", signerKeyId: null }),
          },
          { name: "x.gpg", result: sig({ signatureStatus: "unknown_key" }) },
        ],
        names,
      ),
    ).toBe(
      [
        "“notes.gpg”: Alice",
        "“invoice.gpg”: not signed",
        "“x.gpg”: Unknown signer",
      ].join("\n"),
    );
  });

  it("keeps a file name from posing as another file's verdict", () => {
    // Named to read as "payroll.asc: Rachel" followed by another entry.
    const note = mixedBatchNote(
      [
        {
          name: "payroll.asc: Alice · notes.asc",
          result: sig({ signatureStatus: "unknown_key" }),
        },
        { name: "b.asc", result: sig() },
      ],
      names,
    );
    const [first] = note.split("\n");
    // One quoted name, then the real outcome, on its own line.
    expect(first).toBe("“payroll.asc: Alice · notes.asc”: Unknown signer");
  });

  it("strips bidi and invisible characters from file names", () => {
    const note = mixedBatchNote(
      [
        {
          name: "inv\u202ecsa.exe",
          result: sig({ signatureStatus: "unsigned", signerKeyId: null }),
        },
      ],
      names,
    );
    expect(note).toBe("“invcsa.exe”: not signed");
  });
});

describe("notAddressed - a decrypted signature that names no one", () => {
  const decrypted = { decrypted: true, notEncrypted: false };

  it("is noted when it came out of an encrypted message", () => {
    // Alice's public signed post, encrypted to us by someone else.
    expect(notAddressed(sig(), decrypted)).toBe(true);
  });

  it("is not noted when the signature names its recipients", () => {
    // Naming us is fine; naming only others is `signedForOthers`.
    expect(notAddressed(sig({ intendedRecipients: [ALICE] }), decrypted)).toBe(
      false,
    );
    expect(notAddressed(sig({ intendedRecipients: [BOB] }), decrypted)).toBe(
      false,
    );
  });

  it("is not noted on Verify, nor on a message that was never encrypted", () => {
    // Verify claims nothing about a recipient; an unencrypted message
    // already says "Not encrypted", which covers it.
    expect(notAddressed(sig(), { decrypted: false, notEncrypted: false })).toBe(
      false,
    );
    expect(notAddressed(sig(), { decrypted: true, notEncrypted: true })).toBe(
      false,
    );
  });
});
