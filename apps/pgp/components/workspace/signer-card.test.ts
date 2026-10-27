import { describe, expect, it } from "vitest";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { isReaderMessage } from "../../lib/reader-protocol";
import { displayOnlySignerCard, signerCardState } from "./signer-card";

// Reply's reader tab used to get a bare contact and render a fixed
// "Signature verified": every warning the panel's card carried (the
// clash pill, "not marked verified by you", "may have been forwarded",
// a lookalike / SHA-1 warning) was lost. It now gets the panel's own card
// state, cut down to what the card displays.

const contact = (over: Partial<PublicContactKey>): PublicContactKey => ({
  keyId: "A".repeat(40),
  userIds: ["Alice <alice@example.com>"],
  algorithm: "ed25519",
  armoredPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSECRET-ARMOR",
  addedAt: 1,
  lastUsedAt: 2,
  ...over,
});

describe("signerCardState", () => {
  const alice = contact({
    securityWarning: "mixes alphabets",
    lookalike: true,
  });
  const impostor = contact({
    keyId: "B".repeat(40),
    armoredPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nIMPOSTOR-ARMOR",
  });

  it("carries the note, the clash and the contact's warnings", () => {
    const state = signerCardState({
      signer: alice,
      tone: "success",
      note: "Signed 1 Jan 2026 · key not marked verified by you",
      statusText: "Signature verified",
      contacts: [alice, impostor],
      myKeys: [],
    });
    expect(state.label).toBe("Signature verified");
    expect(state.note).toContain("key not marked verified by you");
    expect(state.clash?.kind).toBe("address");
    expect(state.contact.securityWarning).toBe("mixes alphabets");
    expect(state.unverified).toBe(false);
  });

  it("labels a caveat, and an unknown signer, the way the panel does", () => {
    expect(
      signerCardState({
        signer: alice,
        tone: "warning",
        caveat: "Signed for someone else",
        contacts: [],
        myKeys: [],
      }).label,
    ).toBe("Signed for someone else");
    const unknown = signerCardState({
      signer: alice,
      tone: "warning",
      statusText: "the signer's key is not in your contacts",
      contacts: [alice, impostor],
      myKeys: [],
    });
    expect(unknown.unverified).toBe(true);
    expect(unknown.note).toBe("the signer's key is not in your contacts");
    expect(unknown.clash).toBeUndefined();
  });
});

describe("displayOnlySignerCard", () => {
  it("drops every public key, its own and each clash holder's", () => {
    const alice = contact({
      verified: true,
      verifiedAt: 5,
      recipients: [
        { keyId: "A".repeat(40), armored: "SECRET-ARMOR" },
      ] as PublicContactKey["recipients"],
    });
    const impostor = contact({
      keyId: "B".repeat(40),
      armoredPublicKey: "IMPOSTOR-ARMOR",
    });
    const shown = displayOnlySignerCard(
      signerCardState({
        signer: alice,
        tone: "success",
        note: "n",
        contacts: [alice, impostor],
        myKeys: [],
      }),
    );
    const wire = JSON.stringify(shown);
    expect(wire).not.toContain("SECRET-ARMOR");
    expect(wire).not.toContain("IMPOSTOR-ARMOR");
    expect(shown.contact.verified).toBe(true);
    expect(shown.clash?.holders).toEqual([
      { keyId: impostor.keyId, userIds: impostor.userIds },
    ]);
    // ...and it is what the reader accepts.
    expect(isReaderMessage({ type: "show", signer: shown, text: "x" })).toBe(
      true,
    );
  });
});
