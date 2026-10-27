/**
 * The picker's engine gate.
 *
 * Two properties matter here and neither is enforced by the compiler:
 *
 *  1. A stored record with NO `kind` is a PGP record -- every contact
 *     saved before the age engine existed has none, and reading the
 *     field directly would quietly place them all in a third, blocked
 *     category.
 *  2. Render order and pick order are different lists. The digit
 *     shortcuts and the Enter fallback index into the pickable list, so
 *     a dimmed row can never swallow a keystroke.
 */

import { describe, expect, it } from "vitest";

import type { KindDiscriminated } from "../../lib/storage/key-kind";
import {
  mixedEngineReason,
  noActiveKeyReason,
  sshPasswordReason,
} from "../../lib/encrypt-recipients";
import {
  blockedByEngine,
  pickableKeys,
  recipientBlockReason,
  selectionEngine,
  splitRecipientSections,
} from "./recipient-engine";

/** Stand-ins for stored records: only the discriminant matters here. */
type Rec = KindDiscriminated & { keyId: string };

const pgp: Rec = { keyId: "PGP-1", kind: "pgp" };
// Written before `kind` existed -- the migration case the whole design
// rests on.
const legacy: Rec = { keyId: "LEGACY" };
const ssh: Rec = { keyId: "SHA256:abc", kind: "ssh" };

describe("selectionEngine", () => {
  it("is null while nothing is selected -- neither engine is committed", () => {
    expect(selectionEngine([])).toBeNull();
  });

  it("reads an absent kind as pgp", () => {
    expect(selectionEngine([legacy])).toBe("pgp");
  });

  it("reports ssh for an SSH selection", () => {
    expect(selectionEngine([ssh])).toBe("ssh");
  });
});

describe("blockedByEngine", () => {
  it("blocks nothing while no engine is committed", () => {
    expect(blockedByEngine(ssh, null)).toBe(false);
    expect(blockedByEngine(pgp, null)).toBe(false);
  });

  it("blocks the other engine's keys once one is committed", () => {
    expect(blockedByEngine(ssh, "pgp")).toBe(true);
    expect(blockedByEngine(pgp, "ssh")).toBe(true);
  });

  it("never blocks a legacy (kind-less) key from a PGP message", () => {
    expect(blockedByEngine(legacy, "pgp")).toBe(false);
  });
});

describe("pickableKeys", () => {
  it("is the whole list while no engine is committed", () => {
    expect(pickableKeys([pgp, ssh], null)).toEqual([pgp, ssh]);
  });

  it("drops blocked rows, so digit N is the Nth row that actually works", () => {
    const visible = [pgp, ssh, legacy];
    const pickable = pickableKeys(visible, "pgp");
    // The SSH row still RENDERS second (dimmed, with the reason); it is
    // simply not what digit 2 picks.
    expect(visible[1]).toBe(ssh);
    expect(pickable[1]).toBe(legacy);
  });

  it("can be empty, so Enter picks nothing rather than the wrong thing", () => {
    expect(pickableKeys([ssh], "pgp")).toEqual([]);
  });
});

describe("recipientBlockReason", () => {
  it("blocks nothing when no engine is committed and no password is set", () => {
    expect(recipientBlockReason(ssh, null, false)).toBeNull();
    expect(recipientBlockReason(pgp, null, false)).toBeNull();
    expect(recipientBlockReason(legacy, null, false)).toBeNull();
  });

  it("blocks SSH recipients once a message password is set", () => {
    // A password is an OpenPGP SKESK; age has no equivalent, so the two
    // choices name different formats. Without this the age path silently
    // drops the password and produces a file with no password on it.
    expect(recipientBlockReason(ssh, null, true)).toBe(sshPasswordReason());
    expect(recipientBlockReason(ssh, "ssh", true)).toBe(sshPasswordReason());
  });

  it("leaves PGP recipients alone when a password is set", () => {
    // The password is ADDITIVE for OpenPGP: SKESK alongside the PKESKs,
    // either opens the message.
    expect(recipientBlockReason(pgp, null, true)).toBeNull();
    expect(recipientBlockReason(pgp, "pgp", true)).toBeNull();
    // ...including the records that predate the `kind` field.
    expect(recipientBlockReason(legacy, "pgp", true)).toBeNull();
  });

  it("prefers the password reason over the mixed-engine one", () => {
    // With a password set AND a PGP recipient already chosen, an SSH key
    // is out for both reasons. "You can't mix engines" is the less
    // useful of two true statements: the fix is to drop the password,
    // not to pick differently.
    expect(recipientBlockReason(ssh, "pgp", true)).toBe(sshPasswordReason());
  });

  it("still reports a genuine engine mix", () => {
    expect(recipientBlockReason(ssh, "pgp", false)).toBe(mixedEngineReason());
    expect(recipientBlockReason(pgp, "ssh", false)).toBe(mixedEngineReason());
  });

  it("blocks a contact with every key turned off, and says why", () => {
    // A refresh can leave a contact holding only keys the user turned
    // off; it has nothing to encrypt to, whatever else is selected.
    const key = (keyId: string, disabled: boolean) => ({
      keyId,
      armored: `ssh-ed25519 ${keyId}`,
      algorithm: "ssh-ed25519",
      ...(disabled ? { disabled: true as const } : {}),
    });
    const contact = (offs: boolean[]) => ({
      kind: "ssh" as const,
      keyId: "SHA256:k0",
      armoredPublicKey: "ssh-ed25519 SHA256:k0",
      recipients: offs.map((off, i) => key(`SHA256:k${i}`, off)),
    });
    expect(recipientBlockReason(contact([true]), null, false)).toBe(
      noActiveKeyReason(),
    );
    expect(recipientBlockReason(contact([true, true]), "ssh", false)).toBe(
      noActiveKeyReason(),
    );
    expect(
      recipientBlockReason(contact([true, false]), null, false),
    ).toBeNull();
  });
});

describe("pickableKeys with a password set", () => {
  it("makes SSH rows invisible to the digit shortcuts", () => {
    // Render order and pick order are different lists (see the header):
    // a dimmed row that stayed pickable would swallow a keystroke, and
    // here it would swallow it into an encrypt that cannot happen.
    expect(pickableKeys([ssh, pgp, legacy], null, true)).toEqual([pgp, legacy]);
  });

  it("is unchanged when no password is set", () => {
    expect(pickableKeys([ssh, pgp], null, false)).toEqual([ssh, pgp]);
  });
});

describe("splitRecipientSections: each key is offered once", () => {
  interface Contact {
    keyId: string;
    keys: string[];
  }
  interface Own {
    keyId: string;
    own: true;
  }
  const contact = (keyId: string, keys = [keyId]): Contact => ({ keyId, keys });
  const own = (keyId: string): Own => ({ keyId, own: true });
  const split = (contacts: Contact[], mine: Own[], allMine = mine) =>
    splitRecipientSections<Contact, Own>(
      [...contacts, ...mine],
      contacts,
      new Set(allMine.map((k) => k.keyId)),
    );

  it("offers an own PGP key imported again as a contact once, as yours", () => {
    // The same fingerprint as a contact record and as an own key. The id
    // means your key (see `resolveSelectedRecipients`), so the contact
    // copy is the row left out.
    const me = contact("PGP-ME");
    const mine = own("PGP-ME");
    const result = split([me], [mine]);
    expect(result.contacts).toEqual([]);
    expect(result.own).toEqual([mine]);
  });

  it("never hides your own key because a contact holds it", () => {
    // A GitHub copy of your own account -- or a pasted file pairing your
    // key with an attacker's under one comment. "You" stays on the list
    // either way, and the contact is offered as itself.
    const github = contact("SSH-LAPTOP", ["SSH-LAPTOP", "SSH-ME", "SSH-WORK"]);
    const mine = own("SSH-ME");
    expect(split([github], [mine])).toEqual({
      contacts: [github],
      own: [mine],
    });
  });

  it("leaves out a contact whose id is one of your keys", () => {
    // Attack (c): the group's id equalled the user's own key, hid "You",
    // and won the id lookup -- encrypting to every key in it.
    const takeover = contact("SSH-ME", ["SSH-ME", "SSH-MALLORY"]);
    const mine = own("SSH-ME");
    expect(split([takeover], [mine])).toEqual({ contacts: [], own: [mine] });
  });

  it("leaves it out even when the search filtered your key out", () => {
    // The id still resolves to your key, whatever matched the search.
    const takeover = contact("SSH-ME", ["SSH-ME", "SSH-MALLORY"]);
    expect(split([takeover], [], [own("SSH-ME")]).contacts).toEqual([]);
  });

  it("never hides a single-key contact behind a bigger one holding its key", () => {
    // Attack (b): a file pairing Mallory's key (first) with Alice's under
    // `alice@laptop` became a second contact holding Alice's key, and the
    // real Alice was hidden behind it. Both are offered.
    const group = contact("SSH-MALLORY", ["SSH-MALLORY", "SSH-ALICE"]);
    const alice = contact("SSH-ALICE");
    expect(split([group, alice], []).contacts).toEqual([group, alice]);
  });

  it("leaves unrelated keys alone", () => {
    const alice = contact("PGP-ALICE");
    const bob = contact("SSH-BOB");
    const mine = own("PGP-ME");
    expect(split([alice, bob], [mine])).toEqual({
      contacts: [alice, bob],
      own: [mine],
    });
  });
});
