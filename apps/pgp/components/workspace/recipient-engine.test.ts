/**
 * Not compiler-enforced: (1) a record with NO `kind` is PGP (pre-age
 * contacts); (2) render order and pick order differ, so a dimmed row never
 * swallows a digit shortcut or Enter.
 */

import { describe, expect, it } from "vitest";

import {
  mixedEngineReason,
  noActiveKeyReason,
  sshPasswordReason,
} from "~/lib/encrypt-recipients";
import type { KindDiscriminated } from "~/lib/storage/key-kind";
import {
  blockedByEngine,
  pickableKeys,
  recipientBlockReason,
  selectionEngine,
  splitRecipientSections,
} from "./recipient-engine";

type Rec = KindDiscriminated & { keyId: string };

const pgp: Rec = { keyId: "PGP-1", kind: "pgp" };
// Pre-`kind` record: the migration case.
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
    // The SSH row still renders second (dimmed); digit 2 doesn't pick it.
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
    // Age has no SKESK equivalent: it would silently drop the password.
    expect(recipientBlockReason(ssh, null, true)).toBe(sshPasswordReason());
    expect(recipientBlockReason(ssh, "ssh", true)).toBe(sshPasswordReason());
  });

  it("leaves PGP recipients alone when a password is set", () => {
    // ADDITIVE for OpenPGP: SKESK alongside the PKESKs.
    expect(recipientBlockReason(pgp, null, true)).toBeNull();
    expect(recipientBlockReason(pgp, "pgp", true)).toBeNull();
    expect(recipientBlockReason(legacy, "pgp", true)).toBeNull();
  });

  it("prefers the password reason over the mixed-engine one", () => {
    // Both are true; the fix is to drop the password, so say that.
    expect(recipientBlockReason(ssh, "pgp", true)).toBe(sshPasswordReason());
  });

  it("still reports a genuine engine mix", () => {
    expect(recipientBlockReason(ssh, "pgp", false)).toBe(mixedEngineReason());
    expect(recipientBlockReason(pgp, "ssh", false)).toBe(mixedEngineReason());
  });

  it("blocks a contact with every key turned off, and says why", () => {
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
    // The id means your key (see `resolveSelectedRecipients`).
    const me = contact("PGP-ME");
    const mine = own("PGP-ME");
    const result = split([me], [mine]);
    expect(result.contacts).toEqual([]);
    expect(result.own).toEqual([mine]);
  });

  it("never hides your own key because a contact holds it", () => {
    // e.g. your key paired with an attacker's under one comment.
    const github = contact("SSH-LAPTOP", ["SSH-LAPTOP", "SSH-ME", "SSH-WORK"]);
    const mine = own("SSH-ME");
    expect(split([github], [mine])).toEqual({
      contacts: [github],
      own: [mine],
    });
  });

  it("leaves out a contact whose id is one of your keys", () => {
    // Attack (c): the group's id equalled your key, hid "You", won the lookup.
    const takeover = contact("SSH-ME", ["SSH-ME", "SSH-MALLORY"]);
    const mine = own("SSH-ME");
    expect(split([takeover], [mine])).toEqual({ contacts: [], own: [mine] });
  });

  it("leaves it out even when the search filtered your key out", () => {
    const takeover = contact("SSH-ME", ["SSH-ME", "SSH-MALLORY"]);
    expect(split([takeover], [], [own("SSH-ME")]).contacts).toEqual([]);
  });

  it("never hides a single-key contact behind a bigger one holding its key", () => {
    // Attack (b): Mallory's key paired with Alice's hid the real Alice.
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
