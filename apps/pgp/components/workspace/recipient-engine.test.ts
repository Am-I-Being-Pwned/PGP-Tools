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
  blockedByEngine,
  pickableKeys,
  selectionEngine,
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
