/**
 * Coverage assertions over the attack model itself.
 *
 * These tests don't exercise crypto -- they assert that our *claims* about
 * the crypto stay honest:
 *
 *   - a threat marked `defended` must name a test that would fail if the
 *     defence regressed, and that file must actually exist;
 *   - a threat marked `accepted` or `partial` must state why;
 *   - `pending` threats are legal but surfaced, so a TODO can't hide.
 *
 * This is the tripwire for the failure mode that produced the drift it was
 * written in response to: a README claiming exponential backoff that no
 * code implemented, and a whole encrypted-history surface that never
 * reached SECURITY.md.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import type { Threat } from "./threat-model";
import { THREAT_MODEL } from "./threat-model";

/** apps/pgp/lib/security -> repo root */
const REPO_ROOT = resolve(import.meta.dirname, "../../../..");

const needsEvidence = (t: Threat) =>
  t.status === "defended" || t.status === "partial";
const needsRationale = (t: Threat) =>
  t.status === "accepted" || t.status === "partial" || t.status === "pending";

describe("threat model integrity", () => {
  it("is not empty", () => {
    expect(THREAT_MODEL.length).toBeGreaterThan(0);
  });

  it("has unique, stable-looking ids", () => {
    const ids = THREAT_MODEL.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^T-[A-Z0-9-]+$/);
  });

  it.each(THREAT_MODEL.map((t) => [t.id, t] as const))(
    "%s describes an attacker, a defence, and a doc section",
    (_id, threat) => {
      expect(threat.title.trim()).not.toBe("");
      expect(threat.attacker.trim()).not.toBe("");
      expect(threat.defence.trim()).not.toBe("");
      expect(threat.section.trim()).not.toBe("");
    },
  );
});

describe("defended threats name live evidence", () => {
  const withEvidence = THREAT_MODEL.filter(needsEvidence);

  it.each(withEvidence.map((t) => [t.id, t] as const))(
    "%s names at least one test or audit script",
    (_id, threat) => {
      // A defence nobody tests is a defence nobody knows still works.
      expect(threat.verifiedBy ?? []).not.toHaveLength(0);
    },
  );

  it.each(
    withEvidence.flatMap((t) =>
      (t.verifiedBy ?? []).map((p) => [t.id, p] as const),
    ),
  )("%s evidence exists on disk: %s", (_id, evidencePath) => {
    // Catches a renamed or deleted spec silently orphaning a claim.
    expect(existsSync(resolve(REPO_ROOT, evidencePath))).toBe(true);
  });
});

describe("unproven threats are justified, not silent", () => {
  it.each(THREAT_MODEL.filter(needsRationale).map((t) => [t.id, t] as const))(
    "%s explains why it is not fully defended",
    (_id, threat) => {
      // An accepted risk without a stated reason is an unexamined one.
      expect((threat.rationale ?? "").trim().length).toBeGreaterThan(40);
    },
  );

  // `pending` is an honest state, not a failure -- but each one is named as
  // its own test case so it stays visible in the suite output instead of
  // quietly becoming permanent. (No console.* here: SECURITY.md §9 check 5
  // forbids it across apps/pgp, and that invariant is a build gate.)
  it.each(
    THREAT_MODEL.filter((t) => t.status === "pending").map(
      (t) => [t.id, t] as const,
    ),
  )("%s is pending a proven defence", (_id, threat) => {
    expect((threat.rationale ?? "").trim()).not.toBe("");
  });
});
