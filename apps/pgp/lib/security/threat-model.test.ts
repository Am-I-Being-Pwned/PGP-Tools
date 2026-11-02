/**
 * Keeps the attack model's claims honest: `defended` must name an existing
 * test, `accepted`/`partial` must say why, `pending` is surfaced.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { THREAT_MODEL, type Threat } from "./threat-model";

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

  // Each `pending` is its own case so it stays visible. No console.* here:
  // SECURITY.md s.9 check 5 forbids it across apps/pgp (build gate).
  it.each(
    THREAT_MODEL.filter((t) => t.status === "pending").map(
      (t) => [t.id, t] as const,
    ),
  )("%s is pending a proven defence", (_id, threat) => {
    expect((threat.rationale ?? "").trim()).not.toBe("");
  });
});
