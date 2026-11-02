import { describe, expect, it } from "vitest";

import type { MasterProtection } from "./storage/master-protection";
import {
  initialVaultLifecycle,
  vaultReducer,
  type VaultEvent,
  type VaultLifecycle,
} from "./vault-phase";

const protection = { method: "password" } as unknown as MasterProtection;

const run = (...events: VaultEvent[]): VaultLifecycle =>
  events.reduce(vaultReducer, initialVaultLifecycle);

const ready: VaultEvent = {
  type: "resolved",
  vault: { kind: "ready", protection, alternate: "sync" },
};

describe("vaultReducer", () => {
  it("starts loading", () => {
    expect(initialVaultLifecycle.phase.kind).toBe("loading");
  });

  it("routes what is stored to one screen", () => {
    expect(run({ type: "resolved", vault: { kind: "none" } }).phase).toEqual({
      kind: "onboarding",
    });
    expect(
      run({ type: "resolved", vault: { kind: "orphaned" } }).phase,
    ).toEqual({ kind: "problem", problem: { kind: "orphaned" } });
    const s = run(ready);
    expect(s.phase).toEqual({ kind: "locked", protection, autoLocked: false });
    expect(s.alternate).toBe("sync");
  });

  it("opens through 'opening' and settles only the current unlock", () => {
    const opening = run(ready, { type: "unlocking" });
    expect(opening.phase).toEqual({ kind: "open", protection, opening: true });

    const stale = vaultReducer(opening, {
      type: "settled",
      generation: opening.generation - 1,
    });
    expect(stale).toBe(opening);

    const settled = vaultReducer(opening, {
      type: "settled",
      generation: opening.generation,
    });
    expect(settled.phase).toEqual({ kind: "open", protection, opening: false });
  });

  // The race the generation exists for: unlock, lock, unlock again --
  // the first unlock finishing must not settle the second.
  it("a slow first unlock cannot settle a later one", () => {
    const first = run(ready, { type: "unlocking" });
    const second = run(
      ready,
      { type: "unlocking" },
      { type: "locked", auto: true },
      { type: "unlocking" },
    );
    const after = vaultReducer(second, {
      type: "settled",
      generation: first.generation,
    });
    expect(after.phase).toMatchObject({ kind: "open", opening: true });
  });

  it("locks to the lock screen, remembering who locked it and the alternate", () => {
    const s = run(ready, { type: "unlocking" }, { type: "locked", auto: true });
    expect(s.phase).toEqual({ kind: "locked", protection, autoLocked: true });
    expect(s.alternate).toBe("sync");
  });

  it("ignores a lock or unlock that does not apply", () => {
    const locked = run(ready);
    expect(vaultReducer(locked, { type: "locked", auto: false })).toBe(locked);
    const onboarding = run({ type: "resolved", vault: { kind: "none" } });
    expect(vaultReducer(onboarding, { type: "unlocking" })).toBe(onboarding);
  });

  it("onboarding lands open and settled", () => {
    const s = run(
      { type: "resolved", vault: { kind: "none" } },
      { type: "onboarded", protection },
    );
    expect(s.phase).toEqual({ kind: "open", protection, opening: false });
  });
});
