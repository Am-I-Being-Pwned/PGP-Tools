import type { MasterProtection } from "./storage/master-protection";
import type { StorageLocation } from "./storage/preferences";
import type { VaultState } from "./storage/vault-state";

export type VaultProblem = Extract<
  VaultState,
  { kind: "elsewhere" | "ambiguous" | "orphaned" }
>;

/** Which screen the panel is on, as one value -- so "unlocked but not
 *  loaded" and its like cannot be represented. */
export type VaultPhase =
  /** Still reading what is stored; render nothing, so a tree that would
   *  be torn down by the lock screen never mounts. */
  | { kind: "loading" }
  | { kind: "onboarding" }
  /** A vault exists but not where the bootstrap points, or has lost its
   *  master protection. Never onboarding. */
  | { kind: "problem"; problem: VaultProblem }
  | {
      kind: "locked";
      protection: MasterProtection;
      /** Locked by the system (idle, tab-away, OS lock), not the user:
       *  the unlock screen must not pop a passkey prompt on its own. */
      autoLocked: boolean;
    }
  | {
      kind: "open";
      protection: MasterProtection | null;
      /** The stores the unlock opened are still being read, or keys
       *  sealed under the master are still opening: auto-run waits. */
      opening: boolean;
    };

export interface VaultLifecycle {
  phase: VaultPhase;
  /** Bumped by every unlock and lock, so an unlock that finishes after
   *  the vault was locked (and maybe reopened) cannot settle the newer one. */
  generation: number;
  /** The other storage area also holds a master protection; the lock
   *  screen offers it. */
  alternate: StorageLocation | null;
}

export type VaultEvent =
  | { type: "resolved"; vault: VaultState }
  | { type: "onboarded"; protection: MasterProtection | null }
  | { type: "unlocking" }
  | { type: "settled"; generation: number }
  | { type: "locked"; auto: boolean };

export const initialVaultLifecycle: VaultLifecycle = {
  phase: { kind: "loading" },
  generation: 0,
  alternate: null,
};

export function vaultReducer(
  state: VaultLifecycle,
  event: VaultEvent,
): VaultLifecycle {
  const { phase, generation } = state;
  switch (event.type) {
    case "resolved": {
      const { vault } = event;
      if (vault.kind !== "ready") {
        return {
          ...state,
          alternate: null,
          phase:
            vault.kind === "none"
              ? { kind: "onboarding" }
              : { kind: "problem", problem: vault },
        };
      }
      return {
        ...state,
        alternate: vault.alternate ?? null,
        phase: {
          kind: "locked",
          protection: vault.protection,
          autoLocked: false,
        },
      };
    }
    case "onboarded":
      return {
        ...state,
        phase: { kind: "open", protection: event.protection, opening: false },
        generation: generation + 1,
      };
    case "unlocking":
      if (phase.kind !== "locked") return state;
      return {
        ...state,
        phase: { kind: "open", protection: phase.protection, opening: true },
        generation: generation + 1,
      };
    case "settled":
      if (phase.kind !== "open" || event.generation !== generation) {
        return state;
      }
      return { ...state, phase: { ...phase, opening: false } };
    case "locked":
      if (phase.kind !== "open") return state;
      return {
        ...state,
        // A vault with no master protection has no lock screen to go to.
        phase: phase.protection
          ? {
              kind: "locked",
              protection: phase.protection,
              autoLocked: event.auto,
            }
          : { ...phase, opening: false },
        generation: generation + 1,
      };
  }
}

/** The protection of a vault that is set up, whether open or locked. */
export function protectionOf(phase: VaultPhase): MasterProtection | null {
  return phase.kind === "open" || phase.kind === "locked"
    ? phase.protection
    : null;
}
