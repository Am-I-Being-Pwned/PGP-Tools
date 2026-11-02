import type { MasterProtection } from "./storage/master-protection";
import type { StorageLocation } from "./storage/preferences";
import type { VaultState } from "./storage/vault-state";

export type VaultProblem = Extract<
  VaultState,
  { kind: "elsewhere" | "ambiguous" | "orphaned" }
>;

/** One value, so impossible combinations can't be represented. */
export type VaultPhase =
  /** Render nothing until storage is read. */
  | { kind: "loading" }
  | { kind: "onboarding" }
  /** A vault exists but not where the bootstrap points, or has lost its
   *  master protection. Never onboarding. */
  | { kind: "problem"; problem: VaultProblem }
  | {
      kind: "locked";
      protection: MasterProtection;
      /** System lock: the unlock screen must not auto-prompt a passkey. */
      autoLocked: boolean;
    }
  | {
      kind: "open";
      protection: MasterProtection | null;
      /** Stores or master-sealed keys still opening; auto-run waits. */
      opening: boolean;
    };

export interface VaultLifecycle {
  phase: VaultPhase;
  /** Bumped on every unlock/lock so a late unlock can't settle a newer one. */
  generation: number;
  /** The other storage area also holds a master protection. */
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

export function protectionOf(phase: VaultPhase): MasterProtection | null {
  return phase.kind === "open" || phase.kind === "locked"
    ? phase.protection
    : null;
}
