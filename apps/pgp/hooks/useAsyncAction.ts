import { useState } from "react";

import type { PresentedError } from "../lib/errors/present";
import { presentError } from "../lib/errors/present";
import { errorMessage } from "../lib/utils/errors";

/** Caught value -> what the UI shows. `null` means "not an error" (a
 *  dismissed passkey prompt, say): nothing is shown. */
export type ErrorMapper = (e: unknown) => PresentedError | null;

/** A fallback string maps through `presentError`: curated copy, raw text
 *  only ever in `detail`. */
export type ErrorPolicy = string | ErrorMapper;

export function toErrorMapper(policy: ErrorPolicy): ErrorMapper {
  return typeof policy === "string" ? (e) => presentError(e, policy) : policy;
}

/** For flows whose engine text IS the user-facing message (an import's
 *  "Incorrect passphrase", an offline-primary key's explanation). */
export function engineMessage(fallback: string): ErrorMapper {
  return (e) => ({ message: errorMessage(e, fallback) });
}

type Task = () => Promise<void> | void;

export interface ActionRunner {
  /** Runs `task` unless one is already in flight. Resolves to the mapped
   *  error, or null on success / when refused / when the mapper says so. */
  run: (task: Task, mapError: ErrorMapper) => Promise<PresentedError | null>;
  readonly inFlight: boolean;
}

/** Framework-free core of {@link useAsyncAction}. The in-flight guard is
 *  synchronous: two clicks in one frame both see React's `busy` false. */
export function createActionRunner(set: {
  busy: (busy: boolean) => void;
  error: (error: PresentedError | null) => void;
}): ActionRunner {
  let inFlight = false;
  return {
    get inFlight() {
      return inFlight;
    },
    async run(task, mapError) {
      if (inFlight) return null;
      inFlight = true;
      set.error(null);
      set.busy(true);
      try {
        await task();
        return null;
      } catch (e) {
        const mapped = mapError(e);
        set.error(mapped);
        return mapped;
      } finally {
        inFlight = false;
        set.busy(false);
      }
    },
  };
}

export interface AsyncAction {
  run: (task: Task) => Promise<PresentedError | null>;
  readonly inFlight: boolean;
  busy: boolean;
  error: PresentedError | null;
  /** For validation failures found before (or inside) a run. */
  setError: (error: string | PresentedError | null) => void;
  reset: () => void;
}

/**
 * Busy flag, re-entrancy guard and error slot for one async action:
 * `const save = useAsyncAction(t("x_failed")); save.run(async () => ...)`.
 * Every caught error goes through one mapper (default `presentError`).
 */
export function useAsyncAction(policy: ErrorPolicy): AsyncAction {
  const [busy, setBusy] = useState(false);
  const [error, setErrorState] = useState<PresentedError | null>(null);
  const [runner] = useState(() =>
    createActionRunner({ busy: setBusy, error: setErrorState }),
  );
  return {
    run: (task) => runner.run(task, toErrorMapper(policy)),
    get inFlight() {
      return runner.inFlight;
    },
    busy,
    error,
    setError: (e) => setErrorState(typeof e === "string" ? { message: e } : e),
    reset: () => setErrorState(null),
  };
}
