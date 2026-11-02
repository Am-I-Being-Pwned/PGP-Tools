/**
 * Pending context-menu op: guard, TTL and sweep, shared by the worker
 * (writer) and usePendingOperation (reader).
 *
 * SECURITY: the value is the user's raw, UNSEALED selection (the worker
 * has no wasm/draft key, see `T-GITHUB-CSP-SCOPE`), so its lifetime IS its
 * exposure. The panel removes it on read; `sweepStalePendingOp` bounds the
 * case where the panel never opens.
 */

import type { OperationAction, PendingOperation } from "./messages";
import { SESSION_PENDING_OP } from "./constants";

const VALID_ACTIONS = new Set<OperationAction>([
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "import-public",
  "import-private",
]);

/** A stale selection must not surface when the panel opens much later. */
export const PENDING_OP_TTL_MS = 60_000;

export function isPendingOperation(msg: unknown): msg is PendingOperation {
  if (typeof msg !== "object" || msg === null) return false;
  const obj = msg as Record<string, unknown>;
  return (
    obj.type === "PENDING_OPERATION" &&
    typeof obj.id === "string" &&
    typeof obj.action === "string" &&
    VALID_ACTIONS.has(obj.action as OperationAction) &&
    typeof obj.text === "string" &&
    typeof obj.sourceTabId === "number" &&
    (obj.windowId === undefined || typeof obj.windowId === "number") &&
    typeof obj.createdAt === "number"
  );
}

/** Only the panel of the selection's own window may take the op. */
export function isPendingOpForWindow(
  op: PendingOperation,
  here: number | undefined,
): boolean {
  return op.windowId === undefined || op.windowId === here;
}

export function isPendingOpFresh(
  op: PendingOperation,
  now = Date.now(),
): boolean {
  return now - op.createdAt < PENDING_OP_TTL_MS;
}

/**
 * Evict a stale or malformed pending op; run on every worker start so an
 * unconsumed selection can't sit in session storage until browser exit.
 * Fresh ops are left alone (the panel may be on its way up).
 *
 * The id re-read matters: a cold start is usually caused by the
 * context-menu click itself, so a new op can land between read and remove.
 */
export async function sweepStalePendingOp(now = Date.now()): Promise<void> {
  const stored: unknown = (
    await chrome.storage.session.get(SESSION_PENDING_OP)
  )[SESSION_PENDING_OP];
  if (stored === undefined) return;
  if (isPendingOperation(stored) && isPendingOpFresh(stored, now)) return;

  const id = isPendingOperation(stored) ? stored.id : undefined;
  const current: unknown = (
    await chrome.storage.session.get(SESSION_PENDING_OP)
  )[SESSION_PENDING_OP];
  const currentId = isPendingOperation(current) ? current.id : undefined;
  if (currentId !== id) return;

  await chrome.storage.session.remove(SESSION_PENDING_OP);
}
