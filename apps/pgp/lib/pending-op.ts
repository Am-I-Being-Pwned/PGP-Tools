/**
 * The pending context-menu operation: shape guard, lifetime, and the
 * worker-side sweep.
 *
 * Shared by `entrypoints/background.ts` (writer) and
 * `hooks/usePendingOperation.ts` (reader) so the two sides cannot
 * disagree about what a valid op is or how long one lives. They used to
 * hold separate copies of the guard; only the reader had a TTL.
 *
 * SECURITY: the value under `SESSION_PENDING_OP` is the user's raw
 * selection -- the plaintext they are about to encrypt, or the
 * ciphertext they are about to decrypt. It is NOT sealed (the worker has
 * no wasm instance, so it has no draft key to seal with -- see
 * `T-GITHUB-CSP-SCOPE`), so its lifetime IS its exposure. The panel
 * removes it on read, but the panel is not guaranteed to open;
 * `sweepStalePendingOp` is what bounds the case where it never does.
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

/** Drop ops older than this. Catches the case where the user
 *  triggered the context menu, closed the side panel without
 *  unlocking, and only opens it much later for some unrelated
 *  reason -- we don't want the stale selection to surface. */
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
    typeof obj.createdAt === "number"
  );
}

export function isPendingOpFresh(
  op: PendingOperation,
  now = Date.now(),
): boolean {
  return now - op.createdAt < PENDING_OP_TTL_MS;
}

/**
 * Evict a pending op that nobody is going to consume.
 *
 * WHY THIS EXISTS. Removal used to depend entirely on the side panel
 * mounting: `usePendingOperation` deletes the entry on read. Every path
 * where the panel never mounts -- `chrome.sidePanel.open` rejecting
 * (its rejection is deliberately swallowed at the call site), the panel
 * being dismissed before the mount effect runs, a panel realm that
 * crashes -- left the selection sitting in `chrome.storage.session` for
 * the rest of the browser session. The TTL only stopped it being
 * APPLIED; it did nothing about it being STORED. Called on every service
 * worker start, so a stray op survives at most until the worker's next
 * wake after the TTL rather than until browser shutdown.
 *
 * Fresh ops are left alone: the panel may still be on its way up.
 *
 * The id re-read is not ceremony. This runs at worker startup, and a
 * cold start is usually caused by the context-menu click itself, so a
 * write can land between our read and our remove -- deleting it would
 * throw away the selection the user just made. Re-reading and comparing
 * ids means we only delete the entry we actually judged stale. The
 * remaining window (between the second read and the remove) is orders of
 * magnitude narrower and, if lost, costs one dropped selection rather
 * than a leak.
 */
export async function sweepStalePendingOp(now = Date.now()): Promise<void> {
  const stored: unknown = (
    await chrome.storage.session.get(SESSION_PENDING_OP)
  )[SESSION_PENDING_OP];
  if (stored === undefined) return;
  // Malformed values are swept too -- nothing will ever consume them,
  // and whatever is under that key is still user data.
  if (isPendingOperation(stored) && isPendingOpFresh(stored, now)) return;

  const id = isPendingOperation(stored) ? stored.id : undefined;
  const current: unknown = (
    await chrome.storage.session.get(SESSION_PENDING_OP)
  )[SESSION_PENDING_OP];
  const currentId = isPendingOperation(current) ? current.id : undefined;
  if (currentId !== id) return;

  await chrome.storage.session.remove(SESSION_PENDING_OP);
}
