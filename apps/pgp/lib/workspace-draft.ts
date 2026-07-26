/**
 * Workspace draft persistence across auto-lock.
 *
 * Goal: when the extension auto-locks (idle / visibility / OS idle) the
 * user's in-progress workspace text shouldn't disappear. We serialise
 * the workspace's salient state, encrypt it under an in-WASM draft key
 * (separate from the master / contacts session, so it survives a master
 * lock), and stash the ciphertext at App-level. On unlock + remount,
 * the workspace decrypts and rehydrates.
 *
 * What is NOT preserved: `File` objects (can't be re-instantiated from
 * disk), transient flags (`loading`, `error`, `needsPassword`), or
 * the password input (intentional — re-prompt on unlock).
 */

import type { WorkspaceAction } from "./messages";
import { decryptDraft, encryptDraft } from "./pgp/wasm";

export interface WorkspaceDraft {
  mode: WorkspaceAction;
  input: string;
  output: string;
  selectedRecipientIds: string[];
  selectedKeyId: string | null;
}

/**
 * A pull-model handle the workspace registers with the App.
 *
 * Deliberately pull, not push: a push contract ("here is my latest
 * draft") means the App holds a live plaintext copy for the whole
 * session, and every copy is one more thing that has to be released at
 * lock time. Instead the App asks for the draft exactly once — inside
 * `doMasterLock`, while the workspace is still mounted — encrypts it,
 * and then calls `wipe()` so the workspace drops its own plaintext
 * (input ref, textarea DOM node, undo buffer) before it unmounts.
 *
 * `wipe()` matters because React keeps the previous fiber alive on
 * `fiber.alternate`, and effect closures hanging off it keep reaching
 * the hook state they captured long after unmount. Refs are a single
 * mutable slot shared by both copies, so emptying the slot is what
 * actually releases the string — the unmount alone does not.
 */
export interface WorkspaceDraftSource {
  /** Snapshot the salient workspace state. `null` when there is nothing
   *  safe to persist (e.g. armored private-key material is in the box). */
  getDraft: () => WorkspaceDraft | null;
  /** Drop every plaintext copy the workspace owns. */
  wipe: () => void;
}

/** True iff the draft has any user-typed content worth persisting. */
export function draftHasContent(d: WorkspaceDraft | null): boolean {
  if (!d) return false;
  return d.input.length > 0 || d.output.length > 0;
}

/**
 * Serialise → encrypt under the in-WASM draft key. Caller stashes the
 * returned bytes wherever they'll survive the React unmount (App-level
 * state). Plaintext encoding is zeroed in the `finally`.
 */
export async function encryptWorkspaceDraft(
  draft: WorkspaceDraft,
): Promise<Uint8Array> {
  const json = JSON.stringify(draft);
  const bytes = new TextEncoder().encode(json);
  try {
    return await encryptDraft(bytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * Decrypt previously-stashed ciphertext back into a `WorkspaceDraft`.
 * The decrypted plaintext buffer is zeroed after parsing.
 */
export async function decryptWorkspaceDraft(
  ciphertext: Uint8Array,
): Promise<WorkspaceDraft | null> {
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = await decryptDraft(ciphertext);
    const json = new TextDecoder().decode(plaintext);
    const parsed: unknown = JSON.parse(json);
    return isWorkspaceDraft(parsed) ? parsed : null;
  } catch {
    return null;
  } finally {
    plaintext?.fill(0);
  }
}

function isWorkspaceDraft(v: unknown): v is WorkspaceDraft {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    (o.mode === "encrypt" ||
      o.mode === "decrypt" ||
      o.mode === "sign" ||
      o.mode === "verify") &&
    typeof o.input === "string" &&
    typeof o.output === "string" &&
    Array.isArray(o.selectedRecipientIds) &&
    o.selectedRecipientIds.every((id) => typeof id === "string") &&
    (o.selectedKeyId === null || typeof o.selectedKeyId === "string")
  );
}
