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

import { decryptDraft, encryptDraft } from "./pgp/wasm";

export interface WorkspaceDraft {
  mode: "encrypt" | "decrypt" | "sign" | "verify";
  input: string;
  output: string;
  selectedRecipientId: string | null;
  selectedKeyId: string | null;
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
    (o.selectedRecipientId === null ||
      typeof o.selectedRecipientId === "string") &&
    (o.selectedKeyId === null || typeof o.selectedKeyId === "string")
  );
}
