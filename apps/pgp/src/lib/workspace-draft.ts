/**
 * Workspace draft survives auto-lock, encrypted under an in-WASM draft key
 * separate from the master session. Files, transient flags and the
 * password input are deliberately NOT preserved.
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
 * Pull, not push, so the App never holds a live plaintext copy: it pulls
 * once inside `doMasterLock`, encrypts, then calls `wipe()`. Unmount alone
 * doesn't free the string (`fiber.alternate` closures keep it reachable);
 * emptying the shared ref slot does.
 */
export interface WorkspaceDraftSource {
  /** `null` when nothing is safe to persist (e.g. private-key material). */
  getDraft: () => WorkspaceDraft | null;
  wipe: () => void;
}

export function draftHasContent(d: WorkspaceDraft | null): boolean {
  if (!d) return false;
  return d.input.length > 0 || d.output.length > 0;
}

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
