import type { SignerCardState } from "../components/workspace/signer-card";

/**
 * Side panel <-> reader tab protocol. The tab is a DUMB VIEW (no vault,
 * keys, wasm or storage); the panel owns the message and lets the tab hold
 * plaintext only while unlocked. Nothing persists; the URL carries only
 * the nonce.
 */

export const READER_PORT_PREFIX = "pgp-reader:";

/** 128 bits. */
const NONCE = /^[0-9a-f]{32}$/;

export function isReaderNonce(v: string): boolean {
  return NONCE.test(v);
}

export function newReaderNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The panel's full signer card state, so the tab keeps every warning.
 *  Display only; no public key (`displayOnlySignerCard`). */
export type ReaderSigner = SignerCardState;

/** Panel -> tab. `show` is resent after every unlock. */
export type ReaderMessage =
  { type: "show"; signer: ReaderSigner; text: string } | { type: "locked" };

export function isReaderMessage(v: unknown): v is ReaderMessage {
  if (typeof v !== "object" || v === null) return false;
  const m = v as Record<string, unknown>;
  if (m.type === "locked") return true;
  if (m.type !== "show" || typeof m.text !== "string") return false;
  const card = m.signer as Record<string, unknown> | null | undefined;
  if (typeof card !== "object" || card === null) return false;
  if (card.tone !== "success" && card.tone !== "warning") return false;
  if (typeof card.label !== "string") return false;
  if (card.note !== undefined && typeof card.note !== "string") return false;
  if (typeof card.unverified !== "boolean") return false;
  if (!isHolder(card.contact)) return false;
  if (card.clash === undefined) return true;
  const clash = card.clash as Record<string, unknown> | null;
  return (
    typeof clash === "object" &&
    clash !== null &&
    typeof clash.kind === "string" &&
    Array.isArray(clash.holders) &&
    clash.holders.every(isHolder)
  );
}

function isHolder(v: unknown): boolean {
  if (typeof v !== "object" || v === null) return false;
  const h = v as Record<string, unknown>;
  return (
    typeof h.keyId === "string" &&
    Array.isArray(h.userIds) &&
    h.userIds.every((u) => typeof u === "string")
  );
}
