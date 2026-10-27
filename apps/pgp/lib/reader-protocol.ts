import type { SignerCardState } from "../components/workspace/signer-card";

/**
 * The side panel <-> reader tab protocol.
 *
 * Reply opens the decrypted message in a browser tab so it stays
 * readable while the reply is written in the panel. The tab is a DUMB
 * VIEW: no vault, no keys, no wasm, no storage. It connects a runtime
 * port named for its nonce and shows whatever the panel sends. The panel
 * owns the message (sealed under its in-memory draft key between
 * showings, see `hooks/useReaderTabs.ts`) and decides when the tab may
 * hold plaintext: only while the panel is unlocked.
 *
 * Nothing here ever touches storage, so nothing about the message -- not
 * even who sent it -- persists anywhere; the URL carries only the nonce.
 */

/** Port name prefix; the rest is the reader's nonce. */
export const READER_PORT_PREFIX = "pgp-reader:";

/** 32 lowercase hex chars (128 bits). */
const NONCE = /^[0-9a-f]{32}$/;

export function isReaderNonce(v: string): boolean {
  return NONCE.test(v);
}

export function newReaderNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Who the message is from, as the panel verified it: the panel's own
 *  signer card state (tone, label, note, clash and the contact's pills),
 *  for the same card in the tab. A bare contact used to travel here, and
 *  the tab lost every warning the panel's card carried. Display only;
 *  the public key is left out (`displayOnlySignerCard`). */
export type ReaderSigner = SignerCardState;

/** Panel -> tab. */
export type ReaderMessage =
  /** Show this message. Sent on connect and again after every unlock. */
  | { type: "show"; signer: ReaderSigner; text: string }
  /** The panel locked: drop the text and say so. */
  | { type: "locked" };

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

/** A key id and its User IDs: the part of a contact every card reads. */
function isHolder(v: unknown): boolean {
  if (typeof v !== "object" || v === null) return false;
  const h = v as Record<string, unknown>;
  return (
    typeof h.keyId === "string" &&
    Array.isArray(h.userIds) &&
    h.userIds.every((u) => typeof u === "string")
  );
}
