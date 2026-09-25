import type { PublicContactKey } from "./storage/contacts";

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

/** Who the message is from, as the panel verified it: the contact
 *  record the panel's own signer card renders, for the same card in the
 *  tab. Display only; the public key itself is left out. */
export type ReaderSigner = PublicContactKey;

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
  const s = m.signer as Record<string, unknown> | null | undefined;
  return (
    typeof s === "object" &&
    s !== null &&
    typeof s.keyId === "string" &&
    Array.isArray(s.userIds) &&
    s.userIds.every((u) => typeof u === "string")
  );
}
