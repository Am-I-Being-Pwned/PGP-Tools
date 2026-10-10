import type { PublicContactKey } from "../storage/contacts";
import { isReaderNonce } from "../reader-protocol";

/**
 * The inline reader frame's two channels (SECURITY.md §17).
 *
 * The frame is an extension page the content script embeds in Gmail
 * where an encrypted or signed block was rendered. Gmail can size and
 * position it, and that is all: a cross-origin frame's document is
 * opaque to the page around it. So the frame can hold plaintext where
 * the page itself never may.
 *
 * 1. FRAME <-> PARENT (`postMessage`). The content script hands the frame
 *    the armored block it found (ciphertext -- the page had it already)
 *    and the colours of the message it sits in; the frame reports its
 *    height and what it is showing, so the content script can size it
 *    and fold the raw armor away. Both sides check the other's identity
 *    (`event.source` is the one window they expect, `event.origin` the
 *    one origin) and the nonce the frame was created with. Gmail's own
 *    scripts can post the same shapes at the frame: that is the accepted
 *    "the page can put any ciphertext in front of the add-on" case (see
 *    T-GMAIL-PAGE-BOUNDARY), and nothing in this channel moves plaintext.
 *
 * 2. FRAME <-> PANEL (runtime port). The frame asks the side panel to
 *    read the block; the panel -- the only realm with keys -- decrypts
 *    or verifies it and posts the result back, or says why not. The
 *    panel accepts the port only from a frame page of this extension
 *    (`isGmailFramePort`). Plaintext travels panel -> frame over this
 *    port and nowhere else, as it does to Reply's reader tab.
 */

/** Port name prefix; the rest is the frame's nonce. */
export const GMAIL_FRAME_PORT_PREFIX = "pgp-gmail-frame:";
/** The frame page, relative to the extension root. */
export const GMAIL_FRAME_PAGE = "gmail-frame.html";

export const isGmailFrameNonce = isReaderNonce;

export type GmailFrameKind = "message" | "signed";

// ── frame <-> parent ──────────────────────────────────────────────────

/** Colours sampled from the Gmail message the frame sits in, so it can
 *  blend with whatever theme Gmail is wearing. CSS colour strings as
 *  `getComputedStyle` returned them. */
export interface GmailFrameTheme {
  color: string;
  background: string;
}

/** Content script -> frame. */
export interface GmailFrameParentMessage {
  type: "pgp-frame:armor";
  nonce: string;
  kind: GmailFrameKind;
  text: string;
  theme: GmailFrameTheme;
}

/** Frame -> content script. */
export type GmailFrameChildMessage =
  /** The frame's script is listening: send the armor. (The content
   *  script cannot post on the iframe's `load`: the page's React tree,
   *  and so its listener, mounts after that event has fired.) */
  | { type: "pgp-frame:ready"; nonce: string }
  /** Only while showing the message: its height. Nothing is reported
   *  in any other state, so the page cannot read key possession or
   *  lock state off the frame's size (see `pgp-frame:state`). */
  | { type: "pgp-frame:size"; nonce: string; height: number }
  /** Whether the frame is showing the message. ONE BIT, deliberately:
   *  the frame's finer states (locked / failed / no key) would tell the
   *  page which keys the user holds and when the vault is open. */
  | { type: "pgp-frame:state"; nonce: string; shown: boolean }
  /** The user toggled "Show original" in the frame: fold the raw armor
   *  under the frame, or bring it back. */
  | { type: "pgp-frame:fold"; nonce: string; fold: boolean }
  /** The user pressed Reply in the frame: open Gmail's own reply window
   *  for this message (it turns encryption on by itself). */
  | { type: "pgp-frame:reply"; nonce: string };

/** What the frame is showing (inside the frame only; the page learns
 *  `shown` or not). */
export type GmailFrameState =
  "waiting" | "shown" | "locked" | "failed" | "unavailable";

/** A colour and nothing else: hex, rgb()/rgba() or a named colour. No
 *  `url(`, no `/`: the value lands in the frame's CSS, and a function
 *  that can name a host would make the plaintext-holding page beacon. */
const CSS_COLOR = /^(#[0-9a-f]{3,8}|rgba?\([\d.,\s%]{1,40}\)|[a-z]{1,24})$/i;

function isTheme(v: unknown): v is GmailFrameTheme {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.color === "string" &&
    CSS_COLOR.test(o.color) &&
    typeof o.background === "string" &&
    CSS_COLOR.test(o.background)
  );
}

export const MAX_FRAME_TEXT = 1_000_000;

export function isGmailFrameParentMessage(
  v: unknown,
): v is GmailFrameParentMessage {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "pgp-frame:armor" &&
    typeof o.nonce === "string" &&
    isGmailFrameNonce(o.nonce) &&
    (o.kind === "message" || o.kind === "signed") &&
    typeof o.text === "string" &&
    o.text.length <= MAX_FRAME_TEXT &&
    isTheme(o.theme)
  );
}

export function isGmailFrameChildMessage(
  v: unknown,
): v is GmailFrameChildMessage {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.nonce !== "string" || !isGmailFrameNonce(o.nonce)) return false;
  if (o.type === "pgp-frame:size") {
    return (
      typeof o.height === "number" &&
      Number.isFinite(o.height) &&
      o.height >= 0 &&
      o.height <= 100_000
    );
  }
  if (o.type === "pgp-frame:ready" || o.type === "pgp-frame:reply") {
    return true;
  }
  if (o.type === "pgp-frame:fold") return typeof o.fold === "boolean";
  return o.type === "pgp-frame:state" && typeof o.shown === "boolean";
}

// ── frame <-> panel ───────────────────────────────────────────────────

/** Frame -> panel: read this block. Sent once the frame has the armor,
 *  and again whenever the panel says it is ready. */
export interface GmailFrameReadRequest {
  type: "read";
  kind: GmailFrameKind;
  text: string;
}

export function isGmailFrameReadRequest(
  v: unknown,
): v is GmailFrameReadRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "read" &&
    (o.kind === "message" || o.kind === "signed") &&
    typeof o.text === "string" &&
    o.text.length > 0 &&
    o.text.length <= MAX_FRAME_TEXT
  );
}

/** Who signed it: the id and user ids of the key the panel verified
 *  against (one of its contacts, or one of the user's own). Display
 *  only; the public key itself is left out. */
export type GmailFrameSigner = Pick<PublicContactKey, "keyId" | "userIds">;

export type GmailFrameSignature =
  /** Signed, and the signer is a key the vault holds. */
  | "valid"
  /** Signed by a key the vault does not hold. */
  | "unknown"
  | "unsigned";

/** Why the panel could not show it; each has its own copy in the frame. */
export type GmailFrameFailure =
  /** None of the vault's keys can open it. */
  | "no-key"
  /** Encrypted to a password, which the frame never asks for. */
  | "password"
  /** The signature does not check out. */
  | "bad-signature"
  /** Not a readable block after all, or the engine refused it. */
  | "error";

/** Panel -> frame. */
export type GmailFramePanelMessage =
  /** Here it is. Sent after a read, and again after every unlock. */
  | {
      type: "show";
      text: string;
      signature: GmailFrameSignature;
      signer: GmailFrameSigner | null;
    }
  /** The panel cannot read it without the user: the vault or the key
   *  the message is for is locked. The frame offers to open the panel. */
  | { type: "locked" }
  | { type: "failed"; reason: GmailFrameFailure };

export function isGmailFramePanelMessage(
  v: unknown,
): v is GmailFramePanelMessage {
  if (typeof v !== "object" || v === null) return false;
  const m = v as Record<string, unknown>;
  if (m.type === "locked") return true;
  if (m.type === "failed") {
    return (
      m.reason === "no-key" ||
      m.reason === "password" ||
      m.reason === "bad-signature" ||
      m.reason === "error"
    );
  }
  if (m.type !== "show" || typeof m.text !== "string") return false;
  if (
    m.signature !== "valid" &&
    m.signature !== "unknown" &&
    m.signature !== "unsigned"
  ) {
    return false;
  }
  if (m.signer === null) return true;
  const s = m.signer as Record<string, unknown> | null | undefined;
  return (
    typeof s === "object" &&
    s !== null &&
    typeof s.keyId === "string" &&
    Array.isArray(s.userIds) &&
    s.userIds.every((u) => typeof u === "string")
  );
}

/**
 * Is this port from one of this extension's frame pages, embedded in a
 * tab? Checked by the panel before it answers anything: the port must
 * come from our own extension (`sender.id`), from a page at the frame
 * URL (`sender.url`, which Chrome sets, not the sender), and from inside
 * a tab's subframe rather than a top-level document or another panel.
 */
export function isGmailFramePort(
  port: Pick<chrome.runtime.Port, "name" | "sender">,
  runtime: { id: string; getURL(path: string): string } = chrome.runtime,
): boolean {
  if (!port.name.startsWith(GMAIL_FRAME_PORT_PREFIX)) return false;
  if (!isGmailFrameNonce(port.name.slice(GMAIL_FRAME_PORT_PREFIX.length))) {
    return false;
  }
  const s = port.sender;
  if (s?.id !== runtime.id) return false;
  if (!s.tab || s.frameId === undefined || s.frameId === 0) return false;
  const url = s.url ?? "";
  const page = runtime.getURL(GMAIL_FRAME_PAGE);
  return url === page || url.startsWith(`${page}#`);
}

/** Frame -> worker: the user pressed "Unlock to read" (or "Open in PGP
 *  Tools") inside the frame. The worker opens the panel on this text
 *  through the pending-op channel, as a banner click would have. */
export interface GmailFrameOpenRequest {
  type: "GMAIL_FRAME_OPEN";
  text: string;
}

export function isGmailFrameOpenRequest(
  v: unknown,
): v is GmailFrameOpenRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "GMAIL_FRAME_OPEN" &&
    typeof o.text === "string" &&
    o.text.length > 0 &&
    o.text.length <= MAX_FRAME_TEXT
  );
}

/** Panel -> every extension page: a panel that can answer frame ports
 *  is up (mounted, or just unlocked). A frame with no port reconnects. */
export const GMAIL_PANEL_READY = "GMAIL_PANEL_READY";
