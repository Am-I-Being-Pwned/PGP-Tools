/**
 * The Gmail add-on's wire protocol: message shapes and the validators
 * every hop re-runs. Shared by the content script (sender), the worker
 * (the boundary that checks) and the panel (the one that inserts
 * ciphertext back), so the three cannot disagree about what is valid.
 *
 * WHAT CROSSES, AND WHAT NEVER DOES. Gmail -> panel: armored text the
 * page already shows (ciphertext, a signed message, a public key), the
 * bytes of an attachment Gmail serves (ciphertext again, fetched by the
 * content script on the panel's request), or the draft the user typed
 * into Gmail's own compose box (Gmail already has it), plus recipient
 * ADDRESSES. Panel -> Gmail: armored `PGP MESSAGE` blocks and encrypted
 * files, nothing else. Plaintext from a decrypt never travels this way
 * -- there is no message type that could carry it. (The inline reader
 * frame shows plaintext INSIDE an extension page Gmail cannot read; its
 * channel is a runtime port to the panel, see `frame-protocol.ts`.)
 *
 * NO URL LITERAL FOR GMAIL LIVES IN THE BUNDLE. The origin is read from
 * the manifest's `optional_host_permissions`, which is the one place it
 * is declared; `scripts/audit-network.mjs` pins that manifest entry and
 * keeps its exact URL-literal sets unchanged.
 */

/** Ceiling on any text the page hands us: far above a real email, far
 *  below anything that would strain session storage or the panel. */
export const MAX_GMAIL_TEXT = 1_000_000;
const MAX_RECIPIENTS = 50;

/** Gmail -> worker: open the panel on this text. The worker derives the
 *  action from the text itself rather than trusting one sent by the
 *  page (see `classifyAction`); only a compose request may be `encrypt`. */
export interface GmailOpenRequest {
  type: "GMAIL_OPEN";
  text: string;
  /** Present when the click came from a compose window's Encrypt button. */
  compose?: GmailComposeRef;
  /** Present when the click came from an attachment chip's button: the
   *  panel fetches the bytes afterwards (`GMAIL_FETCH_ATTACHMENT`), so
   *  nothing but a name and an id travels here. `text` is empty. */
  attachment?: GmailAttachmentRef;
  /** Do not try to open the side panel: there was no click (a compose
   *  window turned encryption on by itself, because the thread holds
   *  PGP and the panel is already open). The op is written as usual. */
  silent?: boolean;
  /** Only bring the side panel up (the cover's button); write no op,
   *  so whatever the user is writing there is left exactly as it is. */
  focus?: boolean;
}

/** Content script -> every extension page: is a side panel up? The
 *  panel answers with a pong; the worker stays silent, so no answer
 *  means no panel. Nothing travels but the question. */
export interface GmailPanelPing {
  type: "GMAIL_PANEL_PING";
}
export interface GmailPanelPong {
  type: "GMAIL_PANEL_PONG";
  /** The vault is open and the workspace can take a draft. */
  unlocked: boolean;
}
export function isGmailPanelPong(v: unknown): v is GmailPanelPong {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as { type?: unknown }).type === "GMAIL_PANEL_PONG" &&
    typeof (v as { unlocked?: unknown }).unlocked === "boolean"
  );
}

export interface GmailAttachmentRef {
  /** Random id the content script stamped on the chip. */
  attachmentId: string;
  /** The file name Gmail shows, for the staged file. */
  name: string;
  /** Stamped by the WORKER from `sender.documentId`, like a draft's. */
  documentId?: string;
}

/** What the panel keeps about an attachment it was asked to open. */
export interface GmailAttachmentTarget extends GmailAttachmentRef {
  tabId: number;
}

export interface GmailComposeRef {
  /** Random id the content script stamped on the compose window, so the
   *  ciphertext comes back to the draft it was written for. */
  composeId: string;
  /** To / Cc addresses read off the compose window, already passed
   *  through `sanitizeRecipients`. Addresses only: Gmail already has
   *  them, and the panel only uses them to preselect matching contacts.
   *  Never Bcc -- see `readRecipients`. */
  recipients: string[];
  /** The Gmail document the draft lives in, stamped by the WORKER from
   *  `sender.documentId` (never taken from the page), so an insert
   *  cannot land in a tab that has since navigated or reloaded. */
  documentId?: string;
}

export type GmailOpenFailure = "not-enabled" | "invalid" | "panel-failed";

export type GmailOpenResponse =
  { ok: true } | { ok: false; error: GmailOpenFailure };

/** Panel -> content script: put this ciphertext into that draft, and
 *  with `send`, press Gmail's own Send for it. */
export interface GmailInsertRequest {
  type: "GMAIL_INSERT";
  composeId: string;
  armored: string;
  send?: boolean;
}

export type GmailInsertResponse =
  /** `sent` is set only when `send` was asked for: whether Gmail took
   *  the click (the compose window went away). */
  | { ok: true; sent?: boolean }
  | { ok: false; error: "compose-gone" | "invalid" };

/** Panel -> content script: put these addresses on that draft's To
 *  line. Addresses only -- the person the user just picked as a
 *  recipient in the panel -- each re-validated before it is typed in. */
export interface GmailAddRecipientsRequest {
  type: "GMAIL_ADD_RECIPIENTS";
  composeId: string;
  addresses: string[];
}

export type GmailAddRecipientsResponse =
  { ok: true } | { ok: false; error: "compose-gone" | "invalid" };

export function isGmailAddRecipientsRequest(
  v: unknown,
): v is GmailAddRecipientsRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "GMAIL_ADD_RECIPIENTS" &&
    isComposeId(o.composeId) &&
    Array.isArray(o.addresses) &&
    o.addresses.length > 0 &&
    o.addresses.length <= MAX_RECIPIENTS &&
    o.addresses.every(isEmailAddress)
  );
}

/** Panel -> content script, in a Gmail tab the panel just opened on a
 *  new compose window: put this ciphertext into its (empty) body, or
 *  attach these encrypted files to it. One or the other, never both. */
export type GmailFillRequest =
  | { type: "GMAIL_FILL"; armored: string; files?: undefined }
  | { type: "GMAIL_FILL"; armored?: undefined; files: GmailFile[] };

export type GmailFillResponse =
  { ok: true } | { ok: false; error: "compose-gone" | "invalid" };

export function isGmailFillRequest(v: unknown): v is GmailFillRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o.type !== "GMAIL_FILL") return false;
  if (o.files === undefined) return isArmoredMessageOnly(o.armored);
  return o.armored === undefined && isGmailFileList(o.files);
}

// ── files: both directions ────────────────────────────────────────────

/** Ceiling on one attachment either way. Gmail's own limit on an
 *  attachment is 25 MB, so nothing above it could be sent anyway. */
export const MAX_GMAIL_FILE_BYTES = 25 * 1024 * 1024;
const MAX_GMAIL_FILES = 20;
/** Chrome's ceiling on one runtime message is 64 MB; base64 of the
 *  file cap is a third over it, well under. */
const MAX_FILE_NAME = 255;

/** A file in a message: name plus base64 bytes. Base64 because runtime
 *  messages are JSON; an `ArrayBuffer` would arrive as `{}`. */
export interface GmailFile {
  name: string;
  data: string;
}

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
/** Base64 of `MAX_GMAIL_FILE_BYTES`, rounded up to a 4-char group. */
const MAX_FILE_BASE64 = Math.ceil(MAX_GMAIL_FILE_BYTES / 3) * 4;

/** A name Gmail could have shown or the panel could have produced: one
 *  path segment of printable characters. */
export function isFileName(v: unknown): v is string {
  return (
    typeof v === "string" &&
    v.length > 0 &&
    v.length <= MAX_FILE_NAME &&
    // eslint-disable-next-line no-control-regex -- control characters are exactly what is refused
    !/[/\\\u0000-\u001f\u007f]/.test(v) &&
    v !== "." &&
    v !== ".."
  );
}

export function isGmailFile(v: unknown): v is GmailFile {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    isFileName(o.name) &&
    typeof o.data === "string" &&
    o.data.length > 0 &&
    o.data.length <= MAX_FILE_BASE64 &&
    o.data.length % 4 === 0 &&
    BASE64.test(o.data)
  );
}

export function isGmailFileList(v: unknown): v is GmailFile[] {
  return (
    Array.isArray(v) &&
    v.length > 0 &&
    v.length <= MAX_GMAIL_FILES &&
    v.every(isGmailFile)
  );
}

/** Chunked, so a 25 MB file does not build one giant argument list. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToBytes(data: string): Uint8Array {
  const binary = atob(data);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Panel -> content script: attach these encrypted files to that draft.
 *  Each is re-checked to be ciphertext (`isEncryptedFileBytes`) before
 *  it is handed to Gmail, exactly as an armored insert is. */
export interface GmailAttachRequest {
  type: "GMAIL_ATTACH";
  composeId: string;
  files: GmailFile[];
}

export type GmailAttachResponse =
  { ok: true } | { ok: false; error: "compose-gone" | "invalid" };

export function isGmailAttachRequest(v: unknown): v is GmailAttachRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "GMAIL_ATTACH" &&
    isComposeId(o.composeId) &&
    isGmailFileList(o.files)
  );
}

/** Panel -> content script: fetch this attachment (one the user pressed
 *  the button on; the id is what the click stamped) and hand back its
 *  bytes. The content script fetches as the page, with Gmail's own
 *  session, which is the only way to reach an attachment without an
 *  API -- and the only network call it can make (`audit-network.mjs`
 *  pins exactly one `fetch` in the content context, same-origin). */
export interface GmailFetchAttachmentRequest {
  type: "GMAIL_FETCH_ATTACHMENT";
  attachmentId: string;
}

export type GmailFetchAttachmentFailure =
  "attachment-gone" | "too-large" | "fetch-failed" | "invalid";

export type GmailFetchAttachmentResponse =
  | { ok: true; file: GmailFile }
  | { ok: false; error: GmailFetchAttachmentFailure };

export function isGmailFetchAttachmentRequest(
  v: unknown,
): v is GmailFetchAttachmentRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return o.type === "GMAIL_FETCH_ATTACHMENT" && isComposeId(o.attachmentId);
}

export function isGmailAttachmentRef(v: unknown): v is GmailAttachmentRef {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    isComposeId(o.attachmentId) &&
    isFileName(o.name) &&
    (o.documentId === undefined ||
      (typeof o.documentId === "string" && DOCUMENT_ID.test(o.documentId)))
  );
}

const AGE_BINARY_MAGIC = "age-encryption.org/v1\n";
const AGE_ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";

/**
 * Is this file ciphertext, as far as its header can say? The file-shaped
 * twin of `isArmoredMessageOnly`, run by the panel before sending and by
 * the content script before handing anything to Gmail:
 *   - binary OpenPGP whose FIRST PACKET is a session-key packet (PKESK
 *     or SKESK) -- a signed-only or literal message is refused;
 *   - an armored PGP MESSAGE with the same first-packet rule;
 *   - an age file, binary (its magic line) or armored.
 * A header is not proof of encryption, but it rules out every plaintext
 * the panel could produce by mistake (a signed file, a decrypt result,
 * a zip of them).
 */
export function isEncryptedFileBytes(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false;
  if ((bytes[0] & 0x80) !== 0) return firstPacketIsSessionKey(bytes);
  // Text forms: decode only as much as a header needs.
  const head = new TextDecoder().decode(
    bytes.subarray(0, Math.min(bytes.length, 64)),
  );
  if (head.startsWith(AGE_BINARY_MAGIC)) return true;
  if (head.startsWith(AGE_ARMOR_BEGIN)) {
    return isArmoredAgeFile(new TextDecoder().decode(bytes));
  }
  if (head.startsWith("-----BEGIN PGP MESSAGE-----")) {
    return isArmoredMessageOnly(new TextDecoder().decode(bytes));
  }
  return false;
}

const AGE_ARMOR_END = "-----END AGE ENCRYPTED FILE-----";
const AGE_BASE64_LINE = /^[A-Za-z0-9+/]{1,64}={0,2}$/;

/** One armored age file: BEGIN, base64 lines, END, whose decoded bytes
 *  open with age's magic line. */
function isArmoredAgeFile(text: string): boolean {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 3) return false;
  if (lines[0] !== AGE_ARMOR_BEGIN) return false;
  if (lines[lines.length - 1] !== AGE_ARMOR_END) return false;
  const body = lines.slice(1, -1);
  if (!body.every((l) => AGE_BASE64_LINE.test(l))) return false;
  let decoded: string;
  try {
    decoded = atob(body.slice(0, 2).join(""));
  } catch {
    return false;
  }
  return decoded.startsWith(AGE_BINARY_MAGIC);
}

/**
 * Gmail's own "compose a new message" URL, To line filled in. The body
 * is NOT put in the URL (a long message would exceed what Google's front
 * end accepts, and it would sit in browser history); it is written into
 * the compose window by the content script once it has loaded. Built
 * from the manifest's origin, so no Gmail literal is in the bundle.
 */
export function gmailComposeUrl(origin: string, to: string[]): string {
  const url = new URL("/mail/", origin);
  url.searchParams.set("view", "cm");
  url.searchParams.set("fs", "1");
  const valid = to.filter(isEmailAddress);
  if (valid.length > 0) url.searchParams.set("to", valid.join(","));
  return url.href;
}

/** What the panel keeps about a compose window while the user writes. */
export interface GmailComposeTarget extends GmailComposeRef {
  tabId: number;
}

// ── origin, from the manifest ─────────────────────────────────────────

/** The add-on's match patterns, as declared in the manifest. */
export function gmailMatchPatterns(
  manifest: {
    optional_host_permissions?: string[];
  } = chrome.runtime.getManifest() as { optional_host_permissions?: string[] },
): string[] {
  return manifest.optional_host_permissions ?? [];
}

/** `<origin>/*` -> `<origin>`. Null for anything that is not exactly an
 *  origin followed by `/*` (wildcard schemes and hosts, paths).
 *
 *  Parsed rather than matched with a regex so no scheme literal lands in
 *  the bundle (`audit-network.mjs` pins every one). The scheme itself is
 *  pinned where it is declared: the audit checks the manifest entry. */
export function originOfPattern(pattern: string): string | null {
  if (!pattern.endsWith("/*") || pattern.includes("*.")) return null;
  let url: URL;
  try {
    url = new URL(pattern.slice(0, -1));
  } catch {
    return null;
  }
  return `${url.origin}/*` === pattern ? url.origin : null;
}

/** The origins a GMAIL_OPEN may come from. */
export function gmailOrigins(patterns = gmailMatchPatterns()): string[] {
  return patterns.map(originOfPattern).filter((o): o is string => o !== null);
}

// ── validators ────────────────────────────────────────────────────────

const COMPOSE_ID = /^[a-f0-9]{32}$/;

export function isComposeId(v: unknown): v is string {
  return typeof v === "string" && COMPOSE_ID.test(v);
}

/** Deliberately plain: this filters what a page could stuff into the
 *  field (markup, control characters, megabytes), it does not try to be
 *  RFC 5322. A rejected oddity just isn't preselected. */
const EMAIL = /^[^\s<>"@,;:()[\]\\]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i;

export function isEmailAddress(v: unknown): v is string {
  return typeof v === "string" && v.length <= 254 && EMAIL.test(v);
}

/** Valid addresses only, lowercased, de-duplicated, capped. */
export function sanitizeRecipients(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out = new Set<string>();
  for (const item of v) {
    if (out.size >= MAX_RECIPIENTS) break;
    if (isEmailAddress(item)) out.add(item.toLowerCase());
  }
  return [...out];
}

/** Chrome's document id: 32 uppercase hex. */
const DOCUMENT_ID = /^[0-9A-F]{32}$/;

export function isGmailComposeRef(v: unknown): v is GmailComposeRef {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    isComposeId(o.composeId) &&
    Array.isArray(o.recipients) &&
    o.recipients.every(isEmailAddress) &&
    o.recipients.length <= MAX_RECIPIENTS &&
    (o.documentId === undefined ||
      (typeof o.documentId === "string" && DOCUMENT_ID.test(o.documentId)))
  );
}

/** Shape check for a GMAIL_OPEN. The text's MEANING is judged by the
 *  worker (`classifyAction`), not here. */
export function isGmailOpenRequest(v: unknown): v is GmailOpenRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "GMAIL_OPEN" &&
    typeof o.text === "string" &&
    o.text.length <= MAX_GMAIL_TEXT &&
    (o.compose === undefined || isGmailComposeRef(o.compose)) &&
    (o.attachment === undefined ||
      (o.compose === undefined &&
        o.text === "" &&
        isGmailAttachmentRef(o.attachment))) &&
    (o.silent === undefined ||
      (o.silent === true && o.compose !== undefined)) &&
    (o.focus === undefined ||
      (o.focus === true && o.compose !== undefined && o.text === ""))
  );
}

const ARMOR_HEADER = /^(Version|Comment|Charset|Hash|MessageID): [ -~]{0,76}$/;
/** More armor headers than any encoder writes. Without a cap, a stack of
 *  `Comment:` lines would be a body of its own. */
const MAX_ARMOR_HEADERS = 4;
const BASE64_LINE = /^[A-Za-z0-9+/]{1,76}={0,2}$/;
const CHECKSUM_LINE = /^=[A-Za-z0-9+/]{4}$/;

/**
 * True only for text that is exactly ONE armored PGP MESSAGE block,
 * surrounded by nothing but whitespace, whose body is armor headers and
 * base64 -- line by line, not "anything between BEGIN and END".
 *
 * This is THE check standing between the panel and Gmail's DOM, and it
 * is run on both sides (panel before sending, content script before
 * writing). Whatever bug upstream hands it -- a decrypt result, a draft,
 * a signed-but-not-encrypted cleartext message, plaintext wrapped in a
 * BEGIN/END pair -- the answer is no, because none of those is a lone
 * `PGP MESSAGE` block of radix-64 that opens with a session-key packet.
 * Headers are allowlisted, printable ASCII, one line each and at most
 * four of them, so even `Comment:` lines cannot carry a body.
 */
export function isArmoredMessageOnly(text: unknown): text is string {
  if (typeof text !== "string" || text.length > MAX_GMAIL_TEXT) return false;
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 4) return false;
  if (lines[0] !== "-----BEGIN PGP MESSAGE-----") return false;
  if (lines[lines.length - 1] !== "-----END PGP MESSAGE-----") return false;

  let i = 1;
  while (i < lines.length - 1 && ARMOR_HEADER.test(lines[i])) i++;
  if (i - 1 > MAX_ARMOR_HEADERS) return false;
  // The blank line that ends the header block is mandatory (RFC 9580
  // §6.2), with or without headers above it.
  if (lines[i] !== "") return false;
  i++;

  const body = lines.slice(i, -1);
  if (body.length === 0) return false;
  const last = body[body.length - 1];
  const dataLines = CHECKSUM_LINE.test(last) ? body.slice(0, -1) : body;
  if (dataLines.length === 0 || !dataLines.every((l) => BASE64_LINE.test(l))) {
    return false;
  }
  return startsWithSessionKeyPacket(dataLines[0]);
}

/**
 * Whether the first OpenPGP packet is a session-key packet: PKESK (tag
 * 1, encrypted to a key) or SKESK (tag 3, encrypted to a password).
 * That is how every ENCRYPTED message begins, and how no plaintext-
 * bearing one does: a signed-only message starts with a one-pass
 * signature (4), a compressed packet (8) or a literal (11), and those
 * would otherwise pass as "armored PGP MESSAGE" while being plaintext
 * in base64. Shape is not proof of encryption, but it rules out every
 * plaintext the panel could produce by mistake.
 */
function startsWithSessionKeyPacket(firstLine: string): boolean {
  let head: string;
  try {
    head = atob(firstLine.slice(0, Math.floor(firstLine.length / 4) * 4));
  } catch {
    return false;
  }
  return firstPacketIsSessionKey(Uint8Array.from(head, (c) => c.charCodeAt(0)));
}

/**
 * The binary form of the same question, by the packet header (RFC 9580
 * §5.2): the tag, then the length octets, then the packet's VERSION,
 * which must be one a session-key packet has (PKESK v3 or v6; SKESK v4,
 * v5 or v6). Checking the version is what stops a file that merely
 * begins with a byte like 0xC1 (an "Á" in a Windows text file) passing
 * on its first byte alone.
 */
export function firstPacketIsSessionKey(bytes: Uint8Array): boolean {
  if (bytes.length < 3) return false;
  const first = bytes[0];
  if ((first & 0x80) === 0) return false;
  let tag: number;
  let headerLength: number;
  if (first & 0x40) {
    tag = first & 0x3f;
    const l = bytes[1];
    headerLength = l < 192 ? 2 : l < 224 ? 3 : l === 255 ? 6 : 2;
  } else {
    tag = (first >> 2) & 0x0f;
    headerLength = [2, 3, 5, 1][first & 0x03];
  }
  if (bytes.length <= headerLength) return false;
  const version = bytes[headerLength];
  if (tag === 1) return version === 3 || version === 6;
  if (tag === 3) return version === 4 || version === 5 || version === 6;
  return false;
}

export function isGmailInsertRequest(v: unknown): v is GmailInsertRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.type === "GMAIL_INSERT" &&
    isComposeId(o.composeId) &&
    isArmoredMessageOnly(o.armored) &&
    (o.send === undefined || typeof o.send === "boolean")
  );
}
