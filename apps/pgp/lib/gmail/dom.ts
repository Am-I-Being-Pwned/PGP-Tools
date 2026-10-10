/**
 * Everything the Gmail add-on knows about Gmail's DOM, in one file.
 *
 * Gmail's class names are obfuscated and change without notice; the two
 * reference integrations (FlowCrypt, Mailvelope) both learned that the
 * hard way and both scatter their selectors across many files. Here they
 * are one table, each entry a fallback chain with the most stable hook
 * first (attributes Gmail uses for its own behaviour -- `g_editable`,
 * `data-message-id`, `[email]` -- before class names). When Gmail breaks
 * the add-on, this is the file to fix.
 *
 * Pure DOM: no `chrome.*`, so it unit-tests under jsdom.
 */

export const SEL = {
  /** A message's rendered body in a thread (FlowCrypt `msgInner`,
   *  Mailvelope `MSG_BODY_SELECTOR`). */
  messageBody: "div.a3s",
  /** The message container that owns a body. */
  messageRoot: "[data-message-id], [data-legacy-message-id], div.adn",
  /** Gmail's "[Message clipped] View entire message" link -- in Gmail's
   *  own footer, never the body (see `clippedLinkFor`). */
  clippedLink: ".iX a",
  /** A compose body: new message, pop-out, or inline reply. */
  composeBody: [
    'div[contenteditable="true"][g_editable="true"]',
    'div.Am.Al.editable[contenteditable="true"]',
    'div[contenteditable="true"][role="textbox"][aria-multiline="true"]',
  ].join(", "),
  /** The element that holds a whole compose window: recipients, subject,
   *  body and toolbar. Tried in order -- nearest stable wrapper first. */
  composeRoot: ["div.I5", "div.M9", "div.aaZ", '[role="dialog"]', "form"],
  /** The Send button (`.aoO` has been Gmail's send class for a decade). */
  sendButton: 'div.T-I.aoO[role="button"], div[role="button"].aoO',
  /** Recipient chips and their legacy hidden inputs. */
  recipientChip: "[email], [data-hovercard-id]",
  /** The To line's text box, where a typed address becomes a chip
   *  (`.agP.aFw` is the class Mailvelope targets; the aria label is
   *  Gmail's own). Never a hidden input. */
  toInput: [
    'input.agP.aFw:not([type="hidden"])',
    "textarea.agP.aFw",
    'input[aria-label^="To" i]:not([type="hidden"])',
    '[name="to"] input:not([type="hidden"])',
  ].join(", "),
  /** Deliberately no `bcc`: see `readRecipients`. */
  recipientInput: 'input[name="to"], input[name="cc"]',
  /** The Bcc row, wherever Gmail marks it. Chips inside are skipped. */
  bccArea: '[name="bcc"], [aria-label^="Bcc" i], [data-name="bcc"]',
  /** The compose toolbar's "Attach files" control. */
  attachButton: [
    '[command="Files"]',
    '[aria-label^="Attach files" i]',
    '[data-tooltip^="Attach files" i]',
    "div.a1.aaA",
  ].join(", "),
  /** A message's Reply control (the footer link or the header arrow). */
  replyButton: [
    '[data-tooltip="Reply"]',
    '[aria-label="Reply"]',
    'span.ams.bkH[role="link"]',
  ].join(", "),
  /** An attachment chip. `download_url` is the attribute Gmail itself
   *  reads to start a download (`<mime>:<name>:<url>`), so it outlives
   *  any class name; the `.aZo` chip and the `.aQH` row are fallbacks
   *  used only to find the chip's visible box. */
  attachmentChip: "[download_url]",
  /** Where an attachment chip's own controls sit (download, drive). */
  attachmentActions: ".aSK, .aQw, .aZi",
} as const;

/** Attribute that marks every element this add-on puts into the page,
 *  so a fresh injection (after an update) can clear an orphaned one. */
export const UI_ATTR = "data-pgp-tools-ui";
/** Stamped on a compose root so ciphertext finds its way back. */
export const COMPOSE_ATTR = "data-pgp-tools-compose";
/** Stamped on an attachment chip the user asked to open, so the panel's
 *  fetch request finds the same chip. */
export const ATTACHMENT_ATTR = "data-pgp-tools-attachment";
/** Set on a message body whose armor an inline frame is showing, so the
 *  raw block folds away under the frame. */
export const FOLDED_ATTR = "data-pgp-tools-folded";
/** Set on a compose body (and its attach control) while the window is
 *  encrypted: the body is hidden under the add-on's card, the control
 *  is dimmed and inert. Text is written in the panel, never here. */
export const COVERED_ATTR = "data-pgp-tools-covered";

// ── reading armor out of a message ────────────────────────────────────

export type ArmorKind = "message" | "signed" | "public-key";

export interface FoundArmor {
  kind: ArmorKind;
  /** The block, BEGIN through END. When `clipped`, BEGIN through the
   *  end of what Gmail rendered -- not usable, but proof it is there. */
  text: string;
  /** BEGIN present, END missing: Gmail cut the message short. */
  clipped: boolean;
}

const MARKERS: { kind: ArmorKind; begin: string; end: string }[] = [
  {
    kind: "message",
    begin: "-----BEGIN PGP MESSAGE-----",
    end: "-----END PGP MESSAGE-----",
  },
  {
    kind: "signed",
    begin: "-----BEGIN PGP SIGNED MESSAGE-----",
    end: "-----END PGP SIGNATURE-----",
  },
  {
    kind: "public-key",
    begin: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    end: "-----END PGP PUBLIC KEY BLOCK-----",
  },
];

/** Cheap pre-check on `textContent`, so a thread of ordinary mail never
 *  pays for an `innerText` layout read. */
export function mightHoldArmor(el: Element): boolean {
  return el.textContent.includes("-----BEGIN PGP ");
}

/**
 * Undo what HTML rendering does to armor: non-breaking spaces, zero-width
 * characters Gmail and senders' clients sprinkle in, CRLF, and trailing
 * spaces. Line breaks themselves survive, because the caller reads
 * `innerText` (layout-aware), unlike the context menu's selectionText.
 */
export function normalizeArmorText(text: string): string {
  return text
    .replace(/\r\n?/g, "\n")
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")
    .split("\n")
    .map((l) => l.trimEnd())
    .join("\n");
}

/**
 * The first armored block in `text` that starts at the beginning of a
 * line. Line-anchored on purpose: a quoted reply renders its armor as
 * `> -----BEGIN ...`, and offering to decrypt the quote of a message the
 * user can already see above it would be noise.
 */
export function findArmor(rawText: string): FoundArmor | null {
  const text = normalizeArmorText(rawText);
  let best: { kind: ArmorKind; start: number; end: string } | null = null;
  for (const m of MARKERS) {
    const start = lineStartIndexOf(text, m.begin);
    if (start !== -1 && (best === null || start < best.start)) {
      best = { kind: m.kind, start, end: m.end };
    }
  }
  if (!best) return null;
  const endAt = text.indexOf(best.end, best.start);
  if (endAt === -1) {
    return { kind: best.kind, text: text.slice(best.start), clipped: true };
  }
  return {
    kind: best.kind,
    text: text.slice(best.start, endAt + best.end.length),
    clipped: false,
  };
}

function lineStartIndexOf(text: string, needle: string): number {
  let from = 0;
  for (;;) {
    const at = text.indexOf(needle, from);
    if (at === -1) return -1;
    if (at === 0 || text[at - 1] === "\n") {
      // Leading spaces are allowed (indentation), a quote marker is not.
      return at;
    }
    const lineStart = text.lastIndexOf("\n", at) + 1;
    if (text.slice(lineStart, at).trim() === "") return at;
    from = at + needle.length;
  }
}

// ── message bodies ────────────────────────────────────────────────────

/** Bodies in a thread, minus anything inside an editor (a draft is not a
 *  received message, even when it quotes one). */
export function messageBodies(doc: Document): HTMLElement[] {
  return [...doc.querySelectorAll<HTMLElement>(SEL.messageBody)].filter(
    (el) => !el.closest('[contenteditable="true"]'),
  );
}

/**
 * Gmail's own link to the unclipped message, as a URL rebuilt from its
 * parts -- or null.
 *
 * The banner carries PGP Tools' name, so where it sends the user must be
 * Gmail's page and nothing an email can choose. Hence: only an anchor in
 * Gmail's `.iX` footer, never one inside the message body (where a
 * hostile email would put `https://phish.example/?view=lg`); only the
 * current origin, under `/mail/`, with `view=lg`; and the returned URL is
 * rebuilt from the origin, path and query rather than handed back as the
 * page wrote it.
 */
export function clippedLinkFor(body: Element, loc: Location): URL | null {
  const root = body.closest(SEL.messageRoot);
  if (!root) return null;
  for (const a of root.querySelectorAll<HTMLAnchorElement>(SEL.clippedLink)) {
    if (body.contains(a)) continue;
    let url: URL;
    try {
      url = new URL(a.getAttribute("href") ?? "", loc.href);
    } catch {
      continue;
    }
    if (
      url.origin === loc.origin &&
      url.pathname.startsWith("/mail/") &&
      url.searchParams.get("view") === "lg"
    ) {
      return new URL(`${url.pathname}${url.search}`, loc.origin);
    }
  }
  return null;
}

/** Gmail's "view entire message" / print pages render one message as a
 *  plain document, with none of the thread markup above. */
export function isStandaloneMessageView(loc: Location): boolean {
  const view = new URLSearchParams(loc.search).get("view");
  return view === "lg" || view === "pt";
}

/** Gmail's "compose a new message" page (`?view=cm`), which the panel
 *  opens itself for "Add to Gmail" with no draft to go back to. */
export function isStandaloneComposeView(
  loc: Pick<Location, "search">,
): boolean {
  return new URLSearchParams(loc.search).get("view") === "cm";
}

// ── compose windows ───────────────────────────────────────────────────

export function composeBodies(doc: Document): HTMLElement[] {
  return [...doc.querySelectorAll<HTMLElement>(SEL.composeBody)];
}

export function composeRootOf(body: Element): HTMLElement | null {
  for (const sel of SEL.composeRoot) {
    const root = body.closest<HTMLElement>(sel);
    if (root) return root;
  }
  return null;
}

/** The compose body inside a root, if it still has one. */
export function composeBodyIn(root: Element): HTMLElement | null {
  return root.querySelector<HTMLElement>(SEL.composeBody);
}

/** Where the Encrypt button goes: right after Send. Null when this
 *  compose window has no Send button we recognise. */
export function sendButtonIn(root: Element): HTMLElement | null {
  return root.querySelector<HTMLElement>(SEL.sendButton);
}

export function attachButtonIn(root: Element): HTMLElement | null {
  return root.querySelector<HTMLElement>(SEL.attachButton);
}

/** The Reply control of the message that owns `body`, or null. */
export function replyButtonFor(body: Element): HTMLElement | null {
  const root = body.closest(SEL.messageRoot);
  if (!root) return null;
  for (const el of root.querySelectorAll<HTMLElement>(SEL.replyButton)) {
    if (!body.contains(el)) return el;
  }
  return null;
}

/**
 * Press one of Gmail's own controls the way a pointer would: Gmail's
 * buttons act on mousedown/mouseup as well as click. Nothing secret is
 * involved either way -- this is how the add-on presses Send after the
 * ciphertext is in, and Reply for the reader frame.
 */
export function pressGmailControl(el: HTMLElement): void {
  const win = el.ownerDocument.defaultView;
  if (!win) return;
  const rect = el.getBoundingClientRect();
  const init = {
    bubbles: true,
    cancelable: true,
    composed: true,
    clientX: rect.left + rect.width / 2,
    clientY: rect.top + rect.height / 2,
    button: 0,
  };
  for (const type of ["mousedown", "mouseup", "click"] as const) {
    el.dispatchEvent(new win.MouseEvent(type, init));
  }
}

const ADDRESS = /^[^\s@<>]+@[^\s@<>]+$/;

/**
 * To / Cc addresses of one compose window. Chips first (`[email]` is
 * Gmail's own hook for hovercards), the old hidden inputs second.
 * Anything inside the editor body is skipped: a quoted header there
 * carries `[email]` too, and it names who wrote the LAST message, not
 * who this one is for.
 *
 * BCC IS LEFT OUT ON PURPOSE. An OpenPGP message lists the key id of
 * every recipient it is encrypted to, so a Bcc'd key would be visible to
 * everyone on the To line. Gmail's Bcc row is skipped wherever it can be
 * recognised (`SEL.bccArea`); SECURITY.md §17 says what that misses.
 */
export function readRecipients(root: Element): string[] {
  const body = composeBodyIn(root);
  const out = new Set<string>();
  for (const el of root.querySelectorAll(SEL.recipientChip)) {
    if (body?.contains(el)) continue;
    if (el.closest(SEL.bccArea)) continue;
    const v = el.getAttribute("email") ?? el.getAttribute("data-hovercard-id");
    if (v && ADDRESS.test(v.trim())) out.add(v.trim().toLowerCase());
  }
  for (const input of root.querySelectorAll<HTMLInputElement>(
    SEL.recipientInput,
  )) {
    for (const part of input.value.split(/[,;]/)) {
      const m = /<([^>]+)>/.exec(part);
      const v = (m ? m[1] : part).trim();
      if (ADDRESS.test(v)) out.add(v.toLowerCase());
    }
  }
  return [...out];
}

const BLOCK_TAGS = new Set([
  "DIV",
  "P",
  "LI",
  "UL",
  "OL",
  "PRE",
  "H1",
  "H2",
  "H3",
  "H4",
  "H5",
  "H6",
  "TABLE",
  "TR",
]);

/**
 * The text of a rendered body, one line per line AS WRITTEN. Walks the
 * tree rather than reading `innerText`: Gmail renders an empty line as
 * `<div><br></div>`, which `innerText` reports as TWO line breaks (the
 * `<br>` and the block's own). Armor readers forgive that; a cleartext
 * signature does not -- the blank lines inside a signed message are part
 * of what was signed, so doubling them fails every verification. Here a
 * block boundary and a `<br>` each count once, and a `<br>` that is the
 * only thing in a block is that block's one line break.
 *
 * Elements Gmail hides (`display: none`, e.g. trimmed quotes) are left
 * out, as `innerText` would; our own hosts always are. `skipQuotes` also
 * drops the quoted original of a reply (a draft is not a received
 * message, even when it quotes one).
 */
export function renderedText(
  root: Element,
  opts: { skipQuotes?: boolean } = {},
): string {
  const win = root.ownerDocument.defaultView;
  const parts: string[] = [];
  const walk = (node: Node, pre: boolean) => {
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent ?? "";
      // Whitespace between block elements is markup formatting, not a
      // line (CSS collapses it away); inside a <pre> it is content.
      if (!pre && text.trim() === "") return;
      parts.push(text);
      return;
    }
    if (!(node instanceof Element)) return;
    if (node.hasAttribute(UI_ATTR)) return;
    if (
      opts.skipQuotes &&
      node.matches(".gmail_quote, .gmail_quote_container, blockquote")
    ) {
      return;
    }
    if (win?.getComputedStyle(node).display === "none") return;
    if (node.tagName === "BR") {
      parts.push("\n");
      return;
    }
    const block = BLOCK_TAGS.has(node.tagName);
    if (block && parts.length > 0 && !parts[parts.length - 1].endsWith("\n")) {
      parts.push("\n");
    }
    const inPre = pre || node.tagName === "PRE";
    node.childNodes.forEach((child) => walk(child, inPre));
    if (block && !parts[parts.length - 1]?.endsWith("\n")) parts.push("\n");
  };
  root.childNodes.forEach((child) => walk(child, root.tagName === "PRE"));
  return parts.join("");
}

/** A received message's text, for `findArmor`. */
export function messageText(body: Element): string {
  return renderedText(body);
}

/**
 * The text the user typed into a compose body, without the quoted
 * message Gmail appends to a reply.
 */
export function composeDraftText(body: Element): string {
  return normalizeArmorText(renderedText(body, { skipQuotes: true }))
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Replace a compose body's content with `armored`, one `<div>` per line
 * -- the markup Gmail itself produces for typed text, so the plain-text
 * part it sends keeps every line break the armor needs.
 *
 * Text goes in through `textContent` only. The caller has already
 * checked it is a lone PGP MESSAGE block; this function does not trust
 * that and never touches `innerHTML` anyway.
 *
 * The quoted original goes too. Quoting ciphertext under ciphertext adds
 * nothing a recipient can read, and keeping it would leave the decrypted
 * text of nothing in particular dangling below the message.
 */
export function writeCiphertext(body: HTMLElement, armored: string): void {
  const doc = body.ownerDocument;
  body.replaceChildren(
    ...armored
      .trim()
      .split("\n")
      .map((line) => {
        const div = doc.createElement("div");
        if (line === "") div.appendChild(doc.createElement("br"));
        else div.textContent = line;
        return div;
      }),
  );
  // Gmail saves drafts (and enables Send) off input events; without one
  // the draft on the server would still be whatever was typed before.
  body.dispatchEvent(new Event("input", { bubbles: true }));
}

/** Does this body currently hold exactly the armor we wrote? Used to
 *  drop the "Encrypted" state the moment the user edits after it. */
export function bodyHoldsCiphertext(body: Element): boolean {
  const text = composeDraftText(body);
  return (
    text.startsWith("-----BEGIN PGP MESSAGE-----") &&
    text.endsWith("-----END PGP MESSAGE-----")
  );
}

/**
 * Put `addresses` on a compose window's To line, skipping any already
 * there. Types them into Gmail's own To box and lets Gmail do the rest:
 * it turns typed text into recipient chips when the box loses focus.
 * The value goes in through the prototype's setter (so a framework
 * tracking the field sees a real change) and as plain text only.
 *
 * False when this compose window has no To box we recognise.
 */
export function addRecipients(root: Element, addresses: string[]): boolean {
  const input = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(
    SEL.toInput,
  );
  if (!input) return false;
  const present = new Set(readRecipients(root));
  const fresh = addresses.filter((a) => !present.has(a.toLowerCase()));
  if (fresh.length === 0) return true;

  const before = input.value.trim();
  const value = `${before ? `${before.replace(/[,;\s]*$/, "")}, ` : ""}${fresh.join(", ")}, `;
  const proto = Object.getPrototypeOf(input) as object;
  input.focus();
  // The prototype's own setter, invoked on the element: a field whose
  // framework shadows `value` still sees the change as a real edit.
  if (!Reflect.set(proto, "value", value, input)) input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.blur();
  return true;
}

// ── attachments ───────────────────────────────────────────────────────

export interface AttachmentChip {
  el: HTMLElement;
  name: string;
  /** Gmail's own download URL for it, same origin as the page. */
  url: URL;
}

const ENCRYPTED_EXT = /\.(pgp|gpg|asc|age)$/i;

/**
 * Parse Gmail's `download_url` attribute: `<mime>:<name>:<url>`. The
 * name may itself contain colons; the URL is everything after the
 * second `https:`-bearing split point, so it is taken from the last
 * `:http` instead of a naive split.
 */
export function parseDownloadUrl(
  attr: string,
  loc: Pick<Location, "origin">,
): { name: string; url: URL } | null {
  const first = attr.indexOf(":");
  if (first === -1) return null;
  const rest = attr.slice(first + 1);
  const at = rest.lastIndexOf(":http");
  if (at === -1) return null;
  const name = rest.slice(0, at).trim();
  let url: URL;
  try {
    url = new URL(rest.slice(at + 1));
  } catch {
    return null;
  }
  // Only Gmail's own attachment endpoint, on this very origin. A hostile
  // email cannot author this attribute (Gmail writes it), but the check
  // costs nothing and is what the fetch pin in the audit describes.
  if (url.origin !== loc.origin || !url.pathname.startsWith("/mail/")) {
    return null;
  }
  if (!name) return null;
  return { name, url };
}

/** Attachment chips in opened messages whose names say they are
 *  encrypted (or armored). Chips inside an editor are a draft's, not a
 *  received message's. */
export function encryptedAttachmentChips(
  doc: Document,
  loc: Pick<Location, "origin">,
): AttachmentChip[] {
  const out: AttachmentChip[] = [];
  for (const el of doc.querySelectorAll<HTMLElement>(SEL.attachmentChip)) {
    if (el.closest('[contenteditable="true"]')) continue;
    const parsed = parseDownloadUrl(el.getAttribute("download_url") ?? "", loc);
    if (!parsed || !ENCRYPTED_EXT.test(parsed.name)) continue;
    out.push({ el, ...parsed });
  }
  return out;
}

/**
 * Hand files to a compose window the way a user dropping them would:
 * a `drop` event on the body carrying a `DataTransfer` with the files.
 * Gmail's compose listens for exactly that and uploads what it finds.
 *
 * The caller has already checked every file is ciphertext; this does
 * not trust that and runs `check` on each again. False when the body is
 * gone or any file fails the check -- then NOTHING is dropped, because
 * attaching half of a set is worse than attaching none.
 */
export function dropFiles(
  body: HTMLElement,
  files: { name: string; bytes: Uint8Array }[],
  check: (bytes: Uint8Array) => boolean,
): boolean {
  if (!body.isConnected || files.length === 0) return false;
  if (!files.every((f) => check(f.bytes))) return false;
  const win = body.ownerDocument.defaultView;
  if (!win) return false;
  const dt = new win.DataTransfer();
  for (const f of files) {
    dt.items.add(
      new win.File([f.bytes as BlobPart], f.name, {
        type: "application/octet-stream",
      }),
    );
  }
  for (const type of ["dragenter", "dragover", "drop"] as const) {
    body.dispatchEvent(
      new win.DragEvent(type, {
        bubbles: true,
        cancelable: true,
        dataTransfer: dt,
      }),
    );
  }
  return true;
}

// ── theme ─────────────────────────────────────────────────────────────

/** `rgba(0, 0, 0, 0)` and `transparent` are what an unset background
 *  computes to; walk up until a real colour. */
function isTransparent(color: string): boolean {
  const c = color.replace(/\s+/g, "").toLowerCase();
  return c === "transparent" || /^rgba\(0,0,0,0\)$/.test(c);
}

/** The text and background colours of the message a frame will sit in,
 *  so the frame can match Gmail's theme. Falls back to black on white. */
export function sampleTheme(
  el: Element,
  win: Pick<Window, "getComputedStyle">,
): { color: string; background: string } {
  const color = win.getComputedStyle(el).color || "rgb(0, 0, 0)";
  let background = "rgb(255, 255, 255)";
  for (let n: Element | null = el; n; n = n.parentElement) {
    const bg = win.getComputedStyle(n).backgroundColor;
    if (bg && !isTransparent(bg)) {
      background = bg;
      break;
    }
  }
  return { color, background };
}
