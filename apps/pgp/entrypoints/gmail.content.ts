/**
 * The Gmail add-on's content script. OFF unless the user turns it on.
 *
 * `registration: "runtime"` keeps it out of the manifest: it is
 * registered by the worker only while the user has granted the optional
 * mail.google.com host permission (Settings -> Gmail), and unregistered
 * the moment that permission goes. `matches` is deliberately absent --
 * WXT would copy it into `host_permissions`, which would make Gmail
 * access an install-time grant. The worker supplies the match pattern
 * from the manifest's `optional_host_permissions` instead.
 *
 * WHAT THIS SCRIPT CAN DO, which is the whole security story of it:
 *   - read armored text Gmail already renders, and the draft the user
 *     typed into Gmail's own compose box (Gmail already has both);
 *   - embed the extension's reader frame where an armored block was,
 *     and hand it that block (the frame's document is cross-origin to
 *     Gmail: the page can size it, not read it);
 *   - ask the worker to open the side panel on that text, or on an
 *     attachment the user pressed the button on;
 *   - fetch ONE attachment's bytes, as the page and only when the panel
 *     asks for a chip the user clicked, and hand them to the panel --
 *     the single network call this bundle contains (audit-network.mjs
 *     pins the `content` context's census to exactly it, same-origin);
 *   - write armored PGP MESSAGE blocks into a compose box, and drop
 *     encrypted files on it, when the panel sends them (validated here
 *     again, line by line / byte by byte).
 * It has no keys, no wasm and no storage. Decrypted text is never sent
 * to it: no message type could carry it. The frame holds plaintext, but
 * the frame is not this script and not Gmail's page.
 *
 * Why no `network-lockdown` import, unlike every other entrypoint: the
 * lockdown makes `fetch` & co. non-configurable, so a second injection
 * into the same isolated world (Settings toggled off and on, with Gmail
 * open) would throw on its own first line. The one fetch here is pinned
 * by the audit instead, and the page's own realm, where Gmail's code
 * runs, is not ours to lock.
 */

import type { GmailFrameParentMessage } from "../lib/gmail/frame-protocol";
import type {
  GmailAddRecipientsResponse,
  GmailAttachResponse,
  GmailFetchAttachmentResponse,
  GmailFile,
  GmailFillResponse,
  GmailInsertResponse,
  GmailOpenRequest,
  GmailOpenResponse,
  GmailPanelPing,
  GmailPanelPong,
} from "../lib/gmail/protocol";
import type {
  AttachmentButton,
  Banner,
  BannerKind,
  ComposeButton,
  Cover,
  Frame,
} from "../lib/gmail/ui";
import {
  addRecipients,
  attachButtonIn,
  ATTACHMENT_ATTR,
  bodyHoldsCiphertext,
  clippedLinkFor,
  COMPOSE_ATTR,
  composeBodies,
  composeBodyIn,
  composeDraftText,
  composeRootOf,
  COVERED_ATTR,
  dropFiles,
  encryptedAttachmentChips,
  findArmor,
  FOLDED_ATTR,
  isStandaloneComposeView,
  isStandaloneMessageView,
  messageBodies,
  messageText,
  mightHoldArmor,
  parseDownloadUrl,
  pressGmailControl,
  readRecipients,
  replyButtonFor,
  sampleTheme,
  sendButtonIn,
  UI_ATTR,
  writeCiphertext,
} from "../lib/gmail/dom";
import {
  GMAIL_FRAME_PAGE,
  GMAIL_PANEL_READY,
  isGmailFrameChildMessage,
} from "../lib/gmail/frame-protocol";
import {
  base64ToBytes,
  bytesToBase64,
  isEncryptedFileBytes,
  isFileName,
  isGmailAddRecipientsRequest,
  isGmailAttachRequest,
  isGmailFetchAttachmentRequest,
  isGmailFillRequest,
  isGmailInsertRequest,
  isGmailPanelPong,
  MAX_GMAIL_FILE_BYTES,
  sanitizeRecipients,
} from "../lib/gmail/protocol";
import {
  createAttachmentButton,
  createBanner,
  createComposeButton,
  createCover,
  createFrame,
} from "../lib/gmail/ui";

/** Debounce for the page observer. Gmail mutates the DOM constantly
 *  (Mailvelope settled on 300ms for the same reason). */
const SCAN_DEBOUNCE_MS = 300;

const FLAG = "__pgpToolsGmail";

/** Fold the raw armor under the frame only when it IS the message: a
 *  block that makes up less than this share of the body sits among
 *  other text the user still wants to see. */
const FOLD_SHARE = 0.7;

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default defineContentScript({
  registration: "runtime",
  runAt: "document_idle",
  main() {
    // A copy injected earlier into this world (the add-on toggled off and
    // on, or an injection racing the registered script) hands over: it
    // tears down, and this one runs. Newest wins, so an older copy can
    // never leave the tab without a working add-on.
    const w = window as unknown as Record<string, (() => void) | undefined>;
    w[FLAG]?.();

    // A copy from before an extension update lives in a world we cannot
    // reach and leaves its UI behind. Clear it before drawing.
    for (const el of document.querySelectorAll(`[${UI_ATTR}]`)) el.remove();
    for (const el of document.querySelectorAll(
      `[${FOLDED_ATTR}], [${COVERED_ATTR}]`,
    )) {
      el.removeAttribute(FOLDED_ATTR);
      el.removeAttribute(COVERED_ATTR);
    }

    const banners = new Map<HTMLElement, Banner>();
    const frames = new Map<HTMLElement, Frame>();
    const attachments = new Map<HTMLElement, AttachmentButton>();
    let observer: MutationObserver | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;

    /** False once the extension has been reloaded or removed: every
     *  `chrome.runtime` call from this copy would throw from now on. */
    const alive = (): boolean => {
      try {
        return !!chrome.runtime.id;
      } catch {
        return false;
      }
    };

    const frameUrl = chrome.runtime.getURL(GMAIL_FRAME_PAGE);
    const extOrigin = new URL(frameUrl).origin;

    // The one rule that hides a folded body. Added once, as a plain
    // stylesheet (Trusted Types govern HTML and script, not CSS text).
    const foldStyle = document.createElement("style");
    foldStyle.setAttribute(UI_ATTR, "");
    foldStyle.textContent = [
      `[${FOLDED_ATTR}] { display: none !important; }`,
      `[contenteditable][${COVERED_ATTR}] { display: none !important; }`,
      `[${COVERED_ATTR}]:not([contenteditable]) { pointer-events: none !important; opacity: .35 !important; }`,
    ].join("\n");
    document.head.appendChild(foldStyle);

    let dead = false;
    const teardown = () => {
      dead = true;
      observer?.disconnect();
      clearTimeout(timer);
      window.removeEventListener("message", onFrameMessage);
      for (const type of ["dragenter", "dragover", "drop"] as const) {
        document.removeEventListener(type, onDrag, true);
      }
      for (const b of banners.values()) b.host.remove();
      for (const f of frames.values()) f.host.remove();
      for (const c of composers.values()) {
        uncoverCompose(c);
        c.btn.host.remove();
      }
      for (const a of attachments.values()) a.host.remove();
      for (const el of document.querySelectorAll(`[${FOLDED_ATTR}]`)) {
        el.removeAttribute(FOLDED_ATTR);
      }
      foldStyle.remove();
      banners.clear();
      frames.clear();
      composers.clear();
      attachments.clear();
    };

    const ask = async (req: GmailOpenRequest): Promise<GmailOpenResponse> => {
      if (!alive()) return { ok: false, error: "panel-failed" };
      try {
        return await chrome.runtime.sendMessage<
          GmailOpenRequest,
          GmailOpenResponse
        >(req);
      } catch {
        return { ok: false, error: "panel-failed" };
      }
    };

    // ── messages: banners (public keys, clipped blocks) ───────────────

    const openFromBody = async (body: HTMLElement, banner: Banner) => {
      if (!alive()) {
        banner.notify("orphaned");
        return;
      }
      if (banner.kind === "clipped") {
        // Gmail's own link to the whole message. It opens in a new tab,
        // where this script runs again and finds the complete block.
        const url = clippedLinkFor(body, location);
        if (url) window.open(url.href, "_blank", "noopener");
        else banner.notify("invalid");
        return;
      }
      // Re-read at click time rather than keeping the text from the
      // scan: nothing from the message is held between scans.
      const found = findArmor(messageText(body));
      if (!found || found.clipped) {
        banner.notify("invalid");
        return;
      }
      banner.setBusy(true);
      const res = await ask({ type: "GMAIL_OPEN", text: found.text });
      banner.setBusy(false);
      banner.notify(res.ok ? "opened" : res.error);
    };

    // ── messages: inline frames (encrypted, signed) ───────────────────

    /** Frames by nonce, for the `message` events they post. */
    const framesByNonce = new Map<
      string,
      { frame: Frame; body: HTMLElement }
    >();

    const foldBody = (body: HTMLElement, fold: boolean) => {
      if (fold) body.setAttribute(FOLDED_ATTR, "");
      else body.removeAttribute(FOLDED_ATTR);
    };

    const onFrameMessage = (event: MessageEvent) => {
      if (dead || event.origin !== extOrigin) return;
      const msg: unknown = event.data;
      if (!isGmailFrameChildMessage(msg)) return;
      const entry = framesByNonce.get(msg.nonce);
      if (event.source !== entry?.frame.frame.contentWindow) return;
      const { frame, body } = entry;
      if (msg.type === "pgp-frame:ready") {
        // The frame is listening: hand it the block (re-read now, so
        // nothing from the message is held between scans) and the
        // colours of the message it sits in.
        const found = findArmor(messageText(body));
        if (!found || found.clipped || found.kind === "public-key") return;
        const armor: GmailFrameParentMessage = {
          type: "pgp-frame:armor",
          nonce: msg.nonce,
          kind: found.kind,
          text: found.text,
          theme: sampleTheme(body, window),
        };
        frame.frame.contentWindow?.postMessage(armor, extOrigin);
        return;
      }
      if (msg.type === "pgp-frame:size") {
        frame.setHeight(msg.height);
        return;
      }
      if (msg.type === "pgp-frame:fold") {
        foldBody(body, msg.fold);
        return;
      }
      if (msg.type === "pgp-frame:reply") {
        // Gmail's own Reply for this message; the window it opens turns
        // encryption on by itself (the thread holds PGP, the panel is up).
        const reply = replyButtonFor(body);
        if (reply) pressGmailControl(reply);
        return;
      }
      // State: the raw armor folds away while the frame shows the
      // message in its place -- but only when the block IS the body.
      if (!msg.shown) {
        frame.setHeight(0);
        foldBody(body, false);
        return;
      }
      const found = findArmor(messageText(body));
      const whole = messageText(body).trim().length;
      if (found && whole > 0 && found.text.length / whole >= FOLD_SHARE) {
        foldBody(body, true);
      }
    };
    window.addEventListener("message", onFrameMessage);

    const mountFrame = (body: HTMLElement) => {
      const nonce = randomId();
      const frame = createFrame(nonce, `${frameUrl}#${nonce}`);
      // The armor goes in when the frame says it is listening
      // (`pgp-frame:ready`, handled above).
      if (body === document.body) body.prepend(frame.host);
      else body.before(frame.host);
      frames.set(body, frame);
      framesByNonce.set(nonce, { frame, body });
    };

    const dropFrame = (body: HTMLElement) => {
      const frame = frames.get(body);
      if (!frame) return;
      frame.host.remove();
      frames.delete(body);
      framesByNonce.delete(frame.nonce);
      foldBody(body, false);
    };

    const scanMessages = () => {
      const bodies = isStandaloneMessageView(location)
        ? [document.body]
        : messageBodies(document);
      const seenBanner = new Set<HTMLElement>();
      const seenFrame = new Set<HTMLElement>();
      for (const body of bodies) {
        if (!mightHoldArmor(body)) continue;
        const found = findArmor(messageText(body));
        if (!found) continue;
        // Encrypted and signed blocks are read in place by the frame; a
        // public key (an import, which is a decision) and a clipped
        // block (nothing to read yet) keep the banner.
        if (!found.clipped && found.kind !== "public-key") {
          seenFrame.add(body);
          const existing = frames.get(body);
          if (existing?.host.isConnected) continue;
          dropFrame(body);
          banners.get(body)?.host.remove();
          banners.delete(body);
          mountFrame(body);
          continue;
        }
        seenBanner.add(body);
        const kind: BannerKind = found.clipped ? "clipped" : found.kind;
        const existing = banners.get(body);
        if (existing?.host.isConnected && existing.kind === kind) continue;
        existing?.host.remove();
        dropFrame(body);
        const banner = createBanner(kind, () => {
          void openFromBody(body, banner);
        });
        if (body === document.body) body.prepend(banner.host);
        else body.before(banner.host);
        banners.set(body, banner);
      }
      for (const [body, banner] of banners) {
        if (!seenBanner.has(body)) {
          banner.host.remove();
          banners.delete(body);
        }
      }
      for (const body of [...frames.keys()]) {
        if (!seenFrame.has(body)) dropFrame(body);
      }
    };

    // ── attachments ──────────────────────────────────────────────────

    const openAttachment = async (
      chip: HTMLElement,
      name: string,
      btn: AttachmentButton,
    ) => {
      if (!alive()) {
        btn.notify("orphaned");
        return;
      }
      let id = chip.getAttribute(ATTACHMENT_ATTR);
      if (!id) {
        id = randomId();
        chip.setAttribute(ATTACHMENT_ATTR, id);
      }
      btn.setBusy(true);
      btn.notify(null);
      const res = await ask({
        type: "GMAIL_OPEN",
        text: "",
        attachment: { attachmentId: id, name },
      });
      btn.setBusy(false);
      btn.notify(res.ok ? "opened" : res.error);
    };

    const scanAttachments = () => {
      const seen = new Set<HTMLElement>();
      for (const chip of encryptedAttachmentChips(document, location)) {
        seen.add(chip.el);
        const existing = attachments.get(chip.el);
        if (existing?.host.isConnected) continue;
        existing?.host.remove();
        const btn = createAttachmentButton(chip.name, () => {
          void openAttachment(chip.el, chip.name, btn);
        });
        chip.el.after(btn.host);
        attachments.set(chip.el, btn);
      }
      for (const [el, btn] of attachments) {
        if (!seen.has(el)) {
          btn.host.remove();
          attachments.delete(el);
        }
      }
    };

    /**
     * Fetch the attachment the panel asked for. The chip is found by
     * the id a CLICK stamped on it -- the panel cannot name a chip the
     * user did not press -- and the URL is re-read from Gmail's own
     * attribute at fetch time, same origin only. Bytes are capped before
     * they are read in full.
     */
    const fetchAttachment = async (
      attachmentId: string,
    ): Promise<GmailFetchAttachmentResponse> => {
      const chip = document.querySelector<HTMLElement>(
        `[${ATTACHMENT_ATTR}="${attachmentId}"]`,
      );
      const parsed = chip
        ? parseDownloadUrl(chip.getAttribute("download_url") ?? "", location)
        : null;
      if (!parsed) return { ok: false, error: "attachment-gone" };
      // The name is re-read with the URL; Gmail's page could have
      // rewritten the attribute since the click.
      if (!isFileName(parsed.name)) return { ok: false, error: "invalid" };
      let res: Response;
      try {
        res = await fetch(parsed.url.href, {
          method: "GET",
          credentials: "same-origin",
          redirect: "follow",
          cache: "no-store",
        });
      } catch {
        return { ok: false, error: "fetch-failed" };
      }
      if (!res.ok || !res.body) return { ok: false, error: "fetch-failed" };
      const declared = Number(res.headers.get("content-length") ?? "0");
      if (declared > MAX_GMAIL_FILE_BYTES) {
        await res.body.cancel().catch(() => undefined);
        return { ok: false, error: "too-large" };
      }
      const chunks: Uint8Array[] = [];
      let total = 0;
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_GMAIL_FILE_BYTES) {
          await reader.cancel().catch(() => undefined);
          return { ok: false, error: "too-large" };
        }
        chunks.push(value);
      }
      if (total === 0) return { ok: false, error: "invalid" };
      const bytes = new Uint8Array(total);
      let at = 0;
      for (const c of chunks) {
        bytes.set(c, at);
        at += c.length;
      }
      return {
        ok: true,
        file: { name: parsed.name, data: bytesToBase64(bytes) },
      };
    };

    // ── compose ─────────────────────────────────────────────────────
    //
    // THE PANEL IS THE COMPOSER; GMAIL KEEPS THE ENVELOPE. While a compose
    // window is "on", its body is hidden under a card and its attach
    // control is inert: To, Cc, Subject and Send stay Gmail's, the text is
    // written in the side panel, and the panel's "Encrypt & send" puts the
    // ciphertext in and presses Send. Nothing typed into this page can be
    // the message -- which is also what makes a swapped-in look-alike box
    // the tell rather than a trap. A window turns itself on when the
    // thread it answers holds PGP and a panel is up to take the draft;
    // the lock pill beside Send is the switch either way.

    interface ComposeWindow {
      root: HTMLElement;
      body: HTMLElement;
      btn: ComposeButton;
      cover: Cover | null;
      attach: HTMLElement | null;
      /** Settled: armed, or the user chose. Until then the window may
       *  still turn itself on when a panel appears. */
      decided: boolean;
      lastPing: number;
    }
    const composers = new Map<HTMLElement, ComposeWindow>();

    const composeIdOf = (root: HTMLElement): string => {
      let id = root.getAttribute(COMPOSE_ATTR);
      if (!id) {
        id = randomId();
        root.setAttribute(COMPOSE_ATTR, id);
      }
      return id;
    };

    const composeRef = (cw: ComposeWindow) => ({
      composeId: composeIdOf(cw.root),
      recipients: sanitizeRecipients(readRecipients(cw.root)),
    });

    /** Is a side panel up? The panel answers; the worker stays silent. */
    const panelUp = async (): Promise<GmailPanelPong | null> => {
      if (!alive()) return null;
      try {
        const res: unknown = await chrome.runtime.sendMessage<GmailPanelPing>({
          type: "GMAIL_PANEL_PING",
        });
        return isGmailPanelPong(res) ? res : null;
      } catch {
        return null;
      }
    };

    /** Does the thread on screen hold anything PGP-encrypted? */
    const threadHoldsPgp = (): boolean =>
      frames.size > 0 ||
      attachments.size > 0 ||
      [...banners.values()].some((b) => b.kind === "clipped");

    const coverCompose = (cw: ComposeWindow) => {
      if (cw.cover) return;
      const cover = createCover(() => void openPanelFor(cw));
      cw.body.setAttribute(COVERED_ATTR, "");
      cw.body.before(cover.host);
      cw.cover = cover;
      const attach = attachButtonIn(cw.root);
      if (attach) {
        attach.setAttribute(COVERED_ATTR, "");
        cw.attach = attach;
      }
    };

    const uncoverCompose = (cw: ComposeWindow) => {
      cw.cover?.host.remove();
      cw.cover = null;
      cw.body.removeAttribute(COVERED_ATTR);
      cw.attach?.removeAttribute(COVERED_ATTR);
      cw.attach = null;
    };

    /** The cover's button: bring the panel up, touch nothing in it. */
    const openPanelFor = async (cw: ComposeWindow) => {
      if (!alive()) {
        cw.btn.notify("orphaned");
        return;
      }
      const res = await ask({
        type: "GMAIL_OPEN",
        text: "",
        compose: composeRef(cw),
        focus: true,
      });
      if (!res.ok) cw.btn.notify(res.error);
    };

    /**
     * Turn a window on: hand the panel whatever is in the box already
     * (Gmail has that text; the panel copy is the one that gets
     * encrypted) plus the addresses, then cover the box. `silent` is
     * the window doing it by itself -- no click, so no panel to open,
     * and no bubble.
     */
    const armCompose = async (cw: ComposeWindow, silent: boolean) => {
      cw.decided = true;
      if (!alive()) {
        cw.btn.notify("orphaned");
        return;
      }
      cw.btn.setState("busy");
      cw.btn.notify(null);
      const text = bodyHoldsCiphertext(cw.body)
        ? ""
        : composeDraftText(cw.body);
      const res = await ask({
        type: "GMAIL_OPEN",
        text,
        compose: composeRef(cw),
        ...(silent ? { silent: true } : {}),
      });
      if (!cw.root.isConnected) return;
      if (!res.ok) {
        cw.btn.setState("off");
        cw.btn.notify(res.error);
        return;
      }
      cw.btn.setState("on");
      if (!silent) cw.btn.notify("opened");
      coverCompose(cw);
    };

    const disarmCompose = (cw: ComposeWindow) => {
      cw.decided = true;
      uncoverCompose(cw);
      cw.btn.setState("off");
      cw.btn.notify(null);
    };

    const toggleCompose = (cw: ComposeWindow) => {
      if (cw.btn.state === "on") disarmCompose(cw);
      else if (cw.btn.state === "off") void armCompose(cw, false);
    };

    /** A window in a PGP thread turns itself on once a panel is up. */
    const maybeAutoArm = async (cw: ComposeWindow) => {
      // Read through a call, not the field: the user may settle the
      // window while the ping is in flight.
      const settled = () => cw.decided;
      // A compose tab the panel opened itself (`view=cm`, "Add to Gmail"
      // with no draft) is the panel's to fill: it is never armed.
      if (settled() || isStandaloneComposeView(location)) return;
      if (!threadHoldsPgp()) return;
      const now = Date.now();
      if (now - cw.lastPing < 3000) return;
      cw.lastPing = now;
      const pong = await panelUp();
      if (!pong || settled() || !cw.root.isConnected) return;
      await armCompose(cw, true);
    };

    const scanCompose = () => {
      const seen = new Set<HTMLElement>();
      for (const body of composeBodies(document)) {
        const root = composeRootOf(body);
        if (!root || seen.has(root)) continue;
        seen.add(root);
        const existing = composers.get(root);
        if (existing?.btn.host.isConnected) {
          // Gmail re-rendered the body under us: keep the cover on it.
          if (existing.cover && !existing.cover.host.isConnected) {
            existing.cover = null;
            existing.body = body;
            coverCompose(existing);
          }
          void maybeAutoArm(existing);
          continue;
        }
        if (existing) {
          uncoverCompose(existing);
          existing.btn.host.remove();
        }
        const send = sendButtonIn(root);
        if (!send) continue;
        const cw: ComposeWindow = {
          root,
          body,
          btn: createComposeButton(() => toggleCompose(cw)),
          cover: null,
          attach: null,
          decided: false,
          lastPing: 0,
        };
        // After Send's own wrapper (`.dC` holds Send + its schedule
        // arrow), so the split button stays one piece.
        const anchor = send.closest(".dC") ?? send;
        anchor.after(cw.btn.host);
        composers.set(root, cw);
        // Editing after the ciphertext went in means the draft is no
        // longer just the ciphertext; say so by dropping "Encrypted".
        body.addEventListener("input", () => {
          if (cw.btn.state === "done" && !bodyHoldsCiphertext(body)) {
            cw.btn.setState("off");
          }
        });
        void maybeAutoArm(cw);
      }
      for (const [root, cw] of composers) {
        if (!seen.has(root)) {
          uncoverCompose(cw);
          cw.btn.host.remove();
          composers.delete(root);
        }
      }
    };

    // A file dropped on a covered window must not be attached in the
    // clear by Gmail underneath the card. Captured at the document, so
    // it is stopped before Gmail's own handlers see it. Our own synthetic
    // drops (encrypted files from the panel) are let through.
    let ourDrop = false;
    const coveredWindowAt = (target: EventTarget | null) => {
      if (!(target instanceof Node)) return null;
      for (const cw of composers.values()) {
        if (cw.cover && cw.root.contains(target)) return cw;
      }
      return null;
    };
    const onDrag = (e: DragEvent) => {
      if (dead || ourDrop) return;
      const cw = coveredWindowAt(e.target);
      if (!cw) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      if (e.type === "drop") cw.cover?.droppedHere();
    };
    for (const type of ["dragenter", "dragover", "drop"] as const) {
      document.addEventListener(type, onDrag, true);
    }

    // ── panel -> compose ─────────────────────────────────────────────

    const decodeFiles = (files: GmailFile[]) =>
      files.map((f) => ({ name: f.name, bytes: base64ToBytes(f.data) }));

    /** Drop the panel's encrypted files on a body, past our own drop
     *  guard (the dispatch is synchronous, so the flag is exact). */
    const dropOurFiles = (body: HTMLElement, files: GmailFile[]): boolean => {
      ourDrop = true;
      try {
        return dropFiles(body, decodeFiles(files), isEncryptedFileBytes);
      } finally {
        ourDrop = false;
      }
    };

    /**
     * Wait (bounded) for the one compose window a fresh `view=cm` tab
     * shows, then write the ciphertext into it, or drop the files on
     * it. Refuses -- rather than guessing -- when there is more than one
     * compose window, or when the one there already holds text: this
     * never overwrites anything the user typed.
     */
    const fillNewCompose = (
      payload: { armored: string } | { files: GmailFile[] },
    ): Promise<boolean> =>
      new Promise((resolve) => {
        const deadline = Date.now() + 15_000;
        const attempt = () => {
          if (dead) return resolve(false);
          const bodies = composeBodies(document);
          if (bodies.length === 1) {
            const body = bodies[0];
            if (composeDraftText(body) !== "") return resolve(false);
            const root = composeRootOf(body);
            const cw = root ? composers.get(root) : undefined;
            if ("armored" in payload) {
              writeCiphertext(body, payload.armored);
            } else if (!dropOurFiles(body, payload.files)) {
              return resolve(false);
            }
            if (cw) {
              cw.decided = true;
              uncoverCompose(cw);
              cw.btn.setState("done");
            }
            body.focus();
            return resolve(true);
          }
          if (bodies.length > 1 || Date.now() > deadline) {
            return resolve(false);
          }
          setTimeout(attempt, 250);
        };
        attempt();
      });

    chrome.runtime.onMessage.addListener((msg: unknown, sender, respond) => {
      // Only the extension's own pages may write into a draft or ask for
      // an attachment: never another content script (sender.tab set),
      // never another extension (sender.id differs).
      if (dead) return undefined;
      if (sender.id !== chrome.runtime.id || sender.tab) return undefined;
      const type = (msg as { type?: unknown } | null)?.type;
      // Settings is turning the add-on off. Revoking the permission only
      // stops FUTURE injections; this stops the copy already running.
      if (type === "GMAIL_TEARDOWN") {
        teardown();
        return undefined;
      }
      // A panel came up: windows in a PGP thread may turn on now.
      if (type === GMAIL_PANEL_READY) {
        for (const cw of composers.values()) {
          cw.lastPing = 0;
          void maybeAutoArm(cw);
        }
        return undefined;
      }
      // A compose window the panel opened ("Add to Gmail" with no draft
      // to go back to): fill its body once Gmail has drawn it.
      if (isGmailFillRequest(msg)) {
        void fillNewCompose(
          msg.files === undefined
            ? { armored: msg.armored }
            : { files: msg.files },
        ).then((ok) =>
          respond(
            (ok
              ? { ok: true }
              : {
                  ok: false,
                  error: "compose-gone",
                }) satisfies GmailFillResponse,
          ),
        );
        return true;
      }
      // The panel wants the bytes of a chip the user pressed.
      if (isGmailFetchAttachmentRequest(msg)) {
        void fetchAttachment(msg.attachmentId).then(respond, () =>
          respond({
            ok: false,
            error: "fetch-failed",
          } satisfies GmailFetchAttachmentResponse),
        );
        return true;
      }
      // A recipient the user picked in the panel joins the To line.
      if (isGmailAddRecipientsRequest(msg)) {
        const root = document.querySelector<HTMLElement>(
          `[${COMPOSE_ATTR}="${msg.composeId}"]`,
        );
        const added = root ? addRecipients(root, msg.addresses) : false;
        respond(
          (added
            ? { ok: true }
            : {
                ok: false,
                error: "compose-gone",
              }) satisfies GmailAddRecipientsResponse,
        );
        return undefined;
      }
      // Encrypted files for a draft: dropped on its body as a user would.
      if (isGmailAttachRequest(msg)) {
        const root = document.querySelector<HTMLElement>(
          `[${COMPOSE_ATTR}="${msg.composeId}"]`,
        );
        const body = root ? composeBodyIn(root) : null;
        if (!root || !body) {
          respond({
            ok: false,
            error: "compose-gone",
          } satisfies GmailAttachResponse);
          return undefined;
        }
        const ok = dropOurFiles(body, msg.files);
        const cw = composers.get(root);
        if (ok && cw) cw.decided = true;
        respond(
          (ok
            ? { ok: true }
            : { ok: false, error: "invalid" }) satisfies GmailAttachResponse,
        );
        return undefined;
      }
      if (!isGmailInsertRequest(msg)) {
        if (
          type === "GMAIL_INSERT" ||
          type === "GMAIL_ATTACH" ||
          type === "GMAIL_FILL"
        ) {
          respond({
            ok: false,
            error: "invalid",
          } satisfies GmailInsertResponse);
        }
        return undefined;
      }
      const root = document.querySelector<HTMLElement>(
        `[${COMPOSE_ATTR}="${msg.composeId}"]`,
      );
      const body = root ? composeBodyIn(root) : null;
      if (!root || !body) {
        respond({
          ok: false,
          error: "compose-gone",
        } satisfies GmailInsertResponse);
        return undefined;
      }
      writeCiphertext(body, msg.armored);
      const cw = composers.get(root);
      if (cw) {
        // The ciphertext is the body now; show it, as Gmail would.
        cw.decided = true;
        uncoverCompose(cw);
        cw.btn.setState("done");
        cw.btn.notify(null);
      }
      if (!msg.send) {
        respond({ ok: true } satisfies GmailInsertResponse);
        return undefined;
      }
      // Press Gmail's Send. "Sent" means the window went away; a window
      // still there (Gmail asked about an empty subject, say) is the
      // user's to send.
      const send = sendButtonIn(root);
      if (send) pressGmailControl(send);
      const deadline = Date.now() + 4000;
      const check = () => {
        if (!root.isConnected || dead) {
          respond({ ok: true, sent: !dead } satisfies GmailInsertResponse);
          return;
        }
        if (Date.now() > deadline) {
          respond({ ok: true, sent: false } satisfies GmailInsertResponse);
          return;
        }
        setTimeout(check, 150);
      };
      check();
      return true;
    });

    // ── observe ──────────────────────────────────────────────────────

    const scan = () => {
      if (dead) return;
      if (!alive()) {
        teardown();
        return;
      }
      scanMessages();
      scanAttachments();
      scanCompose();
    };

    observer = new MutationObserver((records) => {
      // Our own hosts changing is not news.
      if (
        records.every((r) =>
          [...r.addedNodes, ...r.removedNodes].every(
            (n) => n instanceof Element && n.hasAttribute(UI_ATTR),
          ),
        )
      ) {
        return;
      }
      clearTimeout(timer);
      timer = setTimeout(scan, SCAN_DEBOUNCE_MS);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    w[FLAG] = teardown;
    scan();
  },
});
