import { useCallback, useEffect, useRef, useState } from "react";
import {
  ExternalLinkIcon,
  LockIcon,
  LockOpenIcon,
  ReplyIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldQuestionIcon,
  TriangleAlertIcon,
} from "lucide-react";

import type {
  GmailFrameChildMessage,
  GmailFrameFailure,
  GmailFrameKind,
  GmailFrameOpenRequest,
  GmailFramePanelMessage,
  GmailFrameReadRequest,
  GmailFrameSignature,
  GmailFrameSigner,
  GmailFrameTheme,
} from "../../lib/gmail/frame-protocol";
import type { GmailOpenResponse } from "../../lib/gmail/protocol";
import {
  GMAIL_FRAME_PORT_PREFIX,
  GMAIL_PANEL_READY,
  isGmailFrameNonce,
  isGmailFramePanelMessage,
  isGmailFrameParentMessage,
} from "../../lib/gmail/frame-protocol";
import { gmailOrigins } from "../../lib/gmail/protocol";
import { t } from "../../lib/i18n";
import { formatKeyDisplayName } from "../../lib/utils/key-naming";
import { forgetLastRegExpMatch } from "../../lib/utils/regexp-residue";

/**
 * The inline reader: one encrypted (or signed) block, read in place.
 *
 * An extension page Gmail embeds where the armor was. Gmail can place
 * and size it; it cannot read it. Like Reply's reader tab it is a DUMB
 * VIEW with no vault, keys, wasm or storage: it holds the armored block
 * the content script posted (ciphertext the page had anyway) and shows
 * whatever the side panel answers over a runtime port. The message text
 * goes into the <pre> imperatively and never enters React state.
 *
 * WHEN THERE IS NO PANEL, OR IT IS LOCKED, the frame offers one button:
 * "Unlock to read". That is a user gesture inside an extension page, so
 * the worker can open the side panel on it (through the same pending-op
 * channel as a banner click), and the panel -- where the passkey
 * ceremony has to run; it cannot run in a frame Gmail embeds -- unlocks
 * and then answers this frame's port. The frame keeps listening for the
 * panel's "ready" broadcast and reconnects on it.
 */

type View =
  | { state: "waiting" }
  | {
      state: "shown";
      signature: GmailFrameSignature;
      signer: GmailFrameSigner | null;
    }
  | { state: "locked" }
  | { state: "failed"; reason: GmailFrameFailure }
  | { state: "unavailable" };

/** Perceived luminance of an `rgb(...)`/`rgba(...)` string; 0.5 for
 *  anything else, which picks the light theme. */
function luminance(color: string): number {
  const m = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color);
  if (!m) return 0.5;
  const [r, g, b] = [m[1], m[2], m[3]].map((v) => Number(v) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function applyTheme(theme: GmailFrameTheme): void {
  const root = document.documentElement;
  root.style.setProperty("--gf-fg", theme.color);
  root.style.setProperty("--gf-bg", theme.background);
  root.classList.toggle("dark", luminance(theme.background) < 0.5);
}

export function GmailFrame() {
  const [view, setView] = useState<View>({ state: "waiting" });
  const [kind, setKind] = useState<GmailFrameKind>("message");
  const [opening, setOpening] = useState(false);
  const [openNote, setOpenNote] = useState<string | null>(null);
  const [showOriginal, setShowOriginal] = useState(false);
  const textRef = useRef<HTMLPreElement>(null);
  const nonceRef = useRef<string>("");
  /** The armored block, as the content script handed it over. */
  const armorRef = useRef<{ kind: GmailFrameKind; text: string } | null>(null);
  const portRef = useRef<chrome.runtime.Port | null>(null);
  const parentOriginRef = useRef<string>("");

  const post = useCallback((msg: GmailFrameChildMessage) => {
    if (window.parent === window || !parentOriginRef.current) return;
    window.parent.postMessage(msg, parentOriginRef.current);
  }, []);

  const clearText = useCallback(() => {
    if (textRef.current) textRef.current.textContent = "";
    forgetLastRegExpMatch();
  }, []);

  const connect = useCallback(() => {
    const armor = armorRef.current;
    if (!armor || portRef.current) return;
    let port: chrome.runtime.Port;
    try {
      port = chrome.runtime.connect({
        name: GMAIL_FRAME_PORT_PREFIX + nonceRef.current,
      });
    } catch {
      setView({ state: "locked" });
      return;
    }
    portRef.current = port;
    port.onMessage.addListener((raw: unknown) => {
      if (!isGmailFramePanelMessage(raw)) return;
      const msg: GmailFramePanelMessage = raw;
      if (msg.type === "locked") {
        clearText();
        setView({ state: "locked" });
        return;
      }
      if (msg.type === "failed") {
        clearText();
        setView({ state: "failed", reason: msg.reason });
        return;
      }
      if (textRef.current) textRef.current.textContent = msg.text;
      setView({ state: "shown", signature: msg.signature, signer: msg.signer });
    });
    port.onDisconnect.addListener(() => {
      portRef.current = null;
      // Nobody answered (no panel open), or the panel closed: either
      // way the message is not readable until the panel is back.
      clearText();
      setView({ state: "locked" });
    });
    const req: GmailFrameReadRequest = {
      type: "read",
      kind: armor.kind,
      text: armor.text,
    };
    port.postMessage(req);
  }, [clearText]);

  // The armor arrives from the content script, once.
  useEffect(() => {
    const nonce = location.hash.slice(1);
    const origins = gmailOrigins();
    const framer = location.ancestorOrigins.item(0);
    const framedByGmail =
      window.parent !== window && framer !== null && origins.includes(framer);
    if (!isGmailFrameNonce(nonce) || !framedByGmail) {
      setView({ state: "unavailable" });
      return;
    }
    nonceRef.current = nonce;
    // Who to answer: the Gmail origin that framed us, when the browser
    // says which; otherwise the manifest's (there is one).
    parentOriginRef.current = framer;
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window.parent) return;
      if (!origins.includes(event.origin)) return;
      const msg: unknown = event.data;
      if (!isGmailFrameParentMessage(msg) || msg.nonce !== nonce) return;
      if (armorRef.current) return;
      parentOriginRef.current = event.origin;
      applyTheme(msg.theme);
      armorRef.current = { kind: msg.kind, text: msg.text };
      setKind(msg.kind);
      connect();
    };
    window.addEventListener("message", onMessage);
    // Listening now: ask for the block. (Posting on the iframe's `load`
    // would be too early -- this effect runs after it.)
    post({ type: "pgp-frame:ready", nonce });
    return () => window.removeEventListener("message", onMessage);
  }, [connect, post]);

  // A panel coming up (opened, or unlocked) says so to every extension
  // page; a frame without a live port tries again.
  useEffect(() => {
    const onRuntime = (msg: unknown) => {
      if ((msg as { type?: unknown } | null)?.type !== GMAIL_PANEL_READY) {
        return;
      }
      if (!portRef.current) connect();
    };
    chrome.runtime.onMessage.addListener(onRuntime);
    return () => chrome.runtime.onMessage.removeListener(onRuntime);
  }, [connect]);

  useEffect(() => {
    return () => {
      portRef.current?.disconnect();
      portRef.current = null;
    };
  }, []);

  // Size: while showing the message the frame is as tall as its text
  // and says so. In every other state it says nothing and sits at the
  // host's one resting height, so its size tells the page nothing about
  // keys or locks (every non-showing state is laid out to fit it).
  const shownNow = view.state === "shown";
  useEffect(() => {
    if (!shownNow) return;
    const el = document.documentElement;
    const report = () =>
      post({
        type: "pgp-frame:size",
        nonce: nonceRef.current,
        height: Math.ceil(el.getBoundingClientRect().height),
      });
    const ro = new ResizeObserver(report);
    ro.observe(document.body);
    report();
    return () => ro.disconnect();
  }, [post, shownNow]);

  // One bit for the content script: fold the raw armor away or not.
  useEffect(() => {
    post({ type: "pgp-frame:state", nonce: nonceRef.current, shown: shownNow });
    if (!shownNow) setShowOriginal(false);
  }, [post, shownNow]);

  useEffect(() => {
    document.title = t("gmail_frame_title");
  }, []);

  /** "Unlock to read" / "Open in PGP Tools": the worker opens the panel
   *  on this block, as it would for a banner click. */
  const openInPanel = async () => {
    const armor = armorRef.current;
    if (!armor || opening) return;
    setOpening(true);
    setOpenNote(null);
    let res: GmailOpenResponse;
    try {
      const req: GmailFrameOpenRequest = {
        type: "GMAIL_FRAME_OPEN",
        text: armor.text,
      };
      res = await chrome.runtime.sendMessage<
        GmailFrameOpenRequest,
        GmailOpenResponse
      >(req);
    } catch {
      res = { ok: false, error: "panel-failed" };
    }
    setOpening(false);
    if (!res.ok) {
      setOpenNote(
        res.error === "not-enabled"
          ? t("gmail_notice_not_enabled")
          : res.error === "invalid"
            ? t("gmail_notice_invalid")
            : t("gmail_notice_panel_failed"),
      );
    }
  };

  const toggleOriginal = () => {
    const next = !showOriginal;
    setShowOriginal(next);
    post({ type: "pgp-frame:fold", nonce: nonceRef.current, fold: !next });
  };

  const shown = view.state === "shown";
  const signed = kind === "signed";

  return (
    <div
      className="gf"
      data-state={view.state}
      data-shown={shownNow || undefined}
    >
      <style>{CSS}</style>
      <header className="gf-head">
        <span className="gf-badge" data-tone={badgeTone(view, signed)}>
          {badgeIcon(view, signed)}
        </span>
        <div className="gf-title">
          <span className="gf-name">{title(view, signed)}</span>
          {shown && (
            <span className="gf-sub">
              {signerLine(view.signature, view.signer)}
            </span>
          )}
          {view.state === "failed" && (
            <span className="gf-sub">{failureLine(view.reason)}</span>
          )}
          {view.state === "locked" && (
            <span className="gf-sub">{t("gmail_frame_locked_sub")}</span>
          )}
          {openNote && (
            <span className="gf-sub gf-warn" role="status" title={openNote}>
              {openNote}
            </span>
          )}
        </div>
        <div className="gf-actions">
          {shown && !signed && (
            <button
              type="button"
              className="gf-btn gf-primary"
              onClick={() =>
                post({ type: "pgp-frame:reply", nonce: nonceRef.current })
              }
              title={t("gmail_frame_reply_tooltip")}
            >
              <ReplyIcon size={16} aria-hidden="true" />
              {t("gmail_frame_reply")}
            </button>
          )}
          {view.state === "locked" && (
            <button
              type="button"
              className="gf-btn gf-primary"
              onClick={() => void openInPanel()}
              disabled={opening}
            >
              <LockOpenIcon size={16} aria-hidden="true" />
              {opening ? t("gmail_opening") : t("gmail_frame_unlock")}
            </button>
          )}
          {(shown || view.state === "failed") && (
            <button
              type="button"
              className="gf-btn"
              onClick={() => void openInPanel()}
              disabled={opening}
              title={t("gmail_frame_open_tooltip")}
            >
              <ExternalLinkIcon size={15} aria-hidden="true" />
              {opening ? t("gmail_opening") : t("gmail_frame_open")}
            </button>
          )}
        </div>
      </header>
      {/* Always mounted, so the text has a node to go into; hidden (and
          emptied) whenever there is nothing to show. */}
      <pre
        ref={textRef}
        tabIndex={shown ? 0 : -1}
        className="gf-text"
        hidden={!shown}
        aria-label={t("gmail_frame_text_label")}
      />
      {shown && (
        <footer className="gf-foot">
          <button type="button" className="gf-link" onClick={toggleOriginal}>
            {showOriginal
              ? t("gmail_frame_hide_original")
              : t("gmail_frame_show_original")}
          </button>
        </footer>
      )}
      {view.state === "unavailable" && (
        <p className="gf-sub gf-pad">{t("gmail_frame_unavailable")}</p>
      )}
    </div>
  );
}

function badgeTone(view: View, signed: boolean): "ok" | "warn" | "muted" {
  if (view.state === "shown") {
    if (view.signature === "valid") return "ok";
    if (view.signature === "unknown") return "warn";
    return signed ? "warn" : "ok";
  }
  if (view.state === "failed") return "warn";
  return "muted";
}

function badgeIcon(view: View, signed: boolean) {
  const size = 18;
  if (view.state === "shown") {
    if (view.signature === "valid") {
      return <ShieldCheckIcon size={size} aria-hidden="true" />;
    }
    if (view.signature === "unknown") {
      return <ShieldQuestionIcon size={size} aria-hidden="true" />;
    }
    return signed ? (
      <ShieldAlertIcon size={size} aria-hidden="true" />
    ) : (
      <LockOpenIcon size={size} aria-hidden="true" />
    );
  }
  if (view.state === "failed") {
    return <TriangleAlertIcon size={size} aria-hidden="true" />;
  }
  return signed ? (
    <ShieldCheckIcon size={size} aria-hidden="true" />
  ) : (
    <LockIcon size={size} aria-hidden="true" />
  );
}

function title(view: View, signed: boolean): string {
  switch (view.state) {
    case "waiting":
      return signed ? t("gmail_frame_verifying") : t("gmail_frame_decrypting");
    case "shown":
      return signed ? t("gmail_frame_signed") : t("gmail_frame_decrypted");
    case "locked":
      return signed ? t("gmail_banner_signed_title") : t("gmail_frame_locked");
    case "failed":
      return signed ? t("gmail_banner_signed_title") : t("gmail_frame_failed");
    case "unavailable":
      return t("gmail_frame_title");
  }
}

function signerLine(
  signature: GmailFrameSignature,
  signer: GmailFrameSigner | null,
): string {
  if (signature === "unsigned") return t("gmail_frame_unsigned");
  if (signature === "unknown") return t("gmail_frame_signer_unknown");
  const uid = signer?.userIds[0];
  const name = uid
    ? formatKeyDisplayName(uid).name
    : (signer?.keyId.slice(-8) ?? "");
  return t("gmail_frame_signed_by", { name });
}

function failureLine(reason: GmailFrameFailure): string {
  switch (reason) {
    case "no-key":
      return t("gmail_frame_fail_no_key");
    case "password":
      return t("gmail_frame_fail_password");
    case "bad-signature":
      return t("gmail_frame_fail_bad_signature");
    case "error":
      return t("gmail_frame_fail_error");
  }
}

const BRAND = "#188038";

/** Colours come from the Gmail message the frame sits in (`--gf-fg`,
 *  `--gf-bg`), so it reads as part of the email on every theme; every
 *  tint is a mix of those two. Google Sans / Roboto to match. */
const CSS = `
:root { --gf-fg: #1f1f1f; --gf-bg: #fff; }
html, body { margin: 0; background: var(--gf-bg); color: var(--gf-fg); }
body {
  font-family: "Google Sans", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 14px; line-height: 20px;
  -webkit-font-smoothing: antialiased;
}
.gf {
  border-radius: 12px;
  border: 1px solid color-mix(in srgb, var(--gf-fg) 14%, transparent);
  background: color-mix(in srgb, ${BRAND} 5%, var(--gf-bg));
  overflow: hidden;
}
.gf[data-state="failed"] { background: color-mix(in srgb, #f9ab00 8%, var(--gf-bg)); }
.gf-head {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 10px 10px 12px;
}
/* Every state but "shown" fits the host's resting height exactly, so
   the frame's size says nothing about which state it is in. */
.gf:not([data-shown]) { height: 56px; }
.gf:not([data-shown]) .gf-head { height: 56px; box-sizing: border-box; }
.gf:not([data-shown]) .gf-title { max-height: 36px; overflow: hidden; }
.gf-sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.gf-badge {
  flex: none; width: 36px; height: 36px; border-radius: 50%;
  display: grid; place-items: center;
  color: color-mix(in srgb, ${BRAND} 75%, var(--gf-fg));
  background: color-mix(in srgb, ${BRAND} 14%, transparent);
}
.gf-badge[data-tone="warn"] {
  color: #b06000;
  background: color-mix(in srgb, #f9ab00 22%, transparent);
}
.gf-badge[data-tone="muted"] {
  color: color-mix(in srgb, var(--gf-fg) 70%, transparent);
  background: color-mix(in srgb, var(--gf-fg) 8%, transparent);
}
.gf-title { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.gf-name { font-weight: 500; letter-spacing: .1px; }
.gf-sub { font-size: 12px; line-height: 16px; opacity: .72; }
.gf-warn { opacity: 1; color: #b06000; }
.gf-pad { padding: 0 12px 12px 60px; margin: 0; }
.gf-actions { display: flex; gap: 8px; flex: none; }
.gf-btn {
  font: inherit; font-size: 14px; font-weight: 500; letter-spacing: .25px;
  color: inherit; cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px; white-space: nowrap;
  height: 36px; padding: 0 16px 0 12px; border-radius: 18px;
  border: 1px solid color-mix(in srgb, var(--gf-fg) 28%, transparent);
  background: transparent;
  transition: background-color .15s, box-shadow .15s, border-color .15s;
}
.gf-btn:hover:not([disabled]) {
  border-color: ${BRAND};
  background: color-mix(in srgb, ${BRAND} 8%, transparent);
}
.gf-btn[disabled] { cursor: default; opacity: .75; }
.gf-btn:focus-visible { outline: 2px solid ${BRAND}; outline-offset: 2px; }
.gf-primary { border: none; background: ${BRAND}; color: #fff; }
.gf-primary:hover:not([disabled]) {
  background: #137333;
  box-shadow: 0 1px 2px rgba(0,0,0,.3), 0 1px 3px 1px rgba(0,0,0,.15);
}
.gf-text {
  margin: 0; padding: 12px 16px 14px 60px;
  font: 13px/20px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap; overflow-wrap: anywhere;
  border-top: 1px solid color-mix(in srgb, var(--gf-fg) 10%, transparent);
  background: var(--gf-bg);
}
.gf-text:focus { outline: none; }
.gf-foot {
  padding: 6px 12px 8px 60px;
  background: var(--gf-bg);
}
.gf-link {
  font: inherit; font-size: 12px; color: inherit; opacity: .72;
  background: none; border: 0; padding: 0; cursor: pointer;
}
.gf-link:hover { opacity: 1; text-decoration: underline; }
@media (max-width: 560px) {
  .gf-head { flex-wrap: wrap; }
  .gf-actions { margin-left: 48px; }
  .gf-text, .gf-foot, .gf-pad { padding-left: 16px; }
}
@media (prefers-reduced-motion: reduce) { .gf-btn { transition: none; } }
`;
