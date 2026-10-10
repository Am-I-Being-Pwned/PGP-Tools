/**
 * What the Gmail add-on draws into Gmail: an inline reader frame where
 * an encrypted or signed block was rendered (an extension page, so its
 * contents are Gmail's to place but not to read), a banner above a
 * public key or a clipped block, a button on an encrypted attachment,
 * and an Encrypt button beside Send.
 *
 * DESIGN. Both should read as part of Gmail rather than as a sticker on
 * it: Gmail's own type (Google Sans / Roboto), its pill buttons, its 8px
 * rhythm, and -- the part that makes them survive every Gmail theme --
 * colour taken from Gmail rather than set over it. The shadow host
 * inherits Gmail's text colour (`color: inherit` after the `all:
 * initial` reset), and every tint is a `color-mix` of `currentColor`, so
 * the same CSS is right on the white default, the dark theme and a photo
 * theme. The one fixed colour is the brand green on the action itself.
 *
 * ISOLATION. Each piece lives in a CLOSED shadow root: Gmail's CSS cannot
 * restyle it, and Gmail's scripts cannot reach in to read state or click
 * the button (the handler also refuses untrusted events). Mailvelope
 * uses open roots, which leaks its frame ids to the page; closed costs
 * nothing here because nothing in the page needs to see in.
 *
 * Nothing secret is ever rendered here. The banner shows fixed copy from
 * the locale bundle; text from the page is never echoed back into it.
 */

import { t } from "../i18n";
import { UI_ATTR } from "./dom";

/** Icon geometry (Lucide), as element + attributes rather than markup:
 *  Gmail enforces Trusted Types, under which an `innerHTML` write throws,
 *  so nothing in the add-on parses HTML at all. */
type Shape = [tag: "path" | "rect" | "circle", attrs: Record<string, string>];

const ICONS = {
  lock: [
    ["rect", { x: "4", y: "11", width: "16", height: "10", rx: "2" }],
    ["path", { d: "M8 11V7a4 4 0 0 1 8 0v4" }],
  ],
  shield: [
    [
      "path",
      {
        d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
      },
    ],
    ["path", { d: "m9 12 2 2 4-4" }],
  ],
  key: [
    [
      "path",
      {
        d: "M2.6 17.4A2 2 0 0 0 2 18.8V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.2a2 2 0 0 0 1.4-.6l.8-.8a6.5 6.5 0 1 0-4-4z",
      },
    ],
    ["circle", { cx: "16.5", cy: "7.5", r: "1" }],
  ],
  panel: [
    ["rect", { x: "3", y: "3", width: "18", height: "18", rx: "2" }],
    ["path", { d: "M15 3v18" }],
  ],
  expand: [
    ["path", { d: "M15 3h6v6" }],
    ["path", { d: "M10 14 21 3" }],
    ["path", { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" }],
  ],
  check: [["path", { d: "M20 6 9 17l-5-5" }]],
  alert: [
    ["circle", { cx: "12", cy: "12", r: "10" }],
    ["path", { d: "M12 8v4" }],
    ["path", { d: "M12 16h.01" }],
  ],
} satisfies Record<string, Shape[]>;

type IconName = keyof typeof ICONS;

const SVG_NS = "http://www.w3.org/2000/svg";

function icon(name: IconName, size = 18): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [k, v] of Object.entries({
    viewBox: "0 0 24 24",
    width: String(size),
    height: String(size),
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "2",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  })) {
    svg.setAttribute(k, v);
  }
  for (const [tag, attrs] of ICONS[name] as Shape[]) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.appendChild(el);
  }
  return svg;
}

function spinner(): HTMLElement {
  const el = document.createElement("span");
  el.className = "spin";
  return el;
}

const BRAND = "#188038";
/** Brand green pulled toward the inherited text colour: unchanged
 *  enough on white, lifted on a dark theme where pure #188038 sinks. */
const BRAND_INK = `color-mix(in srgb, ${BRAND} 75%, currentColor)`;
const BRAND_HOVER = "#137333";

const BASE_CSS = `
:host {
  all: initial;
  color: inherit;
  font-family: "Google Sans", Roboto, "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
* { box-sizing: border-box; }
button {
  font: inherit;
  color: inherit;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  border-radius: 18px;
  transition: background-color .15s, box-shadow .15s, border-color .15s;
}
button:focus-visible { outline: 2px solid ${BRAND}; outline-offset: 2px; }
button[disabled] { cursor: default; }
.spin {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid currentColor; border-right-color: transparent;
  animation: spin .8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .spin { animation: none; border-right-color: currentColor; opacity: .6; }
  button { transition: none; }
}
`;

function mount(
  tag: string,
  css: string,
): { host: HTMLElement; root: ShadowRoot } {
  const host = document.createElement(tag);
  host.setAttribute(UI_ATTR, "");
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = BASE_CSS + css;
  root.appendChild(style);
  return { host, root };
}

/** Run `fn` only for a real user click. Gmail's own scripts (or anything
 *  injected into the page) can dispatch synthetic clicks at our host;
 *  they come through with `isTrusted === false` and are dropped. */
function onTrustedClick(el: HTMLElement, fn: () => void): void {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!e.isTrusted) return;
    fn();
  });
}

// ── message banner ────────────────────────────────────────────────────

export type BannerKind = "message" | "signed" | "public-key" | "clipped";

export type BannerNotice =
  "opened" | "panel-failed" | "not-enabled" | "invalid" | "orphaned";

const BANNER_CSS = `
:host { display: block; max-width: 720px; margin: 4px 0 16px; }
.bar {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 10px 10px 12px;
  border-radius: 12px;
  border: 1px solid color-mix(in srgb, currentColor 14%, transparent);
  background: color-mix(in srgb, ${BRAND} 6%, transparent);
}
.badge {
  flex: none; width: 36px; height: 36px; border-radius: 50%;
  display: grid; place-items: center;
  color: ${BRAND_INK};
  background: color-mix(in srgb, ${BRAND} 14%, transparent);
}
.bar[data-tone="warn"] .badge {
  color: #b06000;
  background: color-mix(in srgb, #f9ab00 22%, transparent);
}
.text { flex: 1; min-width: 0; }
.title { font-size: 14px; line-height: 20px; font-weight: 500; letter-spacing: .1px; }
.sub { font-size: 12px; line-height: 16px; opacity: .72; margin-top: 1px; }
.sub[hidden] { display: none; }
.act {
  flex: none; height: 36px; padding: 0 16px 0 12px;
  border: none; background: ${BRAND}; color: #fff;
  font-size: 14px; font-weight: 500; letter-spacing: .25px;
}
.act:hover:not([disabled]) {
  background: ${BRAND_HOVER};
  box-shadow: 0 1px 2px rgba(0,0,0,.3), 0 1px 3px 1px rgba(0,0,0,.15);
}
.act[disabled] { opacity: .75; }
@media (max-width: 560px) {
  .bar { flex-wrap: wrap; }
  .act { margin-left: 48px; }
}
`;

const BANNER_COPY: Record<
  BannerKind,
  {
    icon: IconName;
    title: () => string;
    action: () => string;
    actionIcon: IconName;
  }
> = {
  message: {
    icon: "lock",
    title: () => t("gmail_banner_message_title"),
    action: () => t("gmail_banner_message_action"),
    actionIcon: "panel",
  },
  signed: {
    icon: "shield",
    title: () => t("gmail_banner_signed_title"),
    action: () => t("gmail_banner_signed_action"),
    actionIcon: "panel",
  },
  "public-key": {
    icon: "key",
    title: () => t("gmail_banner_key_title"),
    action: () => t("gmail_banner_key_action"),
    actionIcon: "panel",
  },
  clipped: {
    icon: "lock",
    title: () => t("gmail_banner_clipped_title"),
    action: () => t("gmail_banner_clipped_action"),
    actionIcon: "expand",
  },
};

const NOTICE_COPY: Record<BannerNotice, () => string> = {
  opened: () => t("gmail_notice_opened"),
  "panel-failed": () => t("gmail_notice_panel_failed"),
  "not-enabled": () => t("gmail_notice_not_enabled"),
  invalid: () => t("gmail_notice_invalid"),
  orphaned: () => t("gmail_notice_orphaned"),
};

export interface Banner {
  host: HTMLElement;
  kind: BannerKind;
  setBusy(busy: boolean): void;
  /** Swap the subtitle for a notice; `null` restores the default. */
  notify(notice: BannerNotice | null): void;
}

export function createBanner(kind: BannerKind, onAction: () => void): Banner {
  const { host, root } = mount("pgp-tools-banner", BANNER_CSS);
  const copy = BANNER_COPY[kind];

  const bar = document.createElement("div");
  bar.className = "bar";
  bar.setAttribute("role", "group");
  bar.setAttribute("aria-label", copy.title());

  const badge = document.createElement("div");
  badge.className = "badge";
  badge.replaceChildren(icon(copy.icon, 20));

  const text = document.createElement("div");
  text.className = "text";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = copy.title();
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.setAttribute("aria-live", "polite");
  text.append(title, sub);

  const act = document.createElement("button");
  act.type = "button";
  act.className = "act";

  // No subtitle by default -- the title and the button say it. The line
  // only appears to carry a notice (opened, or what went wrong).
  const renderSub = (notice: BannerNotice | null) => {
    sub.hidden = notice === null;
    sub.textContent = notice === null ? "" : NOTICE_COPY[notice]();
    const warn = notice !== null && notice !== "opened";
    if (warn) bar.setAttribute("data-tone", "warn");
    else bar.removeAttribute("data-tone");
    badge.replaceChildren(
      icon(notice === null ? copy.icon : warn ? "alert" : "check", 20),
    );
  };

  const renderAct = (busy: boolean) => {
    act.disabled = busy;
    const label = document.createElement("span");
    label.textContent = busy ? t("gmail_opening") : copy.action();
    act.replaceChildren(busy ? spinner() : icon(copy.actionIcon), label);
  };

  renderSub(null);
  renderAct(false);
  onTrustedClick(act, onAction);
  bar.append(badge, text, act);
  root.appendChild(bar);

  let resetTimer: ReturnType<typeof setTimeout> | undefined;
  return {
    host,
    kind,
    setBusy: renderAct,
    notify(notice) {
      clearTimeout(resetTimer);
      renderSub(notice);
      // A success note fades back to the default after a moment; a
      // problem stays until the next click, because it asks for action.
      if (notice === "opened") {
        resetTimer = setTimeout(() => renderSub(null), 4000);
      }
    },
  };
}

// ── compose button ────────────────────────────────────────────────────

/** The compose pill: encryption is off (Gmail's box, Gmail's rules), on
 *  (the body is covered; the panel is the composer), being turned on,
 *  or the ciphertext is in and the message is on its way. */
export type ComposeState = "off" | "busy" | "on" | "done";

const COMPOSE_CSS = `
:host { display: inline-flex; vertical-align: middle; position: relative; margin: 0 8px; }
.enc {
  height: 36px; padding: 0 14px 0 10px;
  border: 1px solid color-mix(in srgb, currentColor 28%, transparent);
  background: transparent;
  font-size: 14px; font-weight: 500; letter-spacing: .25px;
}
.enc svg { color: ${BRAND_INK}; }
.enc:hover:not([disabled]) {
  border-color: ${BRAND};
  background: color-mix(in srgb, ${BRAND} 8%, transparent);
}
.enc[data-state="on"], .enc[data-state="done"] {
  border-color: transparent;
  background: color-mix(in srgb, ${BRAND} 16%, transparent);
  color: ${BRAND_INK};
}
.enc[data-state="on"] svg, .enc[data-state="done"] svg { color: inherit; }
.tip {
  position: absolute; bottom: calc(100% + 8px); left: 0;
  width: max-content; max-width: 280px;
  padding: 8px 12px; border-radius: 8px;
  font-size: 12px; line-height: 16px;
  color: #fff; background: #3c4043;
  box-shadow: 0 1px 3px rgba(0,0,0,.3), 0 4px 8px 3px rgba(0,0,0,.15);
  z-index: 1;
}
.tip[hidden] { display: none; }
`;

export interface ComposeButton {
  host: HTMLElement;
  state: ComposeState;
  setState(state: ComposeState): void;
  /** A short-lived bubble above the button; `null` hides it. */
  notify(notice: BannerNotice | null): void;
}

/** The lock pill beside Send. A toggle: off <-> on. */
export function createComposeButton(onToggle: () => void): ComposeButton {
  const { host, root } = mount("pgp-tools-compose", COMPOSE_CSS);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "enc";
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  tip.setAttribute("role", "status");

  const out: ComposeButton = {
    host,
    state: "off",
    setState,
    notify,
  };

  function setState(state: ComposeState) {
    out.state = state;
    btn.dataset.state = state;
    btn.disabled = state === "busy" || state === "done";
    btn.setAttribute(
      "aria-pressed",
      String(state === "on" || state === "done"),
    );
    btn.title =
      state === "on"
        ? t("gmail_compose_tooltip_on")
        : t("gmail_compose_tooltip_off");
    const label = document.createElement("span");
    label.textContent =
      state === "busy"
        ? t("gmail_opening")
        : state === "on"
          ? t("gmail_compose_on")
          : state === "done"
            ? t("gmail_compose_done")
            : t("gmail_compose_action");
    btn.replaceChildren(
      state === "busy" ? spinner() : icon(state === "done" ? "check" : "lock"),
      label,
    );
  }

  let hideTimer: ReturnType<typeof setTimeout> | undefined;
  function notify(notice: BannerNotice | null) {
    clearTimeout(hideTimer);
    if (notice === null) {
      tip.hidden = true;
      return;
    }
    tip.textContent =
      notice === "opened" ? t("gmail_compose_opened") : NOTICE_COPY[notice]();
    tip.hidden = false;
    hideTimer = setTimeout(() => (tip.hidden = true), 6000);
  }

  setState("off");
  onTrustedClick(btn, onToggle);
  root.append(tip, btn);
  return out;
}

// ── compose cover ─────────────────────────────────────────────────────

const COVER_CSS = `
:host { display: block; }
.card {
  display: flex; align-items: center; gap: 14px;
  min-height: 140px; padding: 16px 16px 16px 20px; margin: 8px 12px 4px;
  border-radius: 12px;
  border: 1px dashed color-mix(in srgb, ${BRAND} 45%, transparent);
  background: color-mix(in srgb, ${BRAND} 5%, transparent);
}
.badge {
  flex: none; width: 40px; height: 40px; border-radius: 50%;
  display: grid; place-items: center;
  color: ${BRAND_INK};
  background: color-mix(in srgb, ${BRAND} 14%, transparent);
}
.text { flex: 1; min-width: 0; }
.title { font-size: 15px; line-height: 22px; font-weight: 500; }
.sub { font-size: 12px; line-height: 16px; opacity: .72; margin-top: 2px; }
.act {
  flex: none; height: 36px; padding: 0 16px 0 12px;
  border: none; background: ${BRAND}; color: #fff;
  font-size: 14px; font-weight: 500; letter-spacing: .25px;
}
.act:hover:not([disabled]) { background: ${BRAND_HOVER}; }
.card[data-tone="drop"] { border-style: solid; background: color-mix(in srgb, ${BRAND} 12%, transparent); }
@media (max-width: 560px) { .card { flex-wrap: wrap; } }
`;

export interface Cover {
  host: HTMLElement;
  /** Flash the "drop files on the panel" note (a file was dropped here). */
  droppedHere(): void;
}

/**
 * What stands where Gmail's compose body was while the window is
 * encrypted: a card that says the message is written in the side panel,
 * with the one button that opens it. It takes no text -- the whole point
 * is that nothing typed into this page can be the message -- and it
 * swallows drops, so a file cannot be attached in the clear underneath.
 */
export function createCover(onOpen: () => void): Cover {
  const { host, root } = mount("pgp-tools-cover", COVER_CSS);
  const card = document.createElement("div");
  card.className = "card";
  card.setAttribute("role", "group");
  card.setAttribute("aria-label", t("gmail_cover_title"));
  const badge = document.createElement("div");
  badge.className = "badge";
  badge.replaceChildren(icon("lock", 22));
  const text = document.createElement("div");
  text.className = "text";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = t("gmail_cover_title");
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = t("gmail_cover_sub");
  text.append(title, sub);
  const act = document.createElement("button");
  act.type = "button";
  act.className = "act";
  act.replaceChildren(icon("panel"), document.createTextNode(""));
  const label = document.createElement("span");
  label.textContent = t("gmail_cover_action");
  act.replaceChildren(icon("panel"), label);
  onTrustedClick(act, onOpen);
  card.append(badge, text, act);
  root.appendChild(card);

  let timer: ReturnType<typeof setTimeout> | undefined;
  return {
    host,
    droppedHere() {
      clearTimeout(timer);
      card.setAttribute("data-tone", "drop");
      sub.textContent = t("gmail_cover_dropped");
      timer = setTimeout(() => {
        card.removeAttribute("data-tone");
        sub.textContent = t("gmail_cover_sub");
      }, 4000);
    },
  };
}

// ── inline reader frame ───────────────────────────────────────────────

const FRAME_CSS = `
:host { display: block; margin: 4px 0 16px; }
iframe {
  display: block; width: 100%; border: 0; height: 56px;
  border-radius: 12px;
  transition: height .15s ease-out;
  color-scheme: normal;
}
@media (prefers-reduced-motion: reduce) { iframe { transition: none; } }
`;

export interface Frame {
  host: HTMLElement;
  frame: HTMLIFrameElement;
  nonce: string;
  setHeight(px: number): void;
}

/**
 * The host for one inline reader frame. The iframe itself is the
 * extension's `gmail-frame.html`; its document is cross-origin to Gmail
 * and so opaque to it. The nonce in the URL hash is what the frame and
 * the content script use to recognise each other's `postMessage`s.
 */
export function createFrame(nonce: string, src: string): Frame {
  const { host, root } = mount("pgp-tools-frame", FRAME_CSS);
  const frame = document.createElement("iframe");
  frame.src = src;
  frame.title = t("gmail_frame_title");
  // No permissions delegated: the frame needs none, and a WebAuthn
  // ceremony in particular is deliberately NOT available here (it runs
  // in the side panel, which the frame opens).
  frame.setAttribute("allow", "");
  frame.setAttribute("referrerpolicy", "no-referrer");
  root.appendChild(frame);
  return {
    host,
    frame,
    nonce,
    /** `0` restores the resting height every non-showing state has. */
    setHeight(px) {
      frame.style.height =
        px <= 0 ? "" : `${Math.max(56, Math.min(px, 100_000))}px`;
    },
  };
}

// ── attachment button ─────────────────────────────────────────────────

const ATTACH_CSS = `
:host { display: inline-flex; vertical-align: middle; margin: 4px 8px 4px 0; }
.att {
  height: 32px; padding: 0 14px 0 10px;
  border: 1px solid color-mix(in srgb, currentColor 28%, transparent);
  background: color-mix(in srgb, ${BRAND} 6%, transparent);
  font-size: 13px; font-weight: 500; letter-spacing: .25px;
  border-radius: 16px;
}
.att svg { color: ${BRAND_INK}; }
.att:hover:not([disabled]) {
  border-color: ${BRAND};
  background: color-mix(in srgb, ${BRAND} 12%, transparent);
}
.note {
  font-size: 12px; line-height: 16px; opacity: .8;
  margin-left: 8px; align-self: center;
}
.note[hidden] { display: none; }
`;

export interface AttachmentButton {
  host: HTMLElement;
  setBusy(busy: boolean): void;
  notify(notice: BannerNotice | null): void;
}

/** "Decrypt with PGP Tools" (or "Open in PGP Tools" for an `.asc`,
 *  which may be a key or a signature) next to an attachment chip. */
export function createAttachmentButton(
  name: string,
  onClick: () => void,
): AttachmentButton {
  const { host, root } = mount("pgp-tools-attachment", ATTACH_CSS);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "att";
  const armoredMaybe = /\.asc$/i.test(name);
  const label = armoredMaybe
    ? t("gmail_attachment_open")
    : t("gmail_attachment_decrypt");
  btn.title = t("gmail_attachment_tooltip", { name });
  const render = (busy: boolean) => {
    btn.disabled = busy;
    const span = document.createElement("span");
    span.textContent = busy ? t("gmail_opening") : label;
    btn.replaceChildren(busy ? spinner() : icon("lock", 16), span);
  };
  const note = document.createElement("span");
  note.className = "note";
  note.hidden = true;
  note.setAttribute("role", "status");
  render(false);
  onTrustedClick(btn, onClick);
  root.append(btn, note);
  let hideTimer: ReturnType<typeof setTimeout> | undefined;
  return {
    host,
    setBusy: render,
    notify(notice) {
      clearTimeout(hideTimer);
      note.hidden = notice === null;
      note.textContent = notice === null ? "" : NOTICE_COPY[notice]();
      if (notice === "opened") {
        hideTimer = setTimeout(() => (note.hidden = true), 4000);
      }
    },
  };
}
