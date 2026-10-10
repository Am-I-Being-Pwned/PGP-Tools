import { describe, expect, it } from "vitest";

import {
  GMAIL_FRAME_PAGE,
  GMAIL_FRAME_PORT_PREFIX,
  isGmailFrameChildMessage,
  isGmailFrameOpenRequest,
  isGmailFramePanelMessage,
  isGmailFrameParentMessage,
  isGmailFramePort,
  isGmailFrameReadRequest,
  MAX_FRAME_TEXT,
} from "./frame-protocol";

const NONCE = "0123456789abcdef0123456789abcdef";
const THEME = { color: "rgb(31, 31, 31)", background: "rgb(255, 255, 255)" };

describe("frame <-> parent", () => {
  it("accepts an armor message with a theme, and refuses the rest", () => {
    const ok = {
      type: "pgp-frame:armor",
      nonce: NONCE,
      kind: "message",
      text: "-----BEGIN PGP MESSAGE-----",
      theme: THEME,
    };
    expect(isGmailFrameParentMessage(ok)).toBe(true);
    expect(isGmailFrameParentMessage({ ...ok, kind: "signed" })).toBe(true);
    expect(isGmailFrameParentMessage({ ...ok, kind: "public-key" })).toBe(
      false,
    );
    expect(isGmailFrameParentMessage({ ...ok, nonce: "short" })).toBe(false);
    expect(
      isGmailFrameParentMessage({
        ...ok,
        text: "x".repeat(MAX_FRAME_TEXT + 1),
      }),
    ).toBe(false);
    // A theme is two CSS colours, not a stylesheet.
    expect(
      isGmailFrameParentMessage({
        ...ok,
        theme: { color: "red; } body { display:none", background: "#fff" },
      }),
    ).toBe(false);
    expect(isGmailFrameParentMessage({ ...ok, theme: { color: "#fff" } })).toBe(
      false,
    );
    // A colour function that could name a host is not a colour.
    expect(
      isGmailFrameParentMessage({
        ...ok,
        theme: { color: "red", background: "url(//evil.example/x)" },
      }),
    ).toBe(false);
    expect(
      isGmailFrameParentMessage({
        ...ok,
        theme: { color: "rgba(0, 0, 0, 0.5)", background: "#1f1f1f" },
      }),
    ).toBe(true);
    expect(isGmailFrameParentMessage(null)).toBe(false);
  });

  it("accepts size, state and fold reports from the frame", () => {
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:size",
        nonce: NONCE,
        height: 120,
      }),
    ).toBe(true);
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:size",
        nonce: NONCE,
        height: -1,
      }),
    ).toBe(false);
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:size",
        nonce: NONCE,
        height: Infinity,
      }),
    ).toBe(false);
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:state",
        nonce: NONCE,
        shown: true,
      }),
    ).toBe(true);
    // One bit, never the finer state: that would tell the page which
    // keys the user holds and when the vault is open.
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:state",
        nonce: NONCE,
        state: "locked",
      }),
    ).toBe(false);
    expect(
      isGmailFrameChildMessage({ type: "pgp-frame:ready", nonce: NONCE }),
    ).toBe(true);
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:fold",
        nonce: NONCE,
        fold: true,
      }),
    ).toBe(true);
    expect(
      isGmailFrameChildMessage({
        type: "pgp-frame:fold",
        nonce: NONCE,
        fold: "yes",
      }),
    ).toBe(false);
    expect(
      isGmailFrameChildMessage({ type: "pgp-frame:size", height: 1 }),
    ).toBe(false);
  });
});

describe("frame <-> panel", () => {
  it("a read carries a kind and non-empty text", () => {
    expect(
      isGmailFrameReadRequest({ type: "read", kind: "message", text: "a" }),
    ).toBe(true);
    expect(
      isGmailFrameReadRequest({ type: "read", kind: "message", text: "" }),
    ).toBe(false);
    expect(
      isGmailFrameReadRequest({ type: "read", kind: "key", text: "a" }),
    ).toBe(false);
  });

  it("the panel's answers are show / locked / failed with closed reasons", () => {
    expect(isGmailFramePanelMessage({ type: "locked" })).toBe(true);
    expect(isGmailFramePanelMessage({ type: "failed", reason: "no-key" })).toBe(
      true,
    );
    expect(isGmailFramePanelMessage({ type: "failed", reason: "oops" })).toBe(
      false,
    );
    expect(
      isGmailFramePanelMessage({
        type: "show",
        text: "hi",
        signature: "valid",
        signer: { keyId: "ABC", userIds: ["Alice <a@x.com>"] },
      }),
    ).toBe(true);
    expect(
      isGmailFramePanelMessage({
        type: "show",
        text: "hi",
        signature: "unsigned",
        signer: null,
      }),
    ).toBe(true);
    expect(
      isGmailFramePanelMessage({
        type: "show",
        text: "hi",
        signature: "maybe",
        signer: null,
      }),
    ).toBe(false);
    expect(
      isGmailFramePanelMessage({
        type: "show",
        text: "hi",
        signature: "valid",
        signer: { keyId: 1 },
      }),
    ).toBe(false);
  });

  it("an open request is non-empty, bounded text", () => {
    expect(
      isGmailFrameOpenRequest({ type: "GMAIL_FRAME_OPEN", text: "a" }),
    ).toBe(true);
    expect(
      isGmailFrameOpenRequest({ type: "GMAIL_FRAME_OPEN", text: "" }),
    ).toBe(false);
    expect(isGmailFrameOpenRequest({ type: "GMAIL_OPEN", text: "a" })).toBe(
      false,
    );
  });
});

describe("isGmailFramePort", () => {
  const runtime = {
    id: "ext",
    getURL: (p: string) => `chrome-extension://ext/${p}`,
  };
  const page = runtime.getURL(GMAIL_FRAME_PAGE);
  const sender = (over: Partial<chrome.runtime.MessageSender> = {}) =>
    ({
      id: "ext",
      url: `${page}#${NONCE}`,
      tab: { id: 3 } as chrome.tabs.Tab,
      frameId: 42,
      ...over,
    }) as chrome.runtime.MessageSender;

  it("accepts a port from our frame page inside a tab's subframe", () => {
    expect(
      isGmailFramePort(
        { name: GMAIL_FRAME_PORT_PREFIX + NONCE, sender: sender() },
        runtime,
      ),
    ).toBe(true);
    expect(
      isGmailFramePort(
        {
          name: GMAIL_FRAME_PORT_PREFIX + NONCE,
          sender: sender({ url: page }),
        },
        runtime,
      ),
    ).toBe(true);
  });

  it("refuses the wrong name, another extension, a top frame, no tab, or another page", () => {
    const name = GMAIL_FRAME_PORT_PREFIX + NONCE;
    expect(
      isGmailFramePort(
        { name: "pgp-reader:" + NONCE, sender: sender() },
        runtime,
      ),
    ).toBe(false);
    expect(
      isGmailFramePort(
        { name: GMAIL_FRAME_PORT_PREFIX + "x", sender: sender() },
        runtime,
      ),
    ).toBe(false);
    expect(
      isGmailFramePort({ name, sender: sender({ id: "other" }) }, runtime),
    ).toBe(false);
    expect(
      isGmailFramePort({ name, sender: sender({ frameId: 0 }) }, runtime),
    ).toBe(false);
    expect(
      isGmailFramePort({ name, sender: sender({ tab: undefined }) }, runtime),
    ).toBe(false);
    expect(
      isGmailFramePort(
        { name, sender: sender({ url: runtime.getURL("sidepanel.html") }) },
        runtime,
      ),
    ).toBe(false);
    expect(
      isGmailFramePort(
        { name, sender: sender({ url: `${page}.evil/x` }) },
        runtime,
      ),
    ).toBe(false);
    expect(isGmailFramePort({ name, sender: undefined }, runtime)).toBe(false);
  });
});
