import { describe, expect, it } from "vitest";

import {
  isOwnExtensionPage,
  MENU_DOCUMENT_URL_PATTERNS,
  menuMayActOn,
} from "./context-menu";

const ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

describe("context menu scope", () => {
  it("acts on web and file pages only", () => {
    expect(MENU_DOCUMENT_URL_PATTERNS).toEqual([
      "http://*/*",
      "https://*/*",
      "file:///*",
    ]);
    expect(
      MENU_DOCUMENT_URL_PATTERNS.some((p) => p.startsWith("chrome-extension")),
    ).toBe(false);
  });

  it("ignores a click on the reader tab", () => {
    expect(
      isOwnExtensionPage({ pageUrl: `${ORIGIN}reader.html#n=1` }, ORIGIN),
    ).toBe(true);
  });

  it("ignores a click in a frame of one of its own pages", () => {
    expect(
      isOwnExtensionPage(
        {
          pageUrl: "https://example.com/",
          frameUrl: `${ORIGIN}sidepanel.html`,
        },
        ORIGIN,
      ),
    ).toBe(true);
  });

  it("acts on an ordinary web page and on a page with no URL info", () => {
    expect(
      isOwnExtensionPage(
        { pageUrl: "https://mail.example.com/inbox", frameUrl: undefined },
        ORIGIN,
      ),
    ).toBe(false);
    expect(isOwnExtensionPage({}, ORIGIN)).toBe(false);
  });

  it("does not treat another extension's page as its own", () => {
    expect(
      isOwnExtensionPage(
        { pageUrl: "chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/x" },
        ORIGIN,
      ),
    ).toBe(false);
  });
});

describe("menuMayActOn", () => {
  const web = "https://mail.example.com/inbox";

  it.each([
    ["a web page", { pageUrl: web }],
    ["a web frame", { pageUrl: web, frameUrl: "https://cdn.example.net/x" }],
    // Webmail composers and readers: Chrome reports the frame's own URL,
    // which no documentUrlPatterns entry could match.
    ["an about:blank frame", { pageUrl: web, frameUrl: "about:blank" }],
    ["an about:srcdoc frame", { pageUrl: web, frameUrl: "about:srcdoc" }],
    ["a file page", { pageUrl: "file:///home/me/msg.asc" }],
    ["plain http", { pageUrl: "http://intranet.example/" }],
  ])("acts on %s", (_name, info) => {
    expect(menuMayActOn(info, ORIGIN)).toBe(true);
  });

  it.each([
    ["the reader tab", { pageUrl: `${ORIGIN}reader.html#n` }],
    [
      "an about:blank frame in the reader tab",
      { pageUrl: `${ORIGIN}reader.html#n`, frameUrl: "about:blank" },
    ],
    [
      "a frame of its own in a web page",
      { pageUrl: web, frameUrl: `${ORIGIN}sidepanel.html` },
    ],
    ["another extension", { pageUrl: "chrome-extension://zzzz/x" }],
    ["a page with no URL", {}],
    ["a data: frame", { pageUrl: web, frameUrl: "data:text/html,hi" }],
    ["a browser page", { pageUrl: "chrome://settings/" }],
    ["a lookalike scheme", { pageUrl: "https-evil:x" }],
  ])("ignores %s", (_name, info) => {
    expect(menuMayActOn(info, ORIGIN)).toBe(false);
  });
});
