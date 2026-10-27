// Where the "Open in PGP Tools" context menu may act. The menu itself is
// created in entrypoints/background.ts; this is the pure half, kept apart
// so the rule is unit-testable.
//
// Why it matters: the click handler writes the selection UNSEALED to
// chrome.storage.session (see `openPanelWithOperation`). That is fine for
// a web page's text, which the page already has. It is not fine for the
// extension's own pages: the reader tab shows decrypted plaintext, and
// selecting it there and choosing the menu would put that plaintext in
// session storage, which T-READER-TAB-PLAINTEXT promises never happens.
//
// WHY THE RULE IS APPLIED AT CLICK TIME, not with `documentUrlPatterns`:
// Chrome matches `documentUrlPatterns` against the URL of the FRAME the
// menu opened in (`MenuItemMatchesParams` in Chromium's
// chrome/browser/extensions/context_menu_helpers.cc compares
// `params.frame_url`, the frame's last committed URL). For an
// `about:blank` or `about:srcdoc` iframe that is literally "about:blank"
// / "about:srcdoc" -- not the parent's URL, whatever origin the frame
// inherits -- and no match pattern can name the `about:` scheme. Webmail
// composers and readers put the message body in exactly such frames, so
// with the patterns set the menu was missing on the very selections it
// exists for. So the item is created without them (shown everywhere) and
// `menuMayActOn` decides on each click, from the TOP page's URL.
//
// The cost: the item now also appears on the extension's own pages (the
// panel, the reader tab), where choosing it does nothing.

/** The pages the menu acts on, as Chrome match patterns: web and file
 *  pages, never chrome-extension:// ones. Matched by `menuMayActOn`
 *  against the TOP page's URL (`info.pageUrl`). */
export const MENU_DOCUMENT_URL_PATTERNS = [
  "http://*/*",
  "https://*/*",
  "file:///*",
];

/** Each pattern's fixed prefix ("http://", "file:///"): every pattern
 *  above is "<scheme>://<any host>/<any path>", so a prefix match is the
 *  whole match. */
const PAGE_PREFIXES = MENU_DOCUMENT_URL_PATTERNS.map((p) =>
  p.slice(0, p.indexOf("*")),
);

/** A frame with no URL of its own: it shows content its parent wrote. */
const INHERITING_FRAME = /^about:(?:blank|srcdoc)(?:[?#]|$)/;

function isWebOrFile(url: string | undefined): boolean {
  return url !== undefined && PAGE_PREFIXES.some((p) => url.startsWith(p));
}

/** True when a click came from one of the extension's own pages (or a
 *  frame of one). `extensionOrigin` is `chrome.runtime.getURL("")`. */
export function isOwnExtensionPage(
  info: { pageUrl?: string; frameUrl?: string },
  extensionOrigin: string,
): boolean {
  return [info.pageUrl, info.frameUrl].some(
    (url) => url?.startsWith(extensionOrigin) === true,
  );
}

/**
 * Whether a menu click may act on its selection: the top page is a web
 * or file page, neither it nor the frame is one of the extension's own,
 * and the frame (if the click was in one) is a web or file document too
 * or an about:blank / about:srcdoc frame inside the page. Anything else
 * -- no page URL, a data: frame, another extension -- is ignored.
 */
export function menuMayActOn(
  info: { pageUrl?: string; frameUrl?: string },
  extensionOrigin: string,
): boolean {
  if (isOwnExtensionPage(info, extensionOrigin)) return false;
  if (!isWebOrFile(info.pageUrl)) return false;
  const frame = info.frameUrl;
  return (
    frame === undefined || isWebOrFile(frame) || INHERITING_FRAME.test(frame)
  );
}
