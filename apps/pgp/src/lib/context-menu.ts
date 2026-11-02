// Where the context menu may act (pure half; the menu is in background.ts).
//
// The click writes the selection UNSEALED to session storage, so it must
// never act on the extension's own pages: the reader tab shows decrypted
// plaintext (T-READER-TAB-PLAINTEXT).
//
// Checked at click time, not via `documentUrlPatterns`: Chrome matches those
// against the FRAME URL, which is "about:blank"/"about:srcdoc" for webmail
// body frames and can't be named by a pattern. Cost: the item also shows
// (inert) on our own pages.

/** Matched by `menuMayActOn` against the TOP page's URL. */
export const MENU_DOCUMENT_URL_PATTERNS = [
  "http://*/*",
  "https://*/*",
  "file:///*",
];

/** Every pattern is "<scheme>://*", so a prefix match is the whole match. */
const PAGE_PREFIXES = MENU_DOCUMENT_URL_PATTERNS.map((p) =>
  p.slice(0, p.indexOf("*")),
);

const INHERITING_FRAME = /^about:(?:blank|srcdoc)(?:[?#]|$)/;

function isWebOrFile(url: string | undefined): boolean {
  return url !== undefined && PAGE_PREFIXES.some((p) => url.startsWith(p));
}

/** `extensionOrigin` is `chrome.runtime.getURL("")`. */
export function isOwnExtensionPage(
  info: { pageUrl?: string; frameUrl?: string },
  extensionOrigin: string,
): boolean {
  return [info.pageUrl, info.frameUrl].some(
    (url) => url?.startsWith(extensionOrigin) === true,
  );
}

/** Top page is web/file and not ours; frame (if any) is web/file or an
 *  about:blank/srcdoc child. Anything else is ignored. */
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
