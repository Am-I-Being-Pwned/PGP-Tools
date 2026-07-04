/** Browser download helpers shared by the workspace views. */

/** A named output produced by a per-file operation. */
export interface FileResult {
  name: string;
  data: Uint8Array;
}

export function downloadBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadText(text: string, name: string): void {
  downloadBlob(new Blob([text], { type: "text/plain" }), name);
}

export function downloadBinary(data: Uint8Array, name: string): void {
  // .slice() detaches from any WASM-backed view and satisfies BlobPart.
  downloadBlob(
    new Blob([data.slice()], { type: "application/octet-stream" }),
    name,
  );
}

export function downloadResults(results: FileResult[]): void {
  for (const r of results) {
    downloadBinary(r.data, r.name);
  }
}

const DOWNLOADS_PERMISSION: chrome.permissions.Permissions = {
  permissions: ["downloads"],
};

/** Prompt for the optional `downloads` permission (idempotent). Must be
 *  called from a user gesture. Returns whether it is now granted. */
async function requestDownloadsPermission(): Promise<boolean> {
  if (await chrome.permissions.contains(DOWNLOADS_PERMISSION)) return true;
  return chrome.permissions.request(DOWNLOADS_PERMISSION);
}

export type SaveResult =
  | "saved"
  | "cancelled"
  | "denied"
  | "unsupported"
  | "blocked";

/**
 * Save a signed `.crx` to disk via `chrome.downloads` with a "Save As"
 * prompt, and WITHOUT letting Chrome install it. This is subtle -- here is
 * exactly why it works, straight from the Chromium source:
 *
 *  - `.crx` bytes start with the magic `Cr24\x03...`. Chrome's MIME sniffer
 *    (net/base/mime_sniffer.cc, kCRXMagicNumbers) maps that magic to
 *    `application/x-chrome-extension` no matter what Content-Type we declare
 *    on the blob -- so a plain download of a CRX is seen as an extension.
 *  - The download manager installs a download when
 *    `extensions::util::IsExtensionDownload(item)` is true (chrome_download_
 *    manager_delegate.cc). That function (extensions/browser/extension_util.cc)
 *    returns true when the MIME is `application/x-chrome-extension` -- EXCEPT
 *    it early-returns `false` when the download's target disposition is
 *    `TARGET_DISPOSITION_PROMPT`, i.e. a "Save As" download.
 *
 * So `saveAs: true` is the one download path that lands a real `.crx` on
 * disk without Chrome trying to load it -- no rename, no "Keep" install trap.
 *
 * NB: do NOT swap this for the File System Access picker
 * (`showSaveFilePicker`). It needs no permission and also dodges the
 * installer, but it reliably CRASHES the extension side panel (tested twice).
 * The other installer-free path is dragging the chip to Finder, in the UI.
 *
 * Returns "saved", "cancelled" (user dismissed the Save As dialog), "denied"
 * (permission refused), "blocked" (Chrome refused to write), or "unsupported".
 */
export async function saveCrxViaPrompt(
  data: Uint8Array,
  filename: string,
): Promise<SaveResult> {
  if (!(await requestDownloadsPermission())) return "denied";
  // The namespace only exists once the optional permission is granted, so
  // the @types "always present" typing is a lie here -- guard at runtime.
  const downloads = (chrome as { downloads?: typeof chrome.downloads })
    .downloads;
  if (!downloads) return "unsupported";

  const url = URL.createObjectURL(
    new Blob([data.slice()], { type: "application/octet-stream" }),
  );
  const revoke = () => setTimeout(() => URL.revokeObjectURL(url), 60_000);

  let downloadId: number;
  try {
    // saveAs:true => TARGET_DISPOSITION_PROMPT => not treated as an install.
    downloadId = await downloads.download({ url, filename, saveAs: true });
  } catch (err) {
    revoke();
    // Dismissing the Save As dialog rejects with "canceled"/"Download canceled".
    return /cancel/i.test(String(err)) ? "cancelled" : "blocked";
  }

  try {
    return await waitForDownload(downloads, downloadId);
  } finally {
    revoke();
  }
}

/** Map an interrupted download to a user-facing result: only a genuine
 *  user cancel (USER_CANCELED / USER_SHUTDOWN) is "cancelled"; disk-full /
 *  file-blocked / AV interruptions surface as "blocked" so the UI offers
 *  the drag-out fallback instead of acting like the user changed their mind. */
function interruptResult(reason: string | undefined): SaveResult {
  return reason?.startsWith("USER_") ? "cancelled" : "blocked";
}

/** Resolve once the download reaches a terminal state. */
function waitForDownload(
  downloads: typeof chrome.downloads,
  id: number,
): Promise<SaveResult> {
  return new Promise((resolve) => {
    const settle = (result: SaveResult) => {
      downloads.onChanged.removeListener(onChanged);
      resolve(result);
    };
    const onChanged = (delta: chrome.downloads.DownloadDelta) => {
      if (delta.id !== id) return;
      if (delta.state?.current === "complete") settle("saved");
      else if (delta.state?.current === "interrupted")
        settle(interruptResult(delta.error?.current));
    };
    downloads.onChanged.addListener(onChanged);
    // If it already reached a decision before we attached the listener.
    downloads.search({ id }, (items) => {
      if (items.length === 0) return;
      const item = items[0];
      if (item.state === "complete") settle("saved");
      else if (item.state === "interrupted")
        settle(interruptResult(item.error));
    });
  });
}
