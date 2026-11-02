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

/** Request the optional `downloads` permission. Without a user gesture
 *  `request` throws; treat that as "not granted" so the caller falls back
 *  to the manual Save button. */
async function requestDownloadsPermission(): Promise<boolean> {
  if (await chrome.permissions.contains(DOWNLOADS_PERMISSION)) return true;
  try {
    return await chrome.permissions.request(DOWNLOADS_PERMISSION);
  } catch {
    return false;
  }
}

export type SaveResult =
  "saved" | "cancelled" | "denied" | "unsupported" | "blocked";

/**
 * Save a signed `.crx` via `chrome.downloads` with a Save As prompt,
 * WITHOUT Chrome installing it. Chrome sniffs the `Cr24` magic as an
 * extension regardless of Content-Type, but `IsExtensionDownload` returns
 * false for `TARGET_DISPOSITION_PROMPT` -- so `saveAs: true` is the one
 * path that lands a real `.crx` on disk.
 *
 * Do NOT swap this for `showSaveFilePicker`: it crashes the side panel.
 */
export async function saveCrxViaPrompt(
  data: Uint8Array,
  filename: string,
): Promise<SaveResult> {
  if (!(await requestDownloadsPermission())) return "denied";
  // Only exists once the optional permission is granted.
  const downloads = (chrome as { downloads?: typeof chrome.downloads })
    .downloads;
  if (!downloads) return "unsupported";

  const url = URL.createObjectURL(
    new Blob([data.slice()], { type: "application/octet-stream" }),
  );
  const revoke = () => setTimeout(() => URL.revokeObjectURL(url), 60_000);

  let downloadId: number;
  try {
    // saveAs:true is what prevents the install (see above).
    downloadId = await downloads.download({ url, filename, saveAs: true });
  } catch (err) {
    revoke();
    return /cancel/i.test(String(err)) ? "cancelled" : "blocked";
  }

  try {
    return await waitForDownload(downloads, downloadId);
  } finally {
    revoke();
  }
}

/** Only USER_* is "cancelled"; anything else is "blocked" so the UI offers
 *  the drag-out fallback. */
function interruptResult(reason: string | undefined): SaveResult {
  return reason?.startsWith("USER_") ? "cancelled" : "blocked";
}

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
    // In case it finished before the listener attached.
    downloads.search({ id }, (items) => {
      if (items.length === 0) return;
      const item = items[0];
      if (item.state === "complete") settle("saved");
      else if (item.state === "interrupted")
        settle(interruptResult(item.error));
    });
  });
}
