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
