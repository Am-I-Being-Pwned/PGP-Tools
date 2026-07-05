import type { Page } from "@playwright/test";

/**
 * Count occurrences of each needle among the strings retained in the V8
 * heap. Forces a GC, takes a heap snapshot via CDP, and searches the
 * streamed snapshot (whose JSON embeds every live string value).
 *
 * This is the check that matters for a WASM-isolated design: private key
 * material must live in WASM linear memory, never lingering in the
 * GC-managed JS heap. Use a needle unique to the secret (a base64 slice
 * of the key), not a generic marker like "BEGIN PGP PRIVATE KEY" -- that
 * appears as a code literal in the bundle and would false-positive.
 *
 * Newlines in a retained multi-line string are JSON-escaped in the
 * snapshot, so pass a single-line (newline-free) needle.
 */
export async function scanJsHeap(
  page: Page,
  needles: string[],
): Promise<Record<string, number>> {
  const client = await page.context().newCDPSession(page);
  await client.send("HeapProfiler.enable");
  await client.send("HeapProfiler.collectGarbage");

  let snapshot = "";
  const onChunk = (e: { chunk: string }) => {
    snapshot += e.chunk;
  };
  client.on("HeapProfiler.addHeapSnapshotChunk", onChunk);
  await client.send("HeapProfiler.takeHeapSnapshot", { reportProgress: false });
  client.off("HeapProfiler.addHeapSnapshotChunk", onChunk);
  await client.send("HeapProfiler.disable");

  const counts: Record<string, number> = {};
  for (const n of needles) {
    let count = 0;
    let idx = snapshot.indexOf(n);
    while (idx !== -1) {
      count++;
      idx = snapshot.indexOf(n, idx + 1);
    }
    counts[n] = count;
  }
  return counts;
}
