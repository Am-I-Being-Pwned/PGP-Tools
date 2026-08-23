import { describe, expect, it } from "vitest";

import type { FileResult } from "../../lib/utils/download";
import { zeroizeResultBytes } from "./useWorkspaceState";

// `zeroizeResultBytes` is the part of `wipePlaintext` that covers the two
// pieces of decrypted content the hook is forced to keep in React render
// state: `binaryOutput` (a decrypted non-text payload) and `fileResults`
// (one entry per decrypted file). Both survive an unmount inside the
// previous fiber, so the wipe has to overwrite the bytes rather than drop
// the reference -- see the function's own comment, and
// e2e/draft-memory.spec.ts for the end-to-end proof.
describe("zeroizeResultBytes", () => {
  const bytesOf = (s: string) => new TextEncoder().encode(s);

  it("overwrites the binary result in place", () => {
    const secret = bytesOf("decrypted payload");
    // The SAME object the caller still holds must come back zeroed:
    // that is the whole point (a fresh empty array would leave the
    // retained one intact).
    zeroizeResultBytes(secret, []);
    expect(Array.from(secret).every((b) => b === 0)).toBe(true);
  });

  it("overwrites every multi-file result in place", () => {
    const results: FileResult[] = [
      { name: "a.txt", data: bytesOf("first decrypted file") },
      { name: "b.txt", data: bytesOf("second decrypted file") },
    ];
    zeroizeResultBytes(undefined, results);
    for (const r of results) {
      expect(Array.from(r.data).every((b) => b === 0)).toBe(true);
    }
    // Names are not secret (they are already on screen and in the
    // download UI), so they are deliberately left alone.
    expect(results.map((r) => r.name)).toEqual(["a.txt", "b.txt"]);
  });

  it("wipes only the view's own window of a shared buffer", () => {
    // Results are handed to us as views over wasm-marshalled memory; a
    // view must not scribble outside its own range.
    const backing = new Uint8Array(8).fill(0xff);
    zeroizeResultBytes(backing.subarray(2, 5), []);
    expect(Array.from(backing)).toEqual([255, 255, 0, 0, 0, 255, 255, 255]);
  });

  it("is a no-op for an absent binary result and an empty file list", () => {
    expect(() => zeroizeResultBytes(undefined, [])).not.toThrow();
  });

  it("tolerates a detached buffer instead of throwing", () => {
    // A detached view (its buffer transferred away) throws on write in
    // some engines and silently no-ops in others. Either way the wipe
    // must not abort -- it still has the remaining buffers to clear.
    const detached = new Uint8Array(4).fill(7);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const alsoSecret = bytesOf("still reachable");
    expect(() =>
      zeroizeResultBytes(detached, [{ name: "x", data: alsoSecret }]),
    ).not.toThrow();
    expect(Array.from(alsoSecret).every((b) => b === 0)).toBe(true);
  });
});
