import type { Page } from "@playwright/test";

/**
 * Scan the extension's live WASM linear memory for UTF-8/ASCII needles,
 * returning the occurrence count of each.
 *
 * Works against the production build with no app hook: CDP `queryObjects`
 * finds every live `WebAssembly.Memory` (the wasm-bindgen module keeps one
 * alive), and we scan the largest one's buffer in-page, returning only the
 * counts. Used to check that sensitive material (e.g. a master password)
 * doesn't linger in memory after it should have been zeroized.
 */
export async function scanWasmMemory(
  page: Page,
  needles: string[],
): Promise<Record<string, number>> {
  const client = await page.context().newCDPSession(page);
  await client.send("Runtime.enable");

  const proto = await client.send("Runtime.evaluate", {
    expression: "WebAssembly.Memory.prototype",
  });
  const protoId = proto.result.objectId;
  if (!protoId) throw new Error("could not resolve WebAssembly.Memory");

  const objects = await client.send("Runtime.queryObjects", {
    prototypeObjectId: protoId,
  });
  const arrayId = objects.objects.objectId;
  if (!arrayId) throw new Error("no WebAssembly.Memory instances found");

  // `this` is the array of Memory instances. Pick the biggest buffer (the
  // wasm heap), build a Latin1 string, and count needles with native
  // indexOf -- far faster than a byte loop over ~64 MB.
  const scanFn = `function (needles) {
    let best = null;
    for (const m of this) {
      const b = m.buffer;
      if (b && (!best || b.byteLength > best.byteLength)) best = b;
    }
    if (!best) return null;
    const mem = new Uint8Array(best);
    let s = "";
    const CH = 32768;
    for (let i = 0; i < mem.length; i += CH) {
      s += String.fromCharCode.apply(null, mem.subarray(i, i + CH));
    }
    const counts = {};
    for (const n of needles) {
      let c = 0, idx = s.indexOf(n);
      while (idx !== -1) { c++; idx = s.indexOf(n, idx + 1); }
      counts[n] = c;
    }
    return counts;
  }`;

  const res = await client.send("Runtime.callFunctionOn", {
    objectId: arrayId,
    functionDeclaration: scanFn,
    arguments: [{ value: needles }],
    returnByValue: true,
  });

  const value = res.result.value as Record<string, number> | null;
  if (!value) throw new Error("no wasm memory buffer to scan");
  return value;
}
