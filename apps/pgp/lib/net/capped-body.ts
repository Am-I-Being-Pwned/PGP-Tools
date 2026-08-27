/**
 * Read at most `maxBytes + 1` bytes of a response body.
 *
 * `await response.text()` would buffer the WHOLE body first and only
 * then let us measure it -- the cap would be applied after the
 * allocation it exists to prevent, which is not what SECURITY.md and the
 * `T-*-UNTRUSTED-PARSE` entries say ("caps applied before parsing"). One
 * byte over the cap is enough for a parser to refuse, so we stop there
 * and drop the connection.
 *
 * The extra byte matters: stopping exactly AT the cap would make a
 * hostile 10 GB body indistinguishable from a legitimate 64 KiB one.
 *
 * ONE COPY, TWO CALLERS. The GitHub SSH-key lookup and the
 * keys.openpgp.org key lookup both read a body chosen by a remote party
 * in the service worker, and both make the same promise about it. A
 * second hand-rolled copy of this loop is free to drift from the one the
 * threat model quotes -- and the drift would be silent, because the
 * cap's whole job is to matter only on a body no test fixture has.
 */

/** What an over-cap body is reported as: one byte past the cap, which is
 *  all a caller's parser needs to refuse it. */
function overCap(maxBytes: number): string {
  return "x".repeat(maxBytes + 1);
}

export async function readCappedBody(
  response: Response,
  maxBytes: number,
): Promise<string> {
  // Content-Length is a hint, not a promise -- it can lie, be absent, or
  // be dropped by a chunked/compressed response. Believing it when it is
  // over the cap costs nothing; the reader below is what enforces.
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    void response.body?.cancel();
    // Over the cap either way; the parser only needs to see that.
    return overCap(maxBytes);
  }

  const body = response.body;
  // No stream to read (a body-less status, or a fetch implementation
  // without one): fall back, still slicing before the parse.
  if (!body) return (await response.text()).slice(0, maxBytes + 1);

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let read = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      read += value.byteLength;
      if (read > maxBytes) {
        // Hang up and decode nothing further. What comes back is a
        // stand-in one byte over the cap rather than the bytes read:
        // past this point the body is refused whatever it says, so
        // decoding the rest of it would be work done for nothing.
        void reader.cancel();
        return overCap(maxBytes);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  return text;
}
