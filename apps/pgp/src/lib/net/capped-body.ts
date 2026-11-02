/**
 * Read at most `maxBytes + 1` bytes of a response body. Caps apply BEFORE
 * buffering (`response.text()` would allocate first), per SECURITY.md and
 * T-*-UNTRUSTED-PARSE; the extra byte lets the parser refuse. Shared by
 * both remote lookups so the quoted guarantee cannot drift.
 */

function overCap(maxBytes: number): string {
  return "x".repeat(maxBytes + 1);
}

export async function readCappedBody(
  response: Response,
  maxBytes: number,
): Promise<string> {
  // Content-Length can lie; trusted only to refuse early.
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    void response.body?.cancel();
    return overCap(maxBytes);
  }

  const body = response.body;
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
