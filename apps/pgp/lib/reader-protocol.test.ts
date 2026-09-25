import { describe, expect, it } from "vitest";

import {
  isReaderMessage,
  isReaderNonce,
  newReaderNonce,
  READER_PORT_PREFIX,
} from "./reader-protocol";

describe("reader protocol", () => {
  it("makes 128-bit hex nonces, a fresh one each time", () => {
    const a = newReaderNonce();
    expect(isReaderNonce(a)).toBe(true);
    expect(newReaderNonce()).not.toBe(a);
  });

  it("accepts only its own nonce shape", () => {
    expect(isReaderNonce("")).toBe(false);
    expect(isReaderNonce("A".repeat(32))).toBe(false);
    expect(isReaderNonce("0".repeat(31))).toBe(false);
    expect(isReaderNonce(`${"0".repeat(32)}#x`)).toBe(false);
  });

  it("validates messages from the panel", () => {
    const signer = { keyId: "ABCD", userIds: ["Alice <a@x>"] };
    expect(isReaderMessage({ type: "locked" })).toBe(true);
    expect(isReaderMessage({ type: "show", signer, text: "hi" })).toBe(true);
    expect(isReaderMessage({ type: "show", signer })).toBe(false);
    expect(isReaderMessage({ type: "show", text: "hi" })).toBe(false);
    expect(isReaderMessage({ type: "show", signer: {}, text: "hi" })).toBe(
      false,
    );
    expect(isReaderMessage({ type: "exfiltrate" })).toBe(false);
    expect(isReaderMessage(null)).toBe(false);
  });

  it("namespaces the port", () => {
    expect(READER_PORT_PREFIX).toBe("pgp-reader:");
  });
});
