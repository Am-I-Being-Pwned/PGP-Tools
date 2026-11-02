/**
 * Marshalling around `gpg-wasm/src/age.rs` (engine stubbed; crypto is
 * covered by the Rust tests). Pins: text in means armored out, and a
 * non-UTF-8 decrypt falls back to raw bytes, as on the PGP path.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  decryptWithHandle,
  encryptToRecipients,
  isAgeCiphertext,
  parseRecipient,
  selectDecryptionKey,
} from "./operations";

const wasm = vi.hoisted(() => ({
  encryptAgeToRecipients: vi.fn(),
  decryptAgeWithHandle: vi.fn(),
  parseSshRecipient: vi.fn(),
  isAgeMessage: vi.fn(),
  selectAgeDecryptionKey: vi.fn(),
}));

vi.mock("../pgp/wasm", () => wasm);

const RECIPIENT =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu alice@example.com";
const ARMORED = "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n";

beforeEach(() => {
  vi.resetAllMocks();
  wasm.encryptAgeToRecipients.mockResolvedValue(
    new TextEncoder().encode(ARMORED),
  );
});

describe("encryptToRecipients", () => {
  it("armors text input and hands back a string", async () => {
    const result = await encryptToRecipients({
      input: { kind: "text", text: "hello" },
      recipients: [RECIPIENT],
    });

    expect(wasm.encryptAgeToRecipients).toHaveBeenCalledWith(
      new TextEncoder().encode("hello"),
      [RECIPIENT],
      true,
    );
    expect(result).toBe(ARMORED);
  });

  it("leaves binary input binary unless armor is asked for", async () => {
    const binary = new Uint8Array([1, 2, 3]);
    wasm.encryptAgeToRecipients.mockResolvedValue(new Uint8Array([9, 8]));

    const result = await encryptToRecipients({
      input: { kind: "binary", binary },
      recipients: [RECIPIENT],
    });

    expect(wasm.encryptAgeToRecipients).toHaveBeenCalledWith(
      binary,
      [RECIPIENT],
      false,
    );
    expect(result).toBeInstanceOf(Uint8Array);
  });

  it("armors binary input on request", async () => {
    await encryptToRecipients({
      input: { kind: "binary", binary: new Uint8Array([1]), armor: true },
      recipients: [RECIPIENT],
    });
    expect(wasm.encryptAgeToRecipients.mock.calls[0][2]).toBe(true);
  });

  it("passes every recipient through, in order", async () => {
    await encryptToRecipients({
      input: { kind: "text", text: "x" },
      recipients: [RECIPIENT, "ssh-rsa AAAAB3Nza bob@host"],
    });
    expect(wasm.encryptAgeToRecipients.mock.calls[0][1]).toEqual([
      RECIPIENT,
      "ssh-rsa AAAAB3Nza bob@host",
    ]);
  });
});

describe("decryptWithHandle", () => {
  it("decodes a UTF-8 plaintext to text", async () => {
    wasm.decryptAgeWithHandle.mockResolvedValue(
      new TextEncoder().encode("secret message"),
    );
    const result = await decryptWithHandle({
      input: { kind: "armored", armoredMessage: ARMORED },
      keyHandle: 7,
    });

    expect(wasm.decryptAgeWithHandle).toHaveBeenCalledWith(
      new TextEncoder().encode(ARMORED),
      7,
    );
    expect(result).toBe("secret message");
  });

  it("keeps a leading byte-order mark in the decoded text", async () => {
    // A dropped BOM would make Copy/Download differ from the original.
    const bom = String.fromCharCode(0xfeff);
    wasm.decryptAgeWithHandle.mockResolvedValue(
      new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode("hi")]),
    );
    const result = await decryptWithHandle({
      input: { kind: "armored", armoredMessage: ARMORED },
      keyHandle: 7,
    });
    expect(result).toBe(`${bom}hi`);
  });

  it("hands back raw bytes when the plaintext is not UTF-8", async () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0x00, 0x01]);
    wasm.decryptAgeWithHandle.mockResolvedValue(bytes);

    const result = await decryptWithHandle({
      input: { kind: "binary", binaryMessage: new Uint8Array([1, 2]) },
      keyHandle: 3,
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect([...(result as Uint8Array)]).toEqual([...bytes]);
  });

  // Scrub the copy nobody needs, never the one being handed on.
  it("zeroizes the plaintext buffer once it has been decoded to text", async () => {
    const buffer = new TextEncoder().encode("secret message");
    wasm.decryptAgeWithHandle.mockResolvedValue(buffer);

    const result = await decryptWithHandle({
      input: { kind: "armored", armoredMessage: ARMORED },
      keyHandle: 7,
    });

    expect(result).toBe("secret message");
    expect([...buffer]).toEqual(Array(buffer.length).fill(0));
  });

  it("does NOT zeroize the buffer it hands back as the result", async () => {
    // Wiped later by the workspace (`zeroizeResultBytes`).
    const original = [0xff, 0xfe, 0x00, 0x01];
    wasm.decryptAgeWithHandle.mockResolvedValue(new Uint8Array(original));

    const result = await decryptWithHandle({
      input: { kind: "binary", binaryMessage: new Uint8Array([1, 2]) },
      keyHandle: 3,
    });
    expect([...(result as Uint8Array)]).toEqual(original);
  });

  it("passes binary ciphertext through untouched", async () => {
    const ciphertext = new Uint8Array([0x61, 0x67, 0x65]);
    wasm.decryptAgeWithHandle.mockResolvedValue(new Uint8Array(0));
    await decryptWithHandle({
      input: { kind: "binary", binaryMessage: ciphertext },
      keyHandle: 1,
    });
    expect(wasm.decryptAgeWithHandle).toHaveBeenCalledWith(ciphertext, 1);
  });
});

describe("parseRecipient / isAgeCiphertext", () => {
  it("returns the canonical recipient plus its public facts", async () => {
    const info = {
      recipient: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu",
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:abc",
      comment: "alice@example.com",
    };
    wasm.parseSshRecipient.mockResolvedValue(info);
    expect(await parseRecipient(RECIPIENT)).toEqual(info);
    expect(wasm.parseSshRecipient).toHaveBeenCalledWith(RECIPIENT);
  });

  it("propagates a parse failure rather than returning a bad recipient", async () => {
    wasm.parseSshRecipient.mockRejectedValue(new Error("not an SSH key"));
    await expect(parseRecipient("nonsense")).rejects.toThrow(/not an SSH key/);
  });

  it("delegates the routing sniff to the engine", async () => {
    wasm.isAgeMessage.mockResolvedValue(true);
    expect(await isAgeCiphertext(new Uint8Array([1]))).toBe(true);
  });
});

/** Which of my SSH keys opens this age file? */
describe("selectDecryptionKey", () => {
  const CANDIDATES = [RECIPIENT, "ssh-rsa AAAAB3Nza bob@host"];

  it("hands back the index of the identity the file is addressed to", async () => {
    wasm.selectAgeDecryptionKey.mockResolvedValue(1);
    const ciphertext = new TextEncoder().encode(ARMORED);
    expect(await selectDecryptionKey(ciphertext, CANDIDATES)).toBe(1);
    expect(wasm.selectAgeDecryptionKey).toHaveBeenCalledWith(
      ciphertext,
      CANDIDATES,
    );
  });

  it("says null when none of the candidates is a recipient", async () => {
    wasm.selectAgeDecryptionKey.mockResolvedValue(null);
    expect(
      await selectDecryptionKey(new Uint8Array([1]), CANDIDATES),
    ).toBeNull();
  });

  it("says null rather than throwing on input that is not an age file", async () => {
    wasm.selectAgeDecryptionKey.mockRejectedValue(
      new Error("Not a valid age file"),
    );
    expect(
      await selectDecryptionKey(new Uint8Array([1]), CANDIDATES),
    ).toBeNull();
  });
});
