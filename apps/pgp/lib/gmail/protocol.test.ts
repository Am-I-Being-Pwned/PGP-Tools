import { describe, expect, it } from "vitest";

import {
  base64ToBytes,
  bytesToBase64,
  gmailComposeUrl,
  gmailOrigins,
  isArmoredMessageOnly,
  isComposeId,
  isEmailAddress,
  isEncryptedFileBytes,
  isGmailAttachmentRef,
  isGmailAttachRequest,
  isGmailFetchAttachmentRequest,
  isGmailFile,
  isGmailFileList,
  isGmailFillRequest,
  isGmailInsertRequest,
  isGmailOpenRequest,
  MAX_GMAIL_TEXT,
  originOfPattern,
  sanitizeRecipients,
} from "./protocol";

// Syntactically valid armor with a meaningless body: these tests are
// about SHAPE, which is all the Gmail boundary judges.
const BODY = [
  "hQEMA2b3c4d5e6f7g8hAQf/abcdefghijklmnopqrstuvwxyz0123456789+/AB",
  "cd/EF+gh==",
];
const ARMOR = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  ...BODY,
  "=AbCd",
  "-----END PGP MESSAGE-----",
].join("\n");

const COMPOSE_ID = "0123456789abcdef0123456789abcdef";

describe("isArmoredMessageOnly", () => {
  it("accepts one armored message, with or without headers and checksum", () => {
    expect(isArmoredMessageOnly(ARMOR)).toBe(true);
    expect(isArmoredMessageOnly(`\n\n  ${ARMOR}\n`)).toBe(true);
    expect(isArmoredMessageOnly(ARMOR.replace("=AbCd\n", ""))).toBe(true);
    expect(
      isArmoredMessageOnly(
        ARMOR.replace(
          "-----BEGIN PGP MESSAGE-----\n",
          "-----BEGIN PGP MESSAGE-----\nVersion: PGP Tools\nComment: hi\n",
        ),
      ),
    ).toBe(true);
    expect(isArmoredMessageOnly(ARMOR.replaceAll("\n", "\r\n"))).toBe(true);
  });

  it("refuses plaintext wrapped in a BEGIN/END pair", () => {
    const smuggled = [
      "-----BEGIN PGP MESSAGE-----",
      "",
      "meet me at the usual place at 9",
      "-----END PGP MESSAGE-----",
    ].join("\n");
    expect(isArmoredMessageOnly(smuggled)).toBe(false);
  });

  it("refuses a body line that is mostly base64 but carries a space", () => {
    expect(isArmoredMessageOnly(ARMOR.replace(BODY[1], "cd/EF gh=="))).toBe(
      false,
    );
  });

  it("refuses a missing header separator", () => {
    expect(
      isArmoredMessageOnly(ARMOR.replace("MESSAGE-----\n\n", "MESSAGE-----\n")),
    ).toBe(false);
  });

  it("refuses a header that isn't on the allowlist, or runs long", () => {
    const withHeader = (h: string) =>
      ARMOR.replace(
        "-----BEGIN PGP MESSAGE-----\n",
        `-----BEGIN PGP MESSAGE-----\n${h}\n`,
      );
    expect(isArmoredMessageOnly(withHeader("Secret: the plaintext"))).toBe(
      false,
    );
    expect(
      isArmoredMessageOnly(withHeader(`Comment: ${"x".repeat(200)}`)),
    ).toBe(false);
  });

  it("refuses text around the block, a second block, and other armor kinds", () => {
    expect(isArmoredMessageOnly(`hello\n${ARMOR}`)).toBe(false);
    expect(isArmoredMessageOnly(`${ARMOR}\nbye`)).toBe(false);
    expect(isArmoredMessageOnly(`${ARMOR}\n${ARMOR}`)).toBe(false);
    expect(
      isArmoredMessageOnly(
        [
          "-----BEGIN PGP SIGNED MESSAGE-----",
          "Hash: SHA256",
          "",
          "a signed plaintext",
          "-----BEGIN PGP SIGNATURE-----",
          "",
          "iQEz",
          "-----END PGP SIGNATURE-----",
        ].join("\n"),
      ),
    ).toBe(false);
    expect(
      isArmoredMessageOnly(
        ARMOR.replaceAll("PGP MESSAGE", "PGP PUBLIC KEY BLOCK"),
      ),
    ).toBe(false);
  });

  it("accepts a password-encrypted (SKESK) and a new-format PKESK message", () => {
    expect(isArmoredMessageOnly(ARMOR.replace("hQEMA2b3", "jA0ECQMC"))).toBe(
      true,
    );
    expect(isArmoredMessageOnly(ARMOR.replace("hQEMA2b3", "wcBMA2b3"))).toBe(
      true,
    );
  });

  it("refuses armor that is plaintext in base64 (signed-only, compressed, literal)", () => {
    // gpg -s -a: a compressed packet (tag 8, old format)
    expect(isArmoredMessageOnly(ARMOR.replace("hQEMA2b3", "owGbwMvM"))).toBe(
      false,
    );
    // a bare literal data packet (tag 11, new format)
    expect(isArmoredMessageOnly(ARMOR.replace("hQEMA2b3", "yxR0AAAA"))).toBe(
      false,
    );
    // a one-pass signature (tag 4)
    expect(isArmoredMessageOnly(ARMOR.replace("hQEMA2b3", "kA0DAAoB"))).toBe(
      false,
    );
  });

  it("refuses a stack of Comment headers carrying a body", () => {
    const comments = Array.from(
      { length: 6 },
      (_, i) => `Comment: line ${i} of the secret`,
    ).join("\n");
    expect(
      isArmoredMessageOnly(
        ARMOR.replace(
          "-----BEGIN PGP MESSAGE-----\n",
          `-----BEGIN PGP MESSAGE-----\n${comments}\n`,
        ),
      ),
    ).toBe(false);
  });

  it("refuses non-strings, empties, and oversize input", () => {
    expect(isArmoredMessageOnly(undefined)).toBe(false);
    expect(isArmoredMessageOnly(42)).toBe(false);
    expect(isArmoredMessageOnly("")).toBe(false);
    expect(
      isArmoredMessageOnly(
        ARMOR.replace(BODY[0], "A".repeat(64) + "\n").padEnd(
          MAX_GMAIL_TEXT + 1,
          "A",
        ),
      ),
    ).toBe(false);
  });
});

describe("origins come from the manifest pattern", () => {
  it("turns an origin pattern into its origin", () => {
    expect(originOfPattern("https://mail.google.com/*")).toBe(
      "https://mail.google.com",
    );
  });

  it("refuses wildcards and paths", () => {
    expect(originOfPattern("*://mail.google.com/*")).toBeNull();
    expect(originOfPattern("https://*.google.com/*")).toBeNull();
    expect(originOfPattern("https://mail.google.com/mail/*")).toBeNull();
    expect(originOfPattern("<all_urls>")).toBeNull();
  });

  it("reads the optional host permissions", () => {
    expect(
      gmailOrigins(["https://mail.google.com/*", "https://*.example.com/*"]),
    ).toEqual(["https://mail.google.com"]);
  });
});

describe("recipients", () => {
  it("accepts plain addresses and refuses markup and junk", () => {
    expect(isEmailAddress("alice@example.com")).toBe(true);
    expect(isEmailAddress("a.b+tag@sub.example.co.uk")).toBe(true);
    expect(isEmailAddress("o'brien@example.ie")).toBe(true);
    expect(isEmailAddress("<b>@x.com")).toBe(false);
    expect(isEmailAddress("Alice <alice@example.com>")).toBe(false);
    expect(isEmailAddress("alice@localhost")).toBe(false);
    expect(isEmailAddress(`${"a".repeat(250)}@x.com`)).toBe(false);
  });

  it("sanitizes: valid only, lowercased, de-duplicated, capped", () => {
    expect(
      sanitizeRecipients([
        "Alice@Example.com",
        "alice@example.com",
        "nope",
        7,
        "bob@example.org",
      ]),
    ).toEqual(["alice@example.com", "bob@example.org"]);
    expect(sanitizeRecipients("alice@example.com")).toEqual([]);
    const many = Array.from({ length: 80 }, (_, i) => `u${i}@example.com`);
    expect(sanitizeRecipients(many)).toHaveLength(50);
  });
});

describe("message guards", () => {
  it("accepts a well-formed GMAIL_OPEN, with and without a compose ref", () => {
    expect(isGmailOpenRequest({ type: "GMAIL_OPEN", text: ARMOR })).toBe(true);
    expect(
      isGmailOpenRequest({
        type: "GMAIL_OPEN",
        text: "",
        compose: { composeId: COMPOSE_ID, recipients: ["a@example.com"] },
      }),
    ).toBe(true);
  });

  it("refuses a bad compose ref or oversize text", () => {
    expect(
      isGmailOpenRequest({
        type: "GMAIL_OPEN",
        text: "",
        compose: { composeId: "../../etc", recipients: [] },
      }),
    ).toBe(false);
    expect(
      isGmailOpenRequest({
        type: "GMAIL_OPEN",
        text: "",
        compose: { composeId: COMPOSE_ID, recipients: ["<script>"] },
      }),
    ).toBe(false);
    expect(
      isGmailOpenRequest({
        type: "GMAIL_OPEN",
        text: "x".repeat(MAX_GMAIL_TEXT + 1),
      }),
    ).toBe(false);
  });

  it("compose ids are 32 lowercase hex, nothing else", () => {
    expect(isComposeId(COMPOSE_ID)).toBe(true);
    expect(isComposeId(COMPOSE_ID.toUpperCase())).toBe(false);
    expect(isComposeId(`${COMPOSE_ID}"]`)).toBe(false);
  });

  it("an insert carries only armor", () => {
    expect(
      isGmailInsertRequest({
        type: "GMAIL_INSERT",
        composeId: COMPOSE_ID,
        armored: ARMOR,
      }),
    ).toBe(true);
    expect(
      isGmailInsertRequest({
        type: "GMAIL_INSERT",
        composeId: COMPOSE_ID,
        armored: "the decrypted plaintext",
      }),
    ).toBe(false);
  });
});

describe("new compose", () => {
  it("builds Gmail's compose URL with only valid addresses on the To line", () => {
    expect(
      gmailComposeUrl("https://mail.google.com", [
        "alice@example.com",
        "bob@example.org",
        "<x>",
      ]),
    ).toBe(
      "https://mail.google.com/mail/?view=cm&fs=1&to=alice%40example.com%2Cbob%40example.org",
    );
    expect(gmailComposeUrl("https://mail.google.com", [])).toBe(
      "https://mail.google.com/mail/?view=cm&fs=1",
    );
  });

  it("a fill carries only armor", () => {
    expect(isGmailFillRequest({ type: "GMAIL_FILL", armored: ARMOR })).toBe(
      true,
    );
    expect(isGmailFillRequest({ type: "GMAIL_FILL", armored: "hello" })).toBe(
      false,
    );
  });
});

describe("files", () => {
  // Binary OpenPGP: a new-format PKESK (0xc1), an old-format SKESK
  // (0x8c = tag 3), and plaintext-bearing packets that must be refused.
  const pkesk = new Uint8Array([0xc1, 0x5e, 0x03, 0x01, 0x02]);
  const skesk = new Uint8Array([0x8c, 0x0d, 0x04, 0x09, 0x03]);
  const literal = new Uint8Array([0xcb, 0x12, 0x62, 0x00, 0x00]);
  const onePass = new Uint8Array([0x90, 0x0d, 0x03, 0x01, 0x08]);
  const enc = (s: string) => new TextEncoder().encode(s);

  it("isEncryptedFileBytes accepts binary PGP that opens with a session-key packet", () => {
    expect(isEncryptedFileBytes(pkesk)).toBe(true);
    expect(isEncryptedFileBytes(skesk)).toBe(true);
    expect(isEncryptedFileBytes(literal)).toBe(false);
    expect(isEncryptedFileBytes(onePass)).toBe(false);
    expect(isEncryptedFileBytes(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))).toBe(
      false,
    );
    expect(isEncryptedFileBytes(new Uint8Array(2))).toBe(false);
    // A high first byte is not enough: the packet's version must be one
    // a session-key packet has ("ÁAB" in Windows-1252 starts 0xC1).
    expect(isEncryptedFileBytes(new Uint8Array([0xc1, 0x41, 0x42, 0x43]))).toBe(
      false,
    );
    expect(isEncryptedFileBytes(new Uint8Array([0xc1, 0x5e, 0x02, 0x01]))).toBe(
      false,
    );
    // v6 PKESK (new format, two-octet length) and v5 SKESK (old format,
    // two-octet length) are the other shapes an encoder writes.
    expect(
      isEncryptedFileBytes(new Uint8Array([0xc1, 0xc0, 0x10, 0x06, 0x00])),
    ).toBe(true);
    expect(
      isEncryptedFileBytes(new Uint8Array([0x8d, 0x01, 0x00, 0x05, 0x00])),
    ).toBe(true);
  });

  it("isEncryptedFileBytes accepts age files and armored messages, not text", () => {
    expect(
      isEncryptedFileBytes(enc("age-encryption.org/v1\n-> X25519 abc\n")),
    ).toBe(true);
    expect(
      isEncryptedFileBytes(
        enc(
          "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBhYmMKLS0tIG1hYwo=\n-----END AGE ENCRYPTED FILE-----\n",
        ),
      ),
    ).toBe(true);
    // Armored age must be a whole file whose body decodes to the magic.
    expect(
      isEncryptedFileBytes(enc("-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n")),
    ).toBe(false);
    expect(
      isEncryptedFileBytes(
        enc(
          "-----BEGIN AGE ENCRYPTED FILE-----\nRGVhciBBbGljZQ==\n-----END AGE ENCRYPTED FILE-----",
        ),
      ),
    ).toBe(false);
    expect(isEncryptedFileBytes(enc(ARMOR))).toBe(true);
    expect(
      isEncryptedFileBytes(
        enc(
          "-----BEGIN PGP MESSAGE-----\n\nDear Alice\n-----END PGP MESSAGE-----",
        ),
      ),
    ).toBe(false);
    expect(
      isEncryptedFileBytes(
        enc("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhi"),
      ),
    ).toBe(false);
    expect(isEncryptedFileBytes(enc("Dear Alice, attack at dawn"))).toBe(false);
  });

  it("base64 round-trips bytes, in chunks", () => {
    const bytes = new Uint8Array(100_000);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7) & 0xff;
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    expect(bytesToBase64(new Uint8Array([0xc1, 0x5e]))).toBe("wV4=");
  });

  it("a file has one path segment for a name and base64 data, capped", () => {
    expect(isGmailFile({ name: "report.pdf.gpg", data: "wV4=" })).toBe(true);
    expect(isGmailFile({ name: "../etc/passwd", data: "wV4=" })).toBe(false);
    expect(isGmailFile({ name: "a\u0000b", data: "wV4=" })).toBe(false);
    expect(isGmailFile({ name: "", data: "wV4=" })).toBe(false);
    expect(isGmailFile({ name: "x".repeat(256), data: "wV4=" })).toBe(false);
    expect(isGmailFile({ name: "a.gpg", data: "" })).toBe(false);
    expect(isGmailFile({ name: "a.gpg", data: "not base64!" })).toBe(false);
    expect(isGmailFile({ name: "a.gpg", data: "wV4" })).toBe(false);
    expect(isGmailFileList([{ name: "a.gpg", data: "wV4=" }])).toBe(true);
    expect(isGmailFileList([])).toBe(false);
    expect(
      isGmailFileList(
        Array.from({ length: 21 }, () => ({ name: "a.gpg", data: "wV4=" })),
      ),
    ).toBe(false);
  });

  it("attach and fetch-attachment requests, and an attachment ref", () => {
    const file = { name: "a.gpg", data: "wV4=" };
    expect(
      isGmailAttachRequest({
        type: "GMAIL_ATTACH",
        composeId: COMPOSE_ID,
        files: [file],
      }),
    ).toBe(true);
    expect(
      isGmailAttachRequest({
        type: "GMAIL_ATTACH",
        composeId: "nope",
        files: [file],
      }),
    ).toBe(false);
    expect(
      isGmailAttachRequest({
        type: "GMAIL_ATTACH",
        composeId: COMPOSE_ID,
        files: [],
      }),
    ).toBe(false);
    expect(
      isGmailFetchAttachmentRequest({
        type: "GMAIL_FETCH_ATTACHMENT",
        attachmentId: COMPOSE_ID,
      }),
    ).toBe(true);
    expect(
      isGmailFetchAttachmentRequest({
        type: "GMAIL_FETCH_ATTACHMENT",
        attachmentId: "x",
      }),
    ).toBe(false);
    expect(
      isGmailAttachmentRef({ attachmentId: COMPOSE_ID, name: "a.gpg" }),
    ).toBe(true);
    expect(
      isGmailAttachmentRef({
        attachmentId: COMPOSE_ID,
        name: "a.gpg",
        documentId: "0123456789ABCDEF0123456789ABCDEF",
      }),
    ).toBe(true);
    expect(
      isGmailAttachmentRef({ attachmentId: COMPOSE_ID, name: "a/b.gpg" }),
    ).toBe(false);
    expect(
      isGmailAttachmentRef({
        attachmentId: COMPOSE_ID,
        name: "a.gpg",
        documentId: "lower",
      }),
    ).toBe(false);
  });

  it("a GMAIL_OPEN for an attachment has empty text and no compose ref", () => {
    const attachment = { attachmentId: COMPOSE_ID, name: "a.gpg" };
    expect(
      isGmailOpenRequest({ type: "GMAIL_OPEN", text: "", attachment }),
    ).toBe(true);
    expect(
      isGmailOpenRequest({ type: "GMAIL_OPEN", text: "x", attachment }),
    ).toBe(false);
    expect(
      isGmailOpenRequest({
        type: "GMAIL_OPEN",
        text: "",
        attachment,
        compose: { composeId: COMPOSE_ID, recipients: [] },
      }),
    ).toBe(false);
  });

  it("a fill carries armor OR files, never both, never neither", () => {
    const file = { name: "a.gpg", data: "wV4=" };
    expect(isGmailFillRequest({ type: "GMAIL_FILL", files: [file] })).toBe(
      true,
    );
    expect(
      isGmailFillRequest({ type: "GMAIL_FILL", armored: ARMOR, files: [file] }),
    ).toBe(false);
    expect(isGmailFillRequest({ type: "GMAIL_FILL" })).toBe(false);
    expect(
      isGmailFillRequest({
        type: "GMAIL_FILL",
        files: [{ name: "a", data: "!" }],
      }),
    ).toBe(false);
  });
});
