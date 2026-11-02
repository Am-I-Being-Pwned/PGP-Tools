import { describe, expect, it } from "vitest";

import {
  looksLikeCollapsedArmor,
  reconstructArmor,
  reconstructCleartextSigned,
  recoverArmorIfNeeded,
  repairArmorEscapes,
} from "./armor-recovery";

// 64-char base64 lines like real armor output.
const LINE_A = "A".repeat(64);
const LINE_B = "B".repeat(64);

function collapse(armor: string): string {
  return armor.replace(/\s+/g, " ");
}

const ARMOR_WITH_HEADERS = [
  "-----BEGIN PGP MESSAGE-----",
  "Version: Encryption Desktop 10.4.1",
  "Comment: https://example.com",
  "",
  LINE_A,
  LINE_B,
  "CCCC",
  "=AbCd",
  "-----END PGP MESSAGE-----",
].join("\n");

const ARMOR_NO_HEADERS = [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----",
  "",
  LINE_A,
  "=AbCd",
  "-----END PGP PUBLIC KEY BLOCK-----",
].join("\n");

describe("looksLikeCollapsedArmor", () => {
  it("detects a collapsed armor block", () => {
    expect(looksLikeCollapsedArmor(collapse(ARMOR_WITH_HEADERS))).toBe(true);
  });

  it("rejects intact armor", () => {
    expect(looksLikeCollapsedArmor(ARMOR_WITH_HEADERS)).toBe(false);
  });

  it("rejects text without a BEGIN marker", () => {
    expect(looksLikeCollapsedArmor("hello world")).toBe(false);
  });

  // CRLF armor (Gpg4win/Kleopatra) is intact, not collapsed.
  it("rejects intact armor with CRLF line endings", () => {
    expect(
      looksLikeCollapsedArmor(ARMOR_WITH_HEADERS.replace(/\n/g, "\r\n")),
    ).toBe(false);
  });
});

describe("reconstructArmor", () => {
  it("round-trips collapsed armor with multi-word header values", () => {
    expect(reconstructArmor(collapse(ARMOR_WITH_HEADERS))).toBe(
      ARMOR_WITH_HEADERS,
    );
  });

  it("round-trips collapsed armor without headers", () => {
    expect(reconstructArmor(collapse(ARMOR_NO_HEADERS))).toBe(ARMOR_NO_HEADERS);
  });

  it("handles armor without a CRC line (OpenPGP v6 omits it)", () => {
    const armor = [
      "-----BEGIN PGP MESSAGE-----",
      "",
      LINE_A,
      "-----END PGP MESSAGE-----",
    ].join("\n");
    expect(reconstructArmor(collapse(armor))).toBe(armor);
  });

  it("re-wraps base64 data to 64 chars per line", () => {
    const result = reconstructArmor(collapse(ARMOR_WITH_HEADERS));
    const dataLines = result
      .split("\n")
      .filter((l) => /^[AB C]+$/.test(l) && l.length > 0);
    for (const line of dataLines) {
      expect(line.length).toBeLessThanOrEqual(64);
    }
  });

  it("round-trips a detached signature block", () => {
    const armor = [
      "-----BEGIN PGP SIGNATURE-----",
      "",
      LINE_A,
      "=AbCd",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(reconstructArmor(collapse(armor))).toBe(armor);
  });

  it("never rewraps a cleartext-signed message body", () => {
    // Cleartext body must not be rewrapped as base64.
    const signed = collapse(
      [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA256",
        "",
        "This human-readable text must survive untouched.",
        "-----BEGIN PGP SIGNATURE-----",
        "",
        LINE_A,
        "=AbCd",
        "-----END PGP SIGNATURE-----",
      ].join("\n"),
    );
    expect(reconstructArmor(signed)).toBe(signed);
  });

  it("bails on mismatched BEGIN/END block types", () => {
    const mismatched = collapse(
      ARMOR_WITH_HEADERS.replace(
        "-----END PGP MESSAGE-----",
        "-----END PGP PUBLIC KEY BLOCK-----",
      ),
    );
    expect(reconstructArmor(mismatched)).toBe(mismatched);
  });

  it("bails when there is no plausible base64 data", () => {
    const junk =
      "-----BEGIN PGP MESSAGE----- not actual armor -----END PGP MESSAGE-----";
    expect(reconstructArmor(junk)).toBe(junk);
  });

  it("returns non-armor text unchanged", () => {
    expect(reconstructArmor("plain text")).toBe("plain text");
  });
});

describe("recoverArmorIfNeeded", () => {
  it("reconstructs collapsed armor", () => {
    expect(recoverArmorIfNeeded(collapse(ARMOR_WITH_HEADERS))).toBe(
      ARMOR_WITH_HEADERS,
    );
  });

  it("passes intact armor through untouched", () => {
    expect(recoverArmorIfNeeded(ARMOR_WITH_HEADERS)).toBe(ARMOR_WITH_HEADERS);
  });

  it("passes plain text through untouched", () => {
    expect(recoverArmorIfNeeded("just some text")).toBe("just some text");
  });
});

// ── Escape repair ────────────────────────────────────────────────────

const MESSAGE = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  "jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj",
  "wjg=",
  "=AEHv",
  "-----END PGP MESSAGE-----",
].join("\n");

function blockIn2(text: string, type: string): string {
  return (
    new RegExp(`-----BEGIN ${type}-----[\\s\\S]*?-----END ${type}-----`).exec(
      text,
    )?.[0] ?? ""
  );
}

function blockIn(text: string): string {
  return (
    /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/.exec(
      text,
    )?.[0] ?? ""
  );
}

describe("repairArmorEscapes", () => {
  it.each([
    ["JSON \\n", MESSAGE.replaceAll("\n", "\\n")],
    ["JSON \\r\\n", MESSAGE.replaceAll("\n", "\\r\\n")],
    ["HTML <br>", MESSAGE.replaceAll("\n", "<br>")],
    ["HTML <br />", MESSAGE.replaceAll("\n", "<br />")],
    ["HTML &#10;", MESSAGE.replaceAll("\n", "&#10;")],
    ["URL %0A", MESSAGE.replaceAll("\n", "%0A")],
    ["URL %0D%0A", MESSAGE.replaceAll("\n", "%0D%0A")],
  ])("puts the newlines back: %s", (_name, mangled) => {
    expect(blockIn(repairArmorEscapes(mangled))).toBe(MESSAGE);
  });

  it("rescues a block embedded in JSON", () => {
    // Marker stuck mid-line behind `{"msg":"` must be re-emitted.
    const embedded = JSON.stringify({ msg: MESSAGE });
    expect(blockIn(repairArmorEscapes(embedded))).toBe(MESSAGE);
    expect(repairArmorEscapes(embedded)).toContain(
      "\n-----BEGIN PGP MESSAGE-----",
    );
  });

  it("leaves armor that is already fine BYTE-IDENTICAL", () => {
    // Byte-identical: stored armor is compared byte-for-byte on re-import.
    expect(repairArmorEscapes(MESSAGE)).toBe(MESSAGE);
    const withNoise = `hello\n${MESSAGE}\nbye`;
    expect(repairArmorEscapes(withNoise)).toBe(withNoise);
  });

  it("NEVER touches text outside an armor block", () => {
    // Text outside armor blocks is never unescaped (composed messages).
    const code = 'console.log("a\\nb");\nconst x = "c\\td";';
    expect(repairArmorEscapes(code)).toBe(code);
  });

  it("returns unclosed armor untouched", () => {
    // Unclosed BEGINs: the regexes' quadratic worst case.
    const unclosed = `-----BEGIN PGP MESSAGE-----\n\nAAAA\\nBBBB`;
    expect(repairArmorEscapes(unclosed)).toBe(unclosed);
    const many = "-----BEGIN PGP MESSAGE-----\n".repeat(50);
    expect(repairArmorEscapes(many)).toBe(many);
  });

  it.each([
    ["OpenSSH private key", "OPENSSH PRIVATE KEY"],
    ["PKCS#8 PEM (CRX signing key)", "PRIVATE KEY"],
    ["PKCS#1 PEM", "RSA PRIVATE KEY"],
    ["armored age file", "AGE ENCRYPTED FILE"],
    ["public key block", "PGP PUBLIC KEY BLOCK"],
  ])("repairs a %s too, not just PGP messages", (_name, type) => {
    // Every PEM-style key kind, not just `BEGIN PGP`.
    const block = [
      `-----BEGIN ${type}-----`,
      "",
      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz",
      "-----END ${type}-----".replace("${type}", type),
    ].join("\n");
    expect(
      blockIn2(repairArmorEscapes(block.replaceAll("\n", "\\n")), type),
    ).toBe(block);
  });

  it("repairs armor copied out of a SOURCE FILE, continuations and all", () => {
    // Real paste of the Rust fixture: `\n` escaping AND backslash-newline
    // continuations at once. `BS` is one literal backslash.
    const BS = "\\";
    const pasted = [
      `-----BEGIN PGP MESSAGE-----${BS}n${BS}n${BS}`,
      `jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj${BS}n${BS}`,
      `KAFUrRe5nBt9CNXSIRuIDsj+k2V4YT+ZnsBO4kx2F3RFv3sKEN8v1cKMq86Qif+p${BS}n${BS}`,
      `wjg=${BS}n${BS}`,
      `=AEHv${BS}n${BS}`,
      `-----END PGP MESSAGE-----${BS}n`,
    ].join("\n");

    const expected = [
      "-----BEGIN PGP MESSAGE-----",
      "",
      "jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj",
      "KAFUrRe5nBt9CNXSIRuIDsj+k2V4YT+ZnsBO4kx2F3RFv3sKEN8v1cKMq86Qif+p",
      "wjg=",
      "=AEHv",
      "-----END PGP MESSAGE-----",
    ].join("\n");

    expect(blockIn(repairArmorEscapes(pasted))).toBe(expected);
  });

  it("keeps a backslash that is not a continuation", () => {
    // Only a backslash IMMEDIATELY before a newline is a continuation.
    const BS = "\\";
    const block = [
      "-----BEGIN PGP MESSAGE-----",
      `Comment: C:${BS}dir${BS}file`,
      "",
      "AAAA",
      "-----END PGP MESSAGE-----",
    ].join("\n");
    expect(repairArmorEscapes(block)).toBe(block);
  });

  it("does not repair across two different blocks", () => {
    // A BEGIN must not swallow text up to another block's END.
    const two = `${MESSAGE}\n\nsome prose with \\n in it\n\n${MESSAGE}`;
    const out = repairArmorEscapes(two);
    expect(out).toContain("some prose with \\n in it");
  });

  it("leaves a cleartext-signed message alone when it still has lines", () => {
    // Signed free text may contain a backslash; rewriting it breaks the
    // signature.
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA512",
      "",
      "the literal two characters \\n must survive",
      "-----BEGIN PGP SIGNATURE-----",
      "",
      "iHUEARYKAB0WIQQ=",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(repairArmorEscapes(signed)).toBe(signed);
  });

  it("does repair a cleartext-signed message that was flattened", () => {
    // No real newline anywhere proves it was escaped.
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA512",
      "",
      "hello",
      "-----BEGIN PGP SIGNATURE-----",
      "",
      "iHUEARYKAB0WIQQ=",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(repairArmorEscapes(signed.replaceAll("\n", "\\n"))).toBe(signed);
  });
});

describe("recoverArmorIfNeeded", () => {
  it("handles escaping and whitespace collapse in the right order", () => {
    // Escape repair must run before collapse detection.
    expect(blockIn(recoverArmorIfNeeded(MESSAGE.replaceAll("\n", "\\n")))).toBe(
      MESSAGE,
    );
  });

  it("still reconstructs a whitespace-collapsed selection", () => {
    const out = recoverArmorIfNeeded(collapse(ARMOR_WITH_HEADERS));
    expect(out).toContain("-----BEGIN PGP MESSAGE-----\n");
    expect(out).toContain("Version: Encryption Desktop 10.4.1");
  });

  it("is a pass-through for ordinary text", () => {
    for (const text of ["", "hello", "a\\nb", "-----BEGIN SOMETHING-----"]) {
      expect(recoverArmorIfNeeded(text)).toBe(text);
    }
  });
});

// ── Kleopatra-style export: CRLF + `Comment: Fingerprint: <40 hex>` ──
describe("Kleopatra-style armor", () => {
  const KLEOPATRA = [
    "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    "Comment: User-ID:   Swift Alert <alert@example.com>",
    "Comment: Created:   22/01/2019 12:00",
    "Comment: Type:      2048-bit RSA (secret key available)",
    "Comment: Usage:     Signing, Encryption, Certifying User-IDs",
    "Comment: Fingerprint:     07DF8027AAFCFA3A349E96CB1AC6ADD598DFB505",
    "",
    "",
    LINE_A,
    LINE_B,
    "CCCC",
    "=AbCd",
    "-----END PGP PUBLIC KEY BLOCK-----",
  ].join("\r\n");

  it("passes CRLF armor through byte for byte", () => {
    expect(recoverArmorIfNeeded(KLEOPATRA)).toBe(KLEOPATRA);
  });

  it("keeps the fingerprint header out of the data when collapsed", () => {
    const rebuilt = recoverArmorIfNeeded(collapse(KLEOPATRA));
    // The 40-char fingerprint is not folded into the payload.
    expect(rebuilt).toContain(`\n${LINE_A}\n${LINE_B}\nCCCC\n=AbCd`);
    expect(rebuilt).toContain(
      "Fingerprint: 07DF8027AAFCFA3A349E96CB1AC6ADD598DFB505",
    );
  });
});

describe("reconstructCleartextSigned", () => {
  const signedMessage = (hash: string[], body: string) =>
    [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      ...hash,
      "",
      body,
      "-----BEGIN PGP SIGNATURE-----",
      "",
      LINE_A,
      "CCCC",
      "=AbCd",
      "-----END PGP SIGNATURE-----",
    ].join("\n");

  it("restores a one-line message exactly, header and signature included", () => {
    const signed = signedMessage(["Hash: SHA512"], "Hi this is a msg");
    expect(reconstructCleartextSigned(collapse(signed))).toBe(signed);
    expect(recoverArmorIfNeeded(collapse(signed))).toBe(signed);
  });

  it("keeps a multi-algorithm Hash header on its line", () => {
    const signed = signedMessage(["Hash: SHA256, SHA512"], "one line");
    expect(reconstructCleartextSigned(collapse(signed))).toBe(signed);
  });

  it("handles a message with no Hash header", () => {
    const signed = signedMessage([], "no header here");
    expect(reconstructCleartextSigned(collapse(signed))).toBe(signed);
  });

  it("joins a multi-line body rather than guessing its line breaks", () => {
    const signed = signedMessage(["Hash: SHA256"], "first line\nsecond line");
    expect(reconstructCleartextSigned(collapse(signed))).toBe(
      signedMessage(["Hash: SHA256"], "first line second line"),
    );
  });

  it("keeps the text around the message byte for byte", () => {
    const signed = signedMessage(["Hash: SHA512"], "hello");
    expect(reconstructCleartextSigned(`before ${collapse(signed)} after`)).toBe(
      `before ${signed} after`,
    );
  });

  it("leaves intact and non-signed text alone", () => {
    const signed = signedMessage(["Hash: SHA512"], "hello");
    expect(reconstructCleartextSigned(signed)).toBeNull();
    expect(recoverArmorIfNeeded(signed)).toBe(signed);
    expect(reconstructCleartextSigned(collapse(ARMOR_NO_HEADERS))).toBeNull();
  });
});

describe("recoverArmorIfNeeded stays fast on hostile input", () => {
  // Page-controlled, newline-free input must not backtrack (worker DoS).
  const SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----";
  const SIG = "-----BEGIN PGP SIGNATURE-----";
  const shapes = {
    "repeated markers": (SIGNED + SIG).repeat(2500),
    "markers with spaces": `${SIGNED} ${SIG} `.repeat(2500),
    "one start, many signature openers": SIGNED + ` ${SIG} x`.repeat(5000),
    "many starts, no signature": `${SIGNED} a `.repeat(5000),
    "armor-ish base64 run": `-----BEGIN PGP MESSAGE----- ${"QUJD ".repeat(40000)}`,
  };

  it.each(Object.entries(shapes))("%s", (_name, input) => {
    expect(input.length).toBeGreaterThan(100_000);
    const started = performance.now();
    recoverArmorIfNeeded(input);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("still rebuilds a real collapsed cleartext message after the rewrite", () => {
    const collapsed =
      "noise -----BEGIN PGP SIGNED MESSAGE----- Hash: SHA256 hello -----BEGIN PGP SIGNATURE----- iHUEARYKAB0WIQQ1O+qq08UbGNZ2zuSyaA3VZBfijwUCakrm5gAKCRCyaA3VZBfi =yShI -----END PGP SIGNATURE----- tail";
    const rebuilt = recoverArmorIfNeeded(collapsed);
    expect(rebuilt).toMatch(
      /^noise -----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n-----BEGIN PGP SIGNATURE-----\n/,
    );
    expect(rebuilt.endsWith(" tail")).toBe(true);
  });
});
