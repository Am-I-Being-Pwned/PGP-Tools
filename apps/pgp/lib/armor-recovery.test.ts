import { describe, expect, it } from "vitest";

import {
  looksLikeCollapsedArmor,
  reconstructArmor,
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
    // The free-text body of a cleartext-signed message must not be
    // reconstructed as base64. The BEGIN type (SIGNED MESSAGE) never
    // matches the first END type (SIGNATURE), so it passes through.
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

/** A real (short) message, the shape every case below is mangled from. */
const MESSAGE = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  "jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj",
  "wjg=",
  "=AEHv",
  "-----END PGP MESSAGE-----",
].join("\n");

/** The armor block inside `text`, so a case can assert on the repaired
 *  block without caring what surrounded it. */
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
    // The case the block re-emit exists for: the BEGIN marker arrives
    // stuck mid-line behind `{"msg":"`, where the armor parser will not
    // find it however well the newlines are restored.
    const embedded = JSON.stringify({ msg: MESSAGE });
    expect(blockIn(repairArmorEscapes(embedded))).toBe(MESSAGE);
    // And the marker now starts a line of its own.
    expect(repairArmorEscapes(embedded)).toContain(
      "\n-----BEGIN PGP MESSAGE-----",
    );
  });

  it("leaves armor that is already fine BYTE-IDENTICAL", () => {
    // Not merely "equivalent". A key's armor is stored verbatim and is
    // compared byte-for-byte to decide re-import vs. update, so a
    // cosmetic rewrite here would show every re-imported key as changed.
    expect(repairArmorEscapes(MESSAGE)).toBe(MESSAGE);
    const withNoise = `hello\n${MESSAGE}\nbye`;
    expect(repairArmorEscapes(withNoise)).toBe(withNoise);
  });

  it("NEVER touches text outside an armor block", () => {
    // The property that makes this safe to run over the workspace input
    // box, which also holds messages being composed. A global unescape
    // would eat the backslash-n in this snippet.
    const code = 'console.log("a\\nb");\nconst x = "c\\td";';
    expect(repairArmorEscapes(code)).toBe(code);
  });

  it("returns unclosed armor untouched", () => {
    // Also the shape the early bail-out exists for: many BEGIN markers
    // with no END is the regexes' quadratic worst case, and it is exactly
    // the input a half-finished paste produces.
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
    // All four kinds of key this app accepts arrive through the same
    // paste box and break the same way. Scoping the repair to `BEGIN
    // PGP` would have fixed one of them.
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
    // REGRESSION, from a real paste. This is the literal in
    // `gpg-wasm/src/tests.rs` selected in an editor and dropped into the
    // workspace -- and it broke, because it carries TWO layers of damage
    // at once: the `\n` escaping AND Rust's backslash-before-newline line
    // continuations. Every other fixture in this file was built by
    // applying ONE mechanical transformation to clean armor, which is a
    // model of the problem rather than the problem; this one was copied.
    //
    // The same shape comes out of C, shell and Python source.
    //
    // `BS` is one literal backslash. Spelling it out beats escaping
    // soup: `${BS}n` is the two characters a JSON escape leaves behind,
    // and a trailing `${BS}` is the continuation.
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
    // The rule is a backslash IMMEDIATELY before a newline. One sitting
    // mid-line is not a continuation and must not vanish -- otherwise the
    // rule stops being the reversal of a known transform and starts
    // deleting characters it does not understand.
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
    // A BEGIN whose END belongs to a different block must not swallow
    // the text between them -- that would splice unrelated content into
    // one armor block.
    const two = `${MESSAGE}\n\nsome prose with \\n in it\n\n${MESSAGE}`;
    const out = repairArmorEscapes(two);
    expect(out).toContain("some prose with \\n in it");
  });

  it("leaves a cleartext-signed message alone when it still has lines", () => {
    // Its body is FREE TEXT and can legitimately contain a backslash --
    // and it is the exact bytes the signature covers. Rewriting them
    // turns a valid signature into a tampering warning.
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
    // No real newline anywhere in the block is proof it went through an
    // escaper, so there is no ambiguity left to protect.
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
    // Collapse detection looks for a real newline after BEGIN. Run
    // first, it would see an escaped message as collapsed and hand it to
    // the base64 rewrapper -- the wrong repair for this damage.
    expect(blockIn(recoverArmorIfNeeded(MESSAGE.replaceAll("\n", "\\n")))).toBe(
      MESSAGE,
    );
  });

  it("still reconstructs a whitespace-collapsed selection", () => {
    // The original job of this module, unaffected.
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
