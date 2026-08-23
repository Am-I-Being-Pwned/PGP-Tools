import { describe, expect, it } from "vitest";

import {
  looksLikeAgeMessage,
  looksLikeForeignSshPrivateKey,
  splitAgeBlocks,
  splitArmoredKeyBlocks,
  splitPublicKeyBlocks,
  splitSshPrivateKeyBlocks,
  splitSshPublicKeyCandidateLines,
  splitSshPublicKeyLines,
} from "./armor-blocks";

function publicBlock(body: string): string {
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${body}\n-----END PGP PUBLIC KEY BLOCK-----`;
}

function privateBlock(body: string): string {
  return `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${body}\n-----END PGP PRIVATE KEY BLOCK-----`;
}

describe("splitArmoredKeyBlocks", () => {
  it("splits a mixed dump into public and private blocks", () => {
    const text = [
      privateBlock("aaa"),
      publicBlock("bbb"),
      privateBlock("ccc"),
      publicBlock("ddd"),
    ].join("\n\n");
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    expect(publicKeys).toEqual([publicBlock("bbb"), publicBlock("ddd")]);
    expect(privateKeys).toEqual([privateBlock("aaa"), privateBlock("ccc")]);
  });

  it("ignores surrounding prose", () => {
    const text = `Here is my key:\n${publicBlock("xyz")}\nCheers!`;
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    expect(publicKeys).toEqual([publicBlock("xyz")]);
    expect(privateKeys).toEqual([]);
  });

  it("returns empty lists for non-armor text", () => {
    expect(splitArmoredKeyBlocks("nothing here")).toEqual({
      publicKeys: [],
      privateKeys: [],
      sshPublicKeys: [],
      sshPrivateKeys: [],
    });
  });

  it("splits SSH keys out of a dump that also holds PGP armor", () => {
    const text = [
      publicBlock("bbb"),
      ED25519_PUB,
      sshPrivateBlock("sss"),
      RSA_PUB,
    ].join("\n\n");
    const blocks = splitArmoredKeyBlocks(text);
    expect(blocks.publicKeys).toEqual([publicBlock("bbb")]);
    expect(blocks.sshPublicKeys).toEqual([ED25519_PUB, RSA_PUB]);
    expect(blocks.sshPrivateKeys).toEqual([sshPrivateBlock("sss")]);
  });

  it("does not confuse private blocks for public ones", () => {
    expect(splitPublicKeyBlocks(privateBlock("aaa"))).toEqual([]);
  });

  it("is safe to call repeatedly (global regex state)", () => {
    const text = publicBlock("abc");
    expect(splitPublicKeyBlocks(text)).toHaveLength(1);
    expect(splitPublicKeyBlocks(text)).toHaveLength(1);
  });
});

// ── age / SSH ────────────────────────────────────────────────────────
//
// Throwaway public keys, structurally real but generated for this file:
// `ssh-<type> AAAA<base64>[ comment]`. The `AAAA` prefix is not
// decoration -- every SSH wire blob starts with a 4-byte big-endian
// length, so the splitter requires it, and these fixtures must carry it
// to exercise the same path a real key takes.

const ED25519_PUB =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com";
const RSA_PUB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7abc+def/ghi= bob@host";

function sshPrivateBlock(body: string): string {
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----`;
}

function ageBlock(body: string): string {
  return `-----BEGIN AGE ENCRYPTED FILE-----\n${body}\n-----END AGE ENCRYPTED FILE-----`;
}

describe("splitSshPublicKeyLines", () => {
  it("splits an authorized_keys paste, one entry per line", () => {
    expect(splitSshPublicKeyLines(`${ED25519_PUB}\n${RSA_PUB}\n`)).toEqual([
      ED25519_PUB,
      RSA_PUB,
    ]);
  });

  it("keeps the comment, which is the key's only name", () => {
    // `sshUserIds` reads the comment off the parsed line for the display
    // name; dropping it here would leave an SSH contact anonymous.
    expect(splitSshPublicKeyLines(ED25519_PUB)[0]).toMatch(
      /alice@example\.com$/,
    );
  });

  it("accepts a key with no comment at all", () => {
    const bare = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu";
    expect(splitSshPublicKeyLines(bare)).toEqual([bare]);
  });

  it("trims leading whitespace from an indented paste", () => {
    expect(splitSshPublicKeyLines(`    ${ED25519_PUB}`)).toEqual([ED25519_PUB]);
  });

  it("does not fire on prose that merely names a key type", () => {
    expect(
      splitSshPublicKeyLines("my ssh-ed25519 key is on the other laptop"),
    ).toEqual([]);
    expect(splitSshPublicKeyLines("ssh-ed25519 please")).toEqual([]);
  });

  it("does not fire on unsupported key types", () => {
    // age handles ssh-ed25519 and ssh-rsa only. An ssh-dss line must not
    // be silently swallowed as a recipient the engine would then refuse.
    expect(
      splitSshPublicKeyLines("ssh-dss AAAAB3NzaC1kc3MAAACBAO body@host"),
    ).toEqual([]);
  });

  it("does not match inside an armored body", () => {
    // Base64 armor lines carry no spaces, so no line inside a block can
    // look like `<type> <base64>`.
    expect(
      splitSshPublicKeyLines(sshPrivateBlock("b3BlbnNzaC1rZXktdjEA")),
    ).toEqual([]);
    expect(splitSshPublicKeyLines(publicBlock("mQINBGabc"))).toEqual([]);
  });
});

describe("splitSshPrivateKeyBlocks / splitAgeBlocks", () => {
  it("splits several OpenSSH private key containers", () => {
    const text = `${sshPrivateBlock("aaa")}\n\n${sshPrivateBlock("bbb")}`;
    expect(splitSshPrivateKeyBlocks(text)).toEqual([
      sshPrivateBlock("aaa"),
      sshPrivateBlock("bbb"),
    ]);
  });

  it("splits armored age blocks out of surrounding prose", () => {
    const text = `here you go:\n${ageBlock("YWdlLWJvZHk")}\ncheers`;
    expect(splitAgeBlocks(text)).toEqual([ageBlock("YWdlLWJvZHk")]);
  });

  it("does not confuse an age block with a PGP message", () => {
    expect(splitAgeBlocks("-----BEGIN PGP MESSAGE-----\nx\n")).toEqual([]);
  });
});

describe("looksLikeAgeMessage", () => {
  it("recognises both the armored and the binary form", () => {
    expect(looksLikeAgeMessage(ageBlock("x"))).toBe(true);
    // Binary age files open with the version line in plain ASCII.
    expect(looksLikeAgeMessage("age-encryption.org/v1\n-> X25519 abc")).toBe(
      true,
    );
  });

  it("does not fire on PGP or plain text", () => {
    expect(looksLikeAgeMessage("-----BEGIN PGP MESSAGE-----")).toBe(false);
    expect(looksLikeAgeMessage("hello world")).toBe(false);
  });
});

/**
 * Recognition, deliberately not acceptance: `gpg-wasm/src/age.rs` has an
 * actionable message for each of these formats ("export it with
 * PuTTYgen", "convert it with `ssh-keygen -p -f`"), and none of them
 * could ever be shown while nothing recognised the format as SSH's.
 */
describe("looksLikeForeignSshPrivateKey", () => {
  it.each([
    ["a PuTTY .ppk", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"],
    [
      "PKCS#8",
      "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----\n",
    ],
    [
      "encrypted PKCS#8",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
    ],
    [
      "a legacy encrypted PEM",
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nZmFrZQ==\n",
    ],
    ["a leading-whitespace paste", "\n  PuTTY-User-Key-File-2: ssh-rsa\n"],
  ])("recognises %s", (_name, text) => {
    expect(looksLikeForeignSshPrivateKey(text)).toBe(true);
  });

  it.each([
    // A CRX signing key, and the age engine must not steal it.
    [
      "an unencrypted PKCS#1 PEM",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n",
    ],
    ["an OpenSSH container", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n"],
    ["a PGP private block", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ==\n"],
    ["a .pub line", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA alice@host"],
    ["prose that names PuTTY", "I tried PuTTY-User-Key-File once."],
    ["nothing at all", ""],
  ])("leaves %s alone", (_name, text) => {
    expect(looksLikeForeignSshPrivateKey(text)).toBe(false);
  });
});

describe("splitSshPublicKeyCandidateLines", () => {
  // The wide form, for the GitHub path: it forwards a line the engine
  // will refuse, so the user gets "ECDSA keys are not supported" rather
  // than "this account has published no keys". See the doc comment on
  // SSH_PUBLIC_CANDIDATE_LINE -- the narrow matcher above is what caused
  // that, twice.
  it.each([
    ["ecdsa", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA"],
    ["fido", "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9w"],
    ["fido ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNh"],
    ["dss", "ssh-dss AAAAB3NzaC1kc3MAAACBAO body@host"],
    ["ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu alice@host"],
    ["rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ"],
  ])("forwards a %s line", (_label, line) => {
    expect(splitSshPublicKeyCandidateLines(line)).toEqual([line]);
  });

  it("still refuses prose, html and bare base64", () => {
    expect(
      splitSshPublicKeyCandidateLines("my ssh-ed25519 key is on the laptop"),
    ).toEqual([]);
    expect(splitSshPublicKeyCandidateLines("ssh-ed25519 please")).toEqual([]);
    expect(
      splitSshPublicKeyCandidateLines("<p>Your account is suspended</p>"),
    ).toEqual([]);
    expect(
      splitSshPublicKeyCandidateLines("AAAAB3NzaC1yc2EAAAADAQABAAABgQ"),
    ).toEqual([]);
  });

  it("does not match a real armored body", () => {
    // Same reason as the narrow matcher: armor lines carry no spaces, so
    // none of them can look like `<type> <base64>`, and armor HEADER
    // lines (`Version:`, `Comment:`, `Proc-Type:`) carry a colon the
    // algorithm token cannot contain.
    //
    // This form IS now applied to pasted and dropped text, not only to a
    // GitHub `key` field -- `import/prepare.ts`, `classify-action.ts`
    // and `drop-routing.ts` all use it, so this test guards a real path
    // rather than a hypothetical one. That is exactly why the exclusions
    // below matter: a paste is arbitrary user text, and mistaking part
    // of an armored block for a key line would hand the engine garbage.
    expect(splitSshPublicKeyCandidateLines(publicBlock("mQINBGabc"))).toEqual(
      [],
    );
    expect(
      splitSshPublicKeyCandidateLines(sshPrivateBlock("b3BlbnNzaC1rZXk")),
    ).toEqual([]);
  });

  it("is a superset of the narrow matcher", () => {
    const text = `${ED25519_PUB}\n${RSA_PUB}`;
    expect(splitSshPublicKeyCandidateLines(text)).toEqual(
      splitSshPublicKeyLines(text),
    );
  });
});
