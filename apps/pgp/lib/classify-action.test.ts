import { describe, expect, it } from "vitest";

import { classifyAction } from "./classify-action";

describe("classifyAction", () => {
  it("classifies a public key block", () => {
    expect(classifyAction("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...")).toBe(
      "import-public",
    );
  });

  it("classifies a private key block", () => {
    expect(classifyAction("-----BEGIN PGP PRIVATE KEY BLOCK-----\n...")).toBe(
      "import-private",
    );
  });

  it("classifies an encrypted message", () => {
    expect(classifyAction("-----BEGIN PGP MESSAGE-----\n...")).toBe("decrypt");
  });

  it("classifies a cleartext-signed message", () => {
    expect(classifyAction("-----BEGIN PGP SIGNED MESSAGE-----\n...")).toBe(
      "verify",
    );
  });

  it("defaults to encrypt for plain text", () => {
    expect(classifyAction("hello world")).toBe("encrypt");
  });

  it("prefers key import when a selection contains both key and message", () => {
    const both =
      "-----BEGIN PGP MESSAGE-----\n...\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n...";
    expect(classifyAction(both)).toBe("import-public");
  });

  it("works on surrounding-text selections", () => {
    expect(
      classifyAction(
        "Here is my key: -----BEGIN PGP PUBLIC KEY BLOCK----- xyz",
      ),
    ).toBe("import-public");
  });
});

describe("classifyAction - age / SSH", () => {
  const ED25519_PUB =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com";

  it("classifies an armored age file as a decrypt", () => {
    expect(
      classifyAction("-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n"),
    ).toBe("decrypt");
  });

  it("classifies a binary age file by its magic line", () => {
    // The binary format has no armor header; its first line is the
    // version string, which is plain ASCII and survives a paste.
    expect(classifyAction("age-encryption.org/v1\n-> X25519 abc\n")).toBe(
      "decrypt",
    );
  });

  it("classifies an SSH public key line as a public import", () => {
    expect(classifyAction(ED25519_PUB)).toBe("import-public");
    expect(classifyAction("ssh-rsa AAAAB3NzaC1yc2EAAAA= bob@host")).toBe(
      "import-public",
    );
  });

  it("classifies an OpenSSH private key as a private import", () => {
    expect(
      classifyAction("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n"),
    ).toBe("import-private");
  });

  it("does not read an OpenSSH private key as a public one", () => {
    // The container holds the public half in its body; the private
    // check runs first so the whole file routes to the protect step.
    const text =
      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----";
    expect(classifyAction(text)).toBe("import-private");
  });

  it("still defaults to encrypt when SSH is only mentioned", () => {
    expect(classifyAction("send me your ssh-ed25519 key")).toBe("encrypt");
  });

  it("prefers an SSH key import over an age message in the same selection", () => {
    expect(
      classifyAction(
        `-----BEGIN AGE ENCRYPTED FILE-----\nx\n-----END AGE ENCRYPTED FILE-----\n${ED25519_PUB}`,
      ),
    ).toBe("import-public");
  });
});


/**
 * Routing must recognise every `.pub` the import flow can explain.
 *
 * `import/prepare.ts` forwards an SSH-shaped line of ANY algorithm to
 * `parseSshRecipient` so the engine's curated refusal is what the user
 * sees. That only helps if the right-click actually opens the import
 * flow: while this classifier used the narrow `ssh-ed25519|ssh-rsa`
 * matcher, a selected ECDSA / FIDO / `ssh-dss` `.pub` fell through to
 * `encrypt` and the message had no screen to appear on. The engine
 * decides validity; every layer above it forwards and displays.
 */
describe("classifyAction - SSH public keys of any algorithm", () => {
  it.each([
    ["ECDSA", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= a@host"],
    [
      "FIDO",
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9w a@host",
    ],
    ["DSA", "ssh-dss AAAAB3NzaC1kc3MAAACBAO0= a@host"],
  ])("routes a %s .pub line to the import flow", (_name, line) => {
    expect(classifyAction(line)).toBe("import-public");
  });

  it.each([
    ["prose about ECDSA", "we should probably move off ecdsa-sha2-nistp256"],
    ["HTML", "<p>ssh-ed25519 keys are listed below</p>"],
    ["bare base64", "AAAAB3NzaC1yc2EAAAADAQABAAABgQ=="],
  ])("still reads %s as text to encrypt", (_name, text) => {
    expect(classifyAction(text)).toBe("encrypt");
  });

  it("still leaves an armored OpenPGP block to the OpenPGP path", () => {
    // A base64 body line starting `AAAA` carries no space, so the wider
    // SSH shape cannot claim it -- and the PGP header is checked first.
    expect(
      classifyAction(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGabc\nAAAA+/abc=\n-----END PGP PUBLIC KEY BLOCK-----",
      ),
    ).toBe("import-public");
    expect(
      classifyAction("-----BEGIN PGP MESSAGE-----\nhQIMA\nAAAAabc=\n"),
    ).toBe("decrypt");
  });

  it("still routes an OpenSSH private key to the private import", () => {
    expect(
      classifyAction(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
      ),
    ).toBe("import-private");
  });
});
