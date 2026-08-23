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

