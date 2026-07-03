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
