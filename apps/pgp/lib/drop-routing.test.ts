import { describe, expect, it } from "vitest";

import type { DropRule, DropSample } from "./drop-routing";
import {
  looksLikeKey,
  looksLikePrivateKey,
  looksLikeSshPublicKey,
  resolveDropRule,
} from "./drop-routing";

const ED25519_PUB =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com";

function sample(text: string): DropSample {
  return { files: [], text, sampleText: text, hasBinaryKeyFile: false };
}

describe("looksLikeKey", () => {
  it("detects a PGP public key block", () => {
    expect(looksLikeKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...")).toBe(
      true,
    );
  });

  it("detects a PGP private key block", () => {
    expect(looksLikeKey("-----BEGIN PGP PRIVATE KEY BLOCK-----\n...")).toBe(
      true,
    );
  });

  it("detects a raw RSA PEM (CRX signing key)", () => {
    expect(looksLikeKey("-----BEGIN RSA PRIVATE KEY-----\n...")).toBe(true);
    expect(looksLikeKey("-----BEGIN PRIVATE KEY-----\n...")).toBe(true);
  });

  it("finds a key header amid surrounding text", () => {
    expect(
      looksLikeKey("my key:\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc"),
    ).toBe(true);
  });

  it("detects an SSH public key line, which carries no armor header", () => {
    // The private-key regex is anchored to "-----BEGIN ", so a dropped
    // `id_ed25519.pub` matches nothing there. Before this it fell
    // through to the workspace and was treated as a message to encrypt.
    expect(looksLikeKey(ED25519_PUB)).toBe(true);
    expect(looksLikeKey("ssh-rsa AAAAB3NzaC1yc2EAAAA= bob@host")).toBe(true);
  });

  it("detects an OpenSSH private key, which now has somewhere to land", () => {
    expect(looksLikeKey("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl")).toBe(
      true,
    );
  });

  it("does not fire on a plain message or a stray substring", () => {
    expect(looksLikeKey("-----BEGIN PGP MESSAGE-----\n...")).toBe(false);
    expect(looksLikeKey("please send me your private key")).toBe(false);
    expect(looksLikeKey("hello world")).toBe(false);
    expect(looksLikeKey("my ssh-ed25519 key is on the other laptop")).toBe(
      false,
    );
  });
});

describe("looksLikeSshPublicKey", () => {
  it("matches a .pub line and an authorized_keys paste", () => {
    expect(looksLikeSshPublicKey(ED25519_PUB)).toBe(true);
    expect(
      looksLikeSshPublicKey(`${ED25519_PUB}\nssh-rsa AAAAB3Nza= b@h\n`),
    ).toBe(true);
  });

  it("does not match an OpenSSH PRIVATE key container", () => {
    // The container embeds the public half, but only inside base64 --
    // a private key must route to the protect step, never to contacts.
    expect(
      looksLikeSshPublicKey(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
      ),
    ).toBe(false);
  });

  it("does not match an age message", () => {
    expect(looksLikeSshPublicKey("-----BEGIN AGE ENCRYPTED FILE-----")).toBe(
      false,
    );
  });
});

describe("looksLikePrivateKey", () => {
  it("covers every armored private-key flavour", () => {
    for (const header of [
      "-----BEGIN PGP PRIVATE KEY BLOCK-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
    ]) {
      expect(looksLikePrivateKey(`${header}\nabc`)).toBe(true);
    }
  });

  it("does not fire on public keys or plain text", () => {
    expect(looksLikePrivateKey("-----BEGIN PGP PUBLIC KEY BLOCK-----")).toBe(
      false,
    );
    expect(looksLikePrivateKey("here is my private key, thanks")).toBe(false);
  });
});

describe("resolveDropRule", () => {
  const rules: DropRule[] = [
    {
      id: "keys",
      match: (s) => looksLikeKey(s.sampleText),
      run: () => undefined,
    },
    { id: "workspace", match: () => true, run: () => undefined },
  ];

  it("routes a key to the keys rule", () => {
    expect(
      resolveDropRule(rules, sample("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        ?.id,
    ).toBe("keys");
  });

  it("routes a dropped SSH public key to the keys rule, not the workspace", () => {
    expect(resolveDropRule(rules, sample(ED25519_PUB))?.id).toBe("keys");
  });

  it("routes a dropped OpenSSH private key to the keys rule", () => {
    expect(
      resolveDropRule(
        rules,
        sample("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl"),
      )?.id,
    ).toBe("keys");
  });

  it("falls through to the catch-all for anything else", () => {
    expect(resolveDropRule(rules, sample("just some text"))?.id).toBe(
      "workspace",
    );
  });

  it("returns null when no rule matches", () => {
    const noCatchAll: DropRule[] = [rules[0]];
    expect(resolveDropRule(noCatchAll, sample("plain text"))).toBeNull();
  });
});

/**
 * The third file that has to agree: a dropped `.pub` of any algorithm is
 * a key, so the "keys" rule owns the drop and `prepareImport` gets to
 * show the engine's refusal. With the narrow matcher an ECDSA or FIDO
 * `.pub` landed in the workspace as if it were a message to encrypt.
 * The engine decides validity; every layer above it forwards and
 * displays.
 */
describe("looksLikeSshPublicKey - any algorithm", () => {
  const rules: DropRule[] = [
    { id: "keys", match: (s) => looksLikeKey(s.sampleText), run: () => undefined },
    { id: "workspace", match: () => true, run: () => undefined },
  ];

  it.each([
    ["ECDSA", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= a@host"],
    [
      "FIDO",
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9w a@host",
    ],
    ["DSA", "ssh-dss AAAAB3NzaC1kc3MAAACBAO0= a@host"],
  ])("routes a dropped %s .pub to the key import", (_name, line) => {
    expect(looksLikeSshPublicKey(line)).toBe(true);
    expect(looksLikeKey(line)).toBe(true);
    expect(resolveDropRule(rules, sample(line))?.id).toBe("keys");
  });

  it.each([
    ["prose about ECDSA", "we should probably move off ecdsa-sha2-nistp256"],
    ["HTML", "<p>ssh-ed25519 keys are listed below</p>"],
    ["bare base64", "AAAAB3NzaC1yc2EAAAADAQABAAABgQ=="],
  ])("leaves %s to the workspace", (_name, text) => {
    expect(looksLikeSshPublicKey(text)).toBe(false);
    expect(resolveDropRule(rules, sample(text))?.id).toBe("workspace");
  });

  it("does not claim an armored block's body", () => {
    const armored =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGabc\nAAAA+/abc=\n-----END PGP PUBLIC KEY BLOCK-----";
    expect(looksLikeSshPublicKey(armored)).toBe(false);
    const openssh =
      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----";
    expect(looksLikeSshPublicKey(openssh)).toBe(false);
    // Still a private key, and still routed as one.
    expect(looksLikePrivateKey(openssh)).toBe(true);
  });

  it("does not claim a raw RSA PEM (the CRX signing key)", () => {
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    expect(looksLikeSshPublicKey(pem)).toBe(false);
    expect(looksLikePrivateKey(pem)).toBe(true);
  });
});
