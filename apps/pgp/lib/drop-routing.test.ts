import { describe, expect, it } from "vitest";

import type { DropRule, DropSample } from "./drop-routing";
import {
  looksLikeKey,
  looksLikePrivateKey,
  resolveDropRule,
} from "./drop-routing";

function sample(text: string): DropSample {
  return { files: [], text, sampleText: text };
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

  it("does not fire on a plain message or a stray substring", () => {
    expect(looksLikeKey("-----BEGIN PGP MESSAGE-----\n...")).toBe(false);
    expect(looksLikeKey("please send me your private key")).toBe(false);
    expect(looksLikeKey("hello world")).toBe(false);
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
