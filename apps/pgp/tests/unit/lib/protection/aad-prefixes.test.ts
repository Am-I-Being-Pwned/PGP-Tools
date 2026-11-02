/**
 * Cross-language consistency of the AAD prefixes and HKDF info strings
 * (Rust in `gpg-wasm/src/{protect,sessions,crx,age}.rs`; TS doc-comment templates).
 * Drift is silent and total: every blob on disk fails its tag check. So
 * values are pinned to literals, and TS templates are compared to the
 * Rust constants. `gpg-wasm/src/**` is read, never written.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const APP_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
);
const WASM_SRC = join(APP_DIR, "gpg-wasm", "src");

/** Read until two consecutive reads agree (sources may be mid-edit). */
function readStable(path: string): string {
  let previous = readFileSync(path, "utf8");
  for (let i = 0; i < 5; i++) {
    const next = readFileSync(path, "utf8");
    if (next === previous) return next;
    previous = next;
  }
  return previous;
}

/** Value of a top-level Rust `const NAME: &str|&[u8] = ...`. */
function rustConst(file: string, name: string): string {
  const src = readStable(join(WASM_SRC, file));
  const re = new RegExp(
    `\\bconst\\s+${name}\\s*:\\s*&(?:'static\\s+)?(?:str|\\[u8(?:\\s*;\\s*\\d+)?\\])\\s*=\\s*b?"((?:[^"\\\\]|\\\\.)*)"\\s*;`,
  );
  const match = re.exec(src);
  if (!match) throw new Error(`${name} not found in gpg-wasm/src/${file}`);
  return match[1];
}

function tsSource(...parts: string[]): string {
  return readStable(join(APP_DIR, "src", ...parts));
}

// Changing a value here changes the on-disk format of every stored key.
const EXPECTED = {
  pgpPassword: "gpg-tools:password:",
  pgpPasskey: "gpg-tools:passkey:",
  crxPassword: "gpg-tools:crx-password:",
  crxPasskey: "gpg-tools:crx-passkey:",
  sshPassword: "gpg-tools:ssh-password:",
  sshPasskey: "gpg-tools:ssh-passkey:",
  pgpPrfInfo: "gpg-tools-prf-v1",
  crxPrfInfo: "gpg-tools-crx-prf-v1",
  sshPrfInfo: "gpg-tools-ssh-prf-v1",
  storeAad: "gpg-tools:store:v1:",
  storeSubkeyInfo: "gpg-tools:store-subkey:v1:",
};

describe("wasm AAD prefixes", () => {
  it("match the literals every stored blob was sealed under", () => {
    expect(rustConst("protect.rs", "PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.pgpPassword,
    );
    expect(rustConst("protect.rs", "PASSKEY_AAD_PREFIX")).toBe(
      EXPECTED.pgpPasskey,
    );
    expect(rustConst("crx.rs", "CRX_PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.crxPassword,
    );
    expect(rustConst("crx.rs", "CRX_PASSKEY_AAD_PREFIX")).toBe(
      EXPECTED.crxPasskey,
    );
    // age/SSH identities, bound to the SHA256 fingerprint.
    expect(rustConst("age.rs", "SSH_PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.sshPassword,
    );
    expect(rustConst("age.rs", "SSH_PASSKEY_AAD_PREFIX")).toBe(
      EXPECTED.sshPasskey,
    );
    expect(rustConst("sessions.rs", "STORE_AAD_PREFIX")).toBe(
      EXPECTED.storeAad,
    );
    expect(rustConst("sessions.rs", "STORE_SUBKEY_INFO_PREFIX")).toBe(
      EXPECTED.storeSubkeyInfo,
    );
  });

  it("keep the PRF HKDF info strings distinct per key type", () => {
    // Colliding info strings would let one ceremony derive the same AES
    // key for a PGP cert and a CRX key.
    expect(rustConst("protect.rs", "PASSKEY_HKDF_INFO")).toBe(
      EXPECTED.pgpPrfInfo,
    );
    expect(rustConst("crx.rs", "CRX_PRF_HKDF_INFO")).toBe(EXPECTED.crxPrfInfo);
    expect(rustConst("age.rs", "SSH_PRF_HKDF_INFO")).toBe(EXPECTED.sshPrfInfo);
    const infos = [
      EXPECTED.pgpPrfInfo,
      EXPECTED.crxPrfInfo,
      EXPECTED.sshPrfInfo,
    ];
    expect(new Set(infos).size).toBe(infos.length);
  });

  it("no prefix is a prefix of another", () => {
    // Prefix-free, or some (prefix, identity) pair could collide with
    // another key type's AAD.
    const all = [
      EXPECTED.pgpPassword,
      EXPECTED.pgpPasskey,
      EXPECTED.crxPassword,
      EXPECTED.crxPasskey,
      EXPECTED.sshPassword,
      EXPECTED.sshPasskey,
      EXPECTED.storeAad,
    ];
    for (const a of all) {
      for (const b of all) {
        if (a === b) continue;
        expect(b.startsWith(a)).toBe(false);
      }
    }
    expect(new Set(all).size).toBe(all.length);
  });
});

describe("TypeScript-side documentation of the same prefixes", () => {
  it("expands `gpg-tools:{method}:{keyId}` to the two OpenPGP prefixes", () => {
    const src = tsSource("lib", "protection", "encrypt-private-key.ts");
    expect(src).toContain("gpg-tools:{method}:{keyId}");
    for (const method of ["password", "passkey"] as const) {
      expect(`gpg-tools:{method}:`.replace("{method}", method)).toBe(
        rustConst("protect.rs", `${method.toUpperCase()}_AAD_PREFIX`),
      );
    }
  });

  it("expands `gpg-tools:crx-{password,passkey}:{extensionId}` to the CRX prefixes", () => {
    const src = tsSource("lib", "crx", "types.ts");
    const template = "gpg-tools:crx-{password,passkey}:{extensionId}";
    expect(src).toContain(template);
    const [head, tail] = template.split("{password,passkey}");
    expect(tail).toBe(":{extensionId}");
    expect(`${head}password:`).toBe(
      rustConst("crx.rs", "CRX_PASSWORD_AAD_PREFIX"),
    );
    expect(`${head}passkey:`).toBe(
      rustConst("crx.rs", "CRX_PASSKEY_AAD_PREFIX"),
    );
  });

  it("documents the store envelope's domain binding with the wasm strings", () => {
    // Slot binding: a blob opens only in the slot it was written to.
    const src = tsSource("lib", "storage", "envelope.ts");
    expect(src).toContain(`${EXPECTED.storeSubkeyInfo}<domain>`);
    expect(src).toContain(`${EXPECTED.storeAad}<domain>`);
  });
});
