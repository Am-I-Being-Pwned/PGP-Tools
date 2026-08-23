/**
 * Cross-language consistency of the AAD prefixes and HKDF info strings.
 *
 * Every private key this vault stores is sealed with its own identity
 * bound into the AEAD's AAD -- `gpg-tools:password:<fingerprint>` for an
 * OpenPGP cert under a password, `gpg-tools:crx-passkey:<extensionId>`
 * for a CRX signing key under a passkey, and so on. The strings live in
 * Rust (`gpg-wasm/src/lib.rs`, `gpg-wasm/src/crx.rs`,
 * `gpg-wasm/src/age.rs`), which is what
 * actually seals and opens; the TypeScript side documents them at every
 * call site that has to reason about the format, with a "keep in sync"
 * note and no compiler anywhere to enforce it.
 *
 * Drift is silent and total: change one prefix and every blob already on
 * disk fails its tag check on the next unlock, with no error that names
 * the cause and no way back. The values are therefore asserted against
 * literals here (a check derived from the source would agree with any
 * edit), and the TS doc-comment templates are expanded and compared to
 * the Rust constants, so a rename on either side fails this test.
 *
 * Modelled on `scripts/audit-invariants.mjs`: source read as data,
 * nothing pinned to a line number. `gpg-wasm/src/**` is READ here and
 * never written.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const APP_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WASM_SRC = join(APP_DIR, "gpg-wasm", "src");

/**
 * Read a file, tolerating a torn read: these Rust sources may be edited
 * while the suite runs, so a read is only trusted once two consecutive
 * reads agree.
 */
function readStable(path: string): string {
  let previous = readFileSync(path, "utf8");
  for (let i = 0; i < 5; i++) {
    const next = readFileSync(path, "utf8");
    if (next === previous) return next;
    previous = next;
  }
  return previous;
}

/**
 * The value of a top-level `const NAME: &str = "..."` or
 * `const NAME: &[u8] = b"..."`. Matched on the declaration itself rather
 * than a position in the file, so reordering or reformatting the Rust
 * doesn't break this.
 */
function rustConst(file: string, name: string): string {
  const src = readStable(join(WASM_SRC, file));
  const re = new RegExp(
    `\\bconst\\s+${name}\\s*:\\s*&(?:'static\\s+)?(?:str|\\[u8(?:\\s*;\\s*\\d+)?\\])\\s*=\\s*b?"((?:[^"\\\\]|\\\\.)*)"\\s*;`,
  );
  const match = re.exec(src);
  if (!match) throw new Error(`${name} not found in gpg-wasm/src/${file}`);
  return match[1];
}

/** A TS source file, read as data for its doc comments. */
function tsSource(...parts: string[]): string {
  return readStable(join(APP_DIR, ...parts));
}

// The single source of truth for this test. Changing a value here is
// changing the on-disk format of every key a user already has.
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
    expect(rustConst("lib.rs", "PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.pgpPassword,
    );
    expect(rustConst("lib.rs", "PASSKEY_AAD_PREFIX")).toBe(EXPECTED.pgpPasskey);
    expect(rustConst("crx.rs", "CRX_PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.crxPassword,
    );
    expect(rustConst("crx.rs", "CRX_PASSKEY_AAD_PREFIX")).toBe(
      EXPECTED.crxPasskey,
    );
    // age/SSH identities: imported SSH keys, sealed by `gpg-wasm/src/age.rs`
    // under the same envelope and bound to the key's SHA256 fingerprint.
    expect(rustConst("age.rs", "SSH_PASSWORD_AAD_PREFIX")).toBe(
      EXPECTED.sshPassword,
    );
    expect(rustConst("age.rs", "SSH_PASSKEY_AAD_PREFIX")).toBe(
      EXPECTED.sshPasskey,
    );
    expect(rustConst("lib.rs", "STORE_AAD_PREFIX")).toBe(EXPECTED.storeAad);
    expect(rustConst("lib.rs", "STORE_SUBKEY_INFO_PREFIX")).toBe(
      EXPECTED.storeSubkeyInfo,
    );
  });

  it("keep the PRF HKDF info strings distinct per key type", () => {
    // Same authenticator, same PRF output: if the info strings collided,
    // one ceremony would derive the same AES key for an OpenPGP cert and
    // a CRX signing key. `protected.rs` calls this out as the reason the
    // info string is a parameter and never a default.
    expect(rustConst("lib.rs", "PASSKEY_HKDF_INFO")).toBe(EXPECTED.pgpPrfInfo);
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
    // The identity is appended to the prefix, so if one prefix were a
    // prefix of another, some (prefix, identity) pair could produce the
    // same AAD bytes as a different key type's -- which is precisely the
    // cross-type confusion the prefixes exist to prevent.
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
    // `encrypt-private-key.ts` is what a reader of the keyring format
    // consults; its template is the TS half of "keep in sync".
    const src = tsSource("lib", "protection", "encrypt-private-key.ts");
    expect(src).toContain("gpg-tools:{method}:{keyId}");
    for (const method of ["password", "passkey"] as const) {
      expect(`gpg-tools:{method}:`.replace("{method}", method)).toBe(
        rustConst("lib.rs", `${method.toUpperCase()}_AAD_PREFIX`),
      );
    }
  });

  it("expands `gpg-tools:crx-{password,passkey}:{extensionId}` to the CRX prefixes", () => {
    const src = tsSource("lib", "crx", "types.ts");
    const template = "gpg-tools:crx-{password,passkey}:{extensionId}";
    expect(src).toContain(template);
    const [head, tail] = template.split("{password,passkey}");
    expect(tail).toBe(":{extensionId}");
    expect(`${head}password:`).toBe(rustConst("crx.rs", "CRX_PASSWORD_AAD_PREFIX"));
    expect(`${head}passkey:`).toBe(rustConst("crx.rs", "CRX_PASSKEY_AAD_PREFIX"));
  });

  it("documents the store envelope's domain binding with the wasm strings", () => {
    // `envelope.ts` promises a blob only opens in the storage slot it was
    // written to. That promise is these two strings.
    const src = tsSource("lib", "storage", "envelope.ts");
    expect(src).toContain(`${EXPECTED.storeSubkeyInfo}<domain>`);
    expect(src).toContain(`${EXPECTED.storeAad}<domain>`);
  });
});
