import type { KeyInfo } from "./types";
import * as wasm from "./wasm";

/** Parse an armored key for public-key metadata (strips isPrivate flag). */
export async function parsePublicKey(armored: string): Promise<KeyInfo> {
  const info = await wasm.parseKey(armored);
  return info.isPrivate ? { ...info, isPrivate: false } : info;
}

/** Parse an armored private key and extract metadata. */
export async function parsePrivateKey(armored: string): Promise<KeyInfo> {
  return wasm.parseKey(armored);
}

/** Extract the public key armor from a private key. */
export async function extractPublicKey(
  armoredPrivateKey: string,
): Promise<string> {
  return wasm.extractPublicKey(armoredPrivateKey);
}

/** Import an armored key (auto-detects public vs private). */
export async function importKey(armored: string): Promise<
  | { type: "public"; keyInfo: KeyInfo; armored: string }
  | {
      type: "private";
      keyInfo: KeyInfo;
      privateKeyArmored: string;
      publicKeyArmored: string;
      secretEncrypted: boolean;
    }
> {
  const trimmed = armored.trim();
  const keyInfo = await wasm.parseKey(trimmed);

  if (keyInfo.isPrivate) {
    const publicKeyArmored = await wasm.extractPublicKey(trimmed);
    const secretEncrypted = await wasm.isSecretEncrypted(trimmed);
    return {
      type: "private",
      keyInfo,
      privateKeyArmored: trimmed,
      publicKeyArmored,
      secretEncrypted,
    };
  }

  return { type: "public", keyInfo, armored: trimmed };
}

