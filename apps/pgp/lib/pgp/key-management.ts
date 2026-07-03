import type { KeyInfo } from "./types";
import * as wasm from "./wasm";

/** Import an armored key (auto-detects public vs private). */
export async function importKey(armored: string): Promise<
  | { type: "public"; keyInfo: KeyInfo; armored: string }
  | {
      type: "private";
      keyInfo: KeyInfo;
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
      publicKeyArmored,
      secretEncrypted,
    };
  }

  return { type: "public", keyInfo, armored: trimmed };
}

