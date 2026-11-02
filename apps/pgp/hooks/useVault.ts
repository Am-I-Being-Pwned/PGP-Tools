import { createContext, use } from "react";

import type { MasterPasskey } from "../lib/protection/vault-unlock";
import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import type { useKeySession } from "./useKeySession";

/** What the open vault offers every view: the one key session, the
 *  master passkey's reusable parts, and the key-level actions that also
 *  touch preferences. Provided by App while the vault is open. */
export interface VaultServices {
  session: ReturnType<typeof useKeySession>;
  /** The master passkey, or null for a password master. */
  masterPasskey: MasterPasskey | null;
  masterPasskeyCredentialId: string | undefined;
  /** Seal new passkey keys under the master's PRF salt, so the vault
   *  ceremony opens them. Only set while `unlockKeysOnOpen` is on. */
  masterSealSalt: ArrayBuffer | undefined;
  /** Cache a freshly generated/imported key's handle (never-cache off). */
  cacheKeys: boolean;
  onKeyCached: (keyId: string, handle: number) => void;
  /** Add a key; the first one becomes the default. */
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  /** Delete a key, clearing the default if it was the one. */
  deleteKey: (keyId: string) => Promise<void>;
  setDefaultKey: (keyId: string | null) => void;
}

export const VaultContext = createContext<VaultServices | null>(null);

export function useVault(): VaultServices {
  const vault = use(VaultContext);
  if (!vault) throw new Error("useVault outside an open vault");
  return vault;
}
