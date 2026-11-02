import { createContext, use } from "react";

import type { MasterPasskey } from "~/lib/protection/vault-unlock";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import type { useKeySession } from "./useKeySession";

export interface VaultServices {
  session: ReturnType<typeof useKeySession>;
  masterPasskey: MasterPasskey | null;
  masterPasskeyCredentialId: string | undefined;
  /** Only set while `unlockKeysOnOpen` is on. */
  masterSealSalt: ArrayBuffer | undefined;
  cacheKeys: boolean;
  onKeyCached: (keyId: string, handle: number) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  deleteKey: (keyId: string) => Promise<void>;
  setDefaultKey: (keyId: string | null) => void;
}

export const VaultContext = createContext<VaultServices | null>(null);

export function useVault(): VaultServices {
  const vault = use(VaultContext);
  if (!vault) throw new Error("useVault outside an open vault");
  return vault;
}
