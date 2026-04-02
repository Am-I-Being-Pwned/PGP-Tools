import { STORAGE_MASTER_PROTECTION } from "../constants";
import { getItem, setItem } from "./engine";

// ── types ───────────────────────────────────────────────────────────
//
// Security note: For the passkey path, `storedSecret` and `prfSalt` are
// stored in plaintext in Chrome storage. This is the standard WebAuthn PRF
// pattern — the actual key is derived via HKDF(PRF_output, storedSecret).
// An attacker who obtains Chrome storage still cannot derive the key
// without the authenticator's PRF output (requires biometric/PIN).
// The storedSecret provides defense against a compromised authenticator
// (attacker needs both the authenticator AND Chrome storage).

interface MasterPasskeyProtection {
  method: "passkey";
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 — see security note above
}

interface MasterPasswordProtection {
  method: "password";
  kdfSalt: string; // base64
  encryptedCanary: string; // base64
  canaryIv: string; // base64
}

export type MasterProtection =
  | MasterPasskeyProtection
  | MasterPasswordProtection;

// ── validation ──────────────────────────────────────────────────────

function isValidMasterProtection(v: unknown): v is MasterProtection {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o.method === "passkey") {
    return (
      typeof o.credentialId === "string" &&
      typeof o.prfSalt === "string" &&
      typeof o.storedSecret === "string"
    );
  }
  if (o.method === "password") {
    return (
      typeof o.kdfSalt === "string" &&
      typeof o.encryptedCanary === "string" &&
      typeof o.canaryIv === "string"
    );
  }
  return false;
}

// ── CRUD ────────────────────────────────────────────────────────────

export async function getMasterProtection(): Promise<MasterProtection | null> {
  const raw = await getItem<unknown>(STORAGE_MASTER_PROTECTION);
  if (isValidMasterProtection(raw)) return raw;
  return null;
}

export async function saveMasterProtection(
  mp: MasterProtection,
): Promise<void> {
  await setItem(STORAGE_MASTER_PROTECTION, mp);
}
