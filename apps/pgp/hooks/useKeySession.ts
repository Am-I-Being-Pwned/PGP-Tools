import { useCallback, useEffect, useRef, useState } from "react";

import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import type { AutoLockTimeout } from "../lib/storage/preferences";
import { fromBase64 } from "../lib/encoding";
import * as wasmApi from "../lib/pgp/wasm";
import { authenticateAndGetPrf } from "../lib/protection/webauthn-prf";
import {
  encryptedBlobFromProtected,
  updateLastUsed,
} from "../lib/storage/keyring";

import {
  ARGON2_MEMORY_KIB,
  ARGON2_ITERATIONS,
  ARGON2_PARALLELISM,
} from "../lib/protection/password-kdf";

interface KeySessionOptions {
  autoLockMinutes: AutoLockTimeout;
  lockOnClose: boolean;
  neverCacheKeys: boolean;
}

/**
 * Manages unlocked key sessions using WASM key handles.
 *
 * Unlock happens entirely in WASM: the encrypted blob bytes are
 * passed directly to WASM which does KDF + AES-GCM decrypt + store.
 * The decrypted private key never enters the JS heap.
 */
export function useKeySession(opts: KeySessionOptions) {
  const handleRef = useRef(new Map<string, number>());
  const [unlockedKeyIds, setUnlockedKeyIds] = useState<Set<string>>(new Set());
  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const doLockAll = useCallback(() => {
    for (const handle of handleRef.current.values()) {
      void wasmApi.dropKey(handle);
    }
    handleRef.current.clear();
    setUnlockedKeyIds(new Set());
  }, []);

  const resetLockTimer = useCallback(() => {
    if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    lockTimerRef.current = setTimeout(
      doLockAll,
      opts.autoLockMinutes * 60 * 1000,
    );
  }, [opts.autoLockMinutes, doLockAll]);

  const lockAllIfNoCache = useCallback(() => {
    if (opts.neverCacheKeys) doLockAll();
  }, [opts.neverCacheKeys, doLockAll]);

  useEffect(() => {
    return () => {
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (!opts.lockOnClose) return;
    const handler = () => {
      if (document.visibilityState === "hidden") {
        doLockAll();
      }
    };
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, [opts.lockOnClose, doLockAll]);

  const markHandleUnlocked = useCallback(
    async (keyId: string, handle: number) => {
      handleRef.current.set(keyId, handle);
      setUnlockedKeyIds((prev) => new Set([...prev, keyId]));
      await updateLastUsed(keyId);
      resetLockTimer();
    },
    [resetLockTimer],
  );

  const unlocking = useRef(false);

  const unlockWithPassword = useCallback(
    async (blob: ProtectedKeyBlob, password: string): Promise<boolean> => {
      if (unlocking.current) return false;

      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "password") return false;

      const passwordBytes = new TextEncoder().encode(password);
      unlocking.current = true;
      try {
        const handle = await wasmApi.unlockWithPassword(
          new Uint8Array(fromBase64(encrypted.ciphertext)),
          new Uint8Array(fromBase64(encrypted.iv)),
          new Uint8Array(fromBase64(encrypted.salt)),
          blob.keyId,
          passwordBytes,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        );

        await markHandleUnlocked(blob.keyId, handle);
        return true;
      } catch {
        return false;
      } finally {
        passwordBytes.fill(0);
        unlocking.current = false;
      }
    },
    [markHandleUnlocked],
  );

  const unlockWithPasskey = useCallback(
    async (blob: ProtectedKeyBlob): Promise<boolean> => {
      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "passkey") return false;

      let prfOutput: Uint8Array | undefined;
      try {
        ({ prfOutput } = await authenticateAndGetPrf(
          encrypted.credentialId,
          fromBase64(encrypted.prfSalt),
        ));

        const handle = await wasmApi.unlockWithPrf(
          new Uint8Array(fromBase64(encrypted.ciphertext)),
          new Uint8Array(fromBase64(encrypted.iv)),
          prfOutput,
          new Uint8Array(fromBase64(encrypted.storedSecret)),
          blob.keyId,
        );

        await markHandleUnlocked(blob.keyId, handle);
        return true;
      } catch {
        return false;
      } finally {
        prfOutput?.fill(0);
      }
    },
    [markHandleUnlocked],
  );

  const lock = useCallback((keyId: string) => {
    const handle = handleRef.current.get(keyId);
    if (handle !== undefined) {
      void wasmApi.dropKey(handle);
    }
    handleRef.current.delete(keyId);
    setUnlockedKeyIds((prev) => {
      const next = new Set(prev);
      next.delete(keyId);
      return next;
    });
  }, []);

  const getKeyHandle = useCallback((keyId: string): number | null => {
    return handleRef.current.get(keyId) ?? null;
  }, []);

  const isUnlocked = useCallback(
    (keyId: string): boolean => {
      return unlockedKeyIds.has(keyId);
    },
    [unlockedKeyIds],
  );

  return {
    unlockWithPassword,
    unlockWithPasskey,
    lock,
    lockAll: doLockAll,
    lockAllIfNoCache,
    getKeyHandle,
    isUnlocked,
    unlockedKeyIds,
  };
}
