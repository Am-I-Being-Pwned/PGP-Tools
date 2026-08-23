import { useCallback, useEffect, useRef, useState } from "react";

import type { StoredKeyKind } from "../lib/storage/key-kind";
import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import type { AutoLockTimeout } from "../lib/storage/preferences";
import { closeSshIdentity, openSshIdentity } from "../lib/age/protect-flow";
import { fromBase64 } from "../lib/encoding";
import * as wasmApi from "../lib/pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../lib/protection/password-kdf";
import { authenticateAndGetPrf } from "../lib/protection/webauthn-prf";
import { storedKeyKind } from "../lib/storage/key-kind";
import {
  encryptedBlobFromProtected,
  updateLastUsed,
} from "../lib/storage/keyring";

interface KeySessionOptions {
  autoLockMinutes: AutoLockTimeout;
  /** When false, the inactivity timer never arms. Manual locks,
   *  `neverCacheKeys`, OS-lockscreen and tab-away (App-side) still
   *  drop handles. */
  autoLockEnabled: boolean;
  neverCacheKeys: boolean;
}

/** One live handle plus the store it came from. The kind is not
 *  cosmetic: PGP handles live in wasm's KEY_STORE and SSH identities in
 *  SSH_KEY_STORE, and the two are addressed by SEPARATE drop calls.
 *  Dropping an SSH handle through `dropKey` would hand an SSH_KEY_STORE
 *  index to the PGP store -- either a no-op that leaks the identity for
 *  the rest of the session, or a drop of whatever PGP key happens to sit
 *  at that index. So the kind is recorded at unlock time, next to the
 *  handle it describes, rather than re-derived later from a blob the
 *  caller may no longer have. */
interface KeyHandleEntry {
  handle: number;
  kind: StoredKeyKind;
}

/** Release one handle back to the store it came from. */
function dropHandle(entry: KeyHandleEntry): Promise<void> {
  return entry.kind === "ssh"
    ? closeSshIdentity(entry.handle)
    : wasmApi.dropKey(entry.handle);
}

/**
 * Manages unlocked key sessions using WASM key handles.
 *
 * Unlock happens entirely in WASM: the encrypted blob bytes are
 * passed directly to WASM which does KDF + AES-GCM decrypt + store.
 * The decrypted private key never enters the JS heap.
 *
 * Both engines unlock through here. Which one a blob belongs to is read
 * with {@link storedKeyKind} (absent `kind` means PGP -- every key
 * stored before the age engine existed), never off `blob.kind` directly.
 */
export function useKeySession(opts: KeySessionOptions) {
  const handleRef = useRef(new Map<string, KeyHandleEntry>());
  const [unlockedKeyIds, setUnlockedKeyIds] = useState<Set<string>>(new Set());
  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const doLockAll = useCallback(() => {
    for (const entry of handleRef.current.values()) {
      void dropHandle(entry);
    }
    handleRef.current.clear();
    setUnlockedKeyIds(new Set());
  }, []);

  const resetLockTimer = useCallback(() => {
    if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    if (!opts.autoLockEnabled) return;
    lockTimerRef.current = setTimeout(
      doLockAll,
      opts.autoLockMinutes * 60 * 1000,
    );
  }, [opts.autoLockEnabled, opts.autoLockMinutes, doLockAll]);

  const lockAllIfNoCache = useCallback(() => {
    if (opts.neverCacheKeys) doLockAll();
  }, [opts.neverCacheKeys, doLockAll]);

  useEffect(() => {
    return () => {
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    };
  }, []);

  // If `autoLockMinutes` or `autoLockEnabled` changes while keys are
  // unlocked, the existing setTimeout is still scheduled at the OLD
  // duration (or running at all). Re-arm under the new settings so
  // the change takes effect immediately.
  useEffect(() => {
    if (handleRef.current.size > 0) {
      resetLockTimer();
    }
  }, [opts.autoLockMinutes, opts.autoLockEnabled, resetLockTimer]);

  const markHandleUnlocked = useCallback(
    async (keyId: string, handle: number, kind: StoredKeyKind = "pgp") => {
      handleRef.current.set(keyId, { handle, kind });
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

      // An SSH identity is sealed under its own AAD prefix and belongs in
      // SSH_KEY_STORE, so it has its own unlock export. Unlocking it via
      // `unlockWithPassword` would fail the AAD check even with the right
      // password -- which the UI would report as "Wrong password".
      if (storedKeyKind(blob) === "ssh") {
        unlocking.current = true;
        try {
          const handle = await openSshIdentity(blob, password);
          await markHandleUnlocked(blob.keyId, handle, "ssh");
          return true;
        } catch {
          return false;
        } finally {
          unlocking.current = false;
        }
      }

      const passwordBytes = new TextEncoder().encode(password);
      unlocking.current = true;
      try {
        const handle = await wasmApi.unlockWithPassword(
          fromBase64(encrypted.ciphertext),
          fromBase64(encrypted.iv),
          fromBase64(encrypted.salt),
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

  const passkeyAbortRef = useRef<AbortController | null>(null);

  const unlockWithPasskey = useCallback(
    async (blob: ProtectedKeyBlob): Promise<boolean | "cancelled"> => {
      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "passkey") return false;

      // `openSshIdentity` runs the WebAuthn ceremony itself and takes no
      // AbortSignal, so an SSH unlock cannot be pre-empted the way the
      // PGP one is below, and a ceremony the USER dismissed is only
      // distinguishable by the error the browser throws. That covers the
      // common "changed my mind" case; a ceremony superseded by a second
      // unlock still reports as a plain failure.
      if (storedKeyKind(blob) === "ssh") {
        try {
          const handle = await openSshIdentity(blob);
          await markHandleUnlocked(blob.keyId, handle, "ssh");
          return true;
        } catch (e) {
          const name = e instanceof Error ? e.name : "";
          return name === "NotAllowedError" || name === "AbortError"
            ? "cancelled"
            : false;
        }
      }

      passkeyAbortRef.current?.abort();
      const ac = new AbortController();
      passkeyAbortRef.current = ac;

      let prfOutput: Uint8Array | undefined;
      try {
        ({ prfOutput } = await authenticateAndGetPrf(
          encrypted.credentialId,
          fromBase64(encrypted.prfSalt),
          ac.signal,
        ));

        const handle = await wasmApi.unlockWithPrf(
          fromBase64(encrypted.ciphertext),
          fromBase64(encrypted.iv),
          prfOutput,
          fromBase64(encrypted.storedSecret),
          blob.keyId,
        );

        await markHandleUnlocked(blob.keyId, handle);
        return true;
      } catch (e) {
        if (ac.signal.aborted) return "cancelled";
        const name = e instanceof Error ? e.name : "";
        if (name === "NotAllowedError" || name === "AbortError") {
          return "cancelled";
        }
        return false;
      } finally {
        prfOutput?.fill(0);
      }
    },
    [markHandleUnlocked],
  );

  const lock = useCallback((keyId: string) => {
    const entry = handleRef.current.get(keyId);
    if (entry !== undefined) {
      void dropHandle(entry);
    }
    handleRef.current.delete(keyId);
    setUnlockedKeyIds((prev) => {
      const next = new Set(prev);
      next.delete(keyId);
      return next;
    });
  }, []);

  // Deliberately still `(keyId) => number | null`: a caller that needs to
  // know WHICH engine's handle it is holds the blob it came from and can
  // read `storedKeyKind` off that. Widening the return type here would
  // push a second thing to unpack onto every existing call site to say
  // something they already know.
  const getKeyHandle = useCallback(
    (keyId: string): number | null => {
      const entry = handleRef.current.get(keyId);
      if (entry === undefined) return null;
      // "Idle" should mean idle since last cryptographic use, not idle
      // since unlock. Every encrypt/decrypt/sign call goes through here,
      // so reset the lock timer on every key access.
      resetLockTimer();
      return entry.handle;
    },
    [resetLockTimer],
  );

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
    resetLockTimer,
    getKeyHandle,
    isUnlocked,
    unlockedKeyIds,
    cacheKeyHandle: markHandleUnlocked,
  };
}
