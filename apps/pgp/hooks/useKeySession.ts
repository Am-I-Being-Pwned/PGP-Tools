import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  MasterPasskey,
  SealedParts,
} from "../lib/protection/vault-unlock";
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
import {
  needsMasterReseal,
  openWithMasterPrf,
  resealUnderMaster,
} from "../lib/protection/vault-unlock";
import { authenticateAndGetPrf } from "../lib/protection/webauthn-prf";
import { storedKeyKind } from "../lib/storage/key-kind";
import {
  encryptedBlobFromProtected,
  updateLastUsed,
} from "../lib/storage/keyring";

interface KeySessionOptions {
  autoLockMinutes: AutoLockTimeout;
  /** When false, only the inactivity timer is off; other lock paths still drop handles. */
  autoLockEnabled: boolean;
  neverCacheKeys: boolean;
  /** Non-null when "unlock keys with the vault" is on with a passkey master:
   *  a per-key passkey unlock also re-seals the key under the master in the
   *  same ceremony. */
  masterReseal: {
    master: MasterPasskey;
    replaceProtection: (keyId: string, parts: SealedParts) => Promise<void>;
  } | null;
}

/** One live handle plus the store it came from. PGP and SSH handles live in
 *  separate wasm stores with separate drop calls; dropping an SSH index via
 *  `dropKey` would leak it or drop an unrelated PGP key. Recorded at unlock
 *  time, never re-derived. */
export interface KeyHandleEntry {
  handle: number;
  kind: StoredKeyKind;
}

/** Release one handle back to the store it came from (kind-aware). */
export function dropHandle(entry: KeyHandleEntry): Promise<void> {
  return entry.kind === "ssh"
    ? closeSshIdentity(entry.handle)
    : wasmApi.dropKey(entry.handle);
}

/** Injected so the core is unit-testable without wasm, IndexedDB or React. */
export interface KeySessionStoreDeps {
  dropHandle: (entry: KeyHandleEntry) => Promise<void>;
  updateLastUsed: (keyId: string) => Promise<void>;
  onUnlockedChanged: (unlockedKeyIds: Set<string>) => void;
  /** A key was unlocked or used: re-arm the inactivity timer. */
  onActivity: () => void;
}

export interface UnlockEntry {
  keyId: string;
  kind: StoredKeyKind;
  open: () => Promise<number>;
}

export interface KeySessionStore {
  /**
   * The ONLY way a handle gets into the map, so every path is
   * generation-checked. `true` if stored, `false` if a lock intervened and
   * the handle was dropped; rejects if `open` rejects.
   */
  unlock: (
    keyId: string,
    kind: StoredKeyKind,
    open: () => Promise<number>,
  ) => Promise<boolean>;
  /**
   * Several unlocks off ONE credential. The loop stops at the first entry
   * after a lock, else a mid-batch lock would let later entries go live
   * behind the lock screen. `entries` may be a loader; the generation is
   * captured before it is awaited so a lock during the read cancels too.
   * Per-entry failures are skipped. Resolves to the number stored.
   */
  unlockMany: (
    entries: UnlockEntry[] | (() => Promise<UnlockEntry[]>),
  ) => Promise<number>;
  lock: (keyId: string) => void;
  lockAll: () => void;
  getHandle: (keyId: string) => number | null;
  size: () => number;
}

/**
 * Open, then persist the re-seal under the master BEFORE returning the
 * handle, so the key only shows unlocked once its new sealing is on disk.
 * Best-effort: a failed re-seal is swallowed (the key keeps its own prompt).
 */
export async function openThenReseal(
  open: () => Promise<number>,
  reseal: ((handle: number) => Promise<void>) | null,
): Promise<number> {
  const handle = await open();
  if (reseal) {
    try {
      await reseal(handle);
    } catch {
      /* keep the per-key prompt; nothing is lost */
    }
  }
  return handle;
}

/**
 * React-free core of {@link useKeySession}.
 *
 * INVARIANT 1 -- no unlock survives a lock. Every lock bumps `generation`;
 * an unlock re-checks it after awaiting and drops the handle if it moved
 * (a WebAuthn ceremony can take seconds, during which the panel may lock
 * with an empty map). A per-key lock bumps it too: deliberately
 * conservative, the cost is a re-prompt.
 *
 * INVARIANT 2 -- the map is the only reference to a live handle.
 * Overwriting an entry drops the old handle first, else nothing could ever
 * drop it.
 */
export function createKeySessionStore(
  deps: KeySessionStoreDeps,
): KeySessionStore {
  const handles = new Map<string, KeyHandleEntry>();
  let generation = 0;

  const publish = (): void => deps.onUnlockedChanged(new Set(handles.keys()));

  const bumpGeneration = (): void => {
    generation += 1;
  };

  const lockAll = (): void => {
    bumpGeneration();
    for (const entry of handles.values()) {
      void deps.dropHandle(entry);
    }
    handles.clear();
    publish();
  };

  const lock = (keyId: string): void => {
    bumpGeneration();
    const entry = handles.get(keyId);
    if (entry !== undefined) {
      void deps.dropHandle(entry);
    }
    handles.delete(keyId);
    publish();
  };

  const unlock = async (
    keyId: string,
    kind: StoredKeyKind,
    open: () => Promise<number>,
  ): Promise<boolean> => {
    const startedAt = generation;
    const handle = await open();

    // INVARIANT 1.
    if (startedAt !== generation) {
      void deps.dropHandle({ handle, kind });
      return false;
    }

    // INVARIANT 2. Same-index guard: a re-cache of what we already hold
    // would otherwise be dropped and then recorded as live.
    const previous = handles.get(keyId);
    if (previous !== undefined && previous.handle !== handle) {
      void deps.dropHandle(previous);
    }

    handles.set(keyId, { handle, kind });
    publish();
    await deps.updateLastUsed(keyId);
    deps.onActivity();
    return true;
  };

  const unlockMany = async (
    entries: UnlockEntry[] | (() => Promise<UnlockEntry[]>),
  ): Promise<number> => {
    const startedAt = generation;
    const list = typeof entries === "function" ? await entries() : entries;
    let stored = 0;
    for (const entry of list) {
      if (generation !== startedAt) break;
      try {
        if (await unlock(entry.keyId, entry.kind, entry.open)) stored += 1;
      } catch {
        // One blob that will not open must not stop the others.
      }
    }
    return stored;
  };

  const getHandle = (keyId: string): number | null => {
    const entry = handles.get(keyId);
    if (entry === undefined) return null;
    // Idle means since last cryptographic use, not since unlock.
    deps.onActivity();
    return entry.handle;
  };

  return {
    unlock,
    unlockMany,
    lock,
    lockAll,
    getHandle,
    size: () => handles.size,
  };
}

/**
 * Unlocked key sessions as WASM handles. Unlock (KDF + decrypt + store)
 * happens entirely in WASM; the decrypted private key never enters the JS
 * heap. Engine is read via {@link storedKeyKind}, never `blob.kind`.
 */
export function useKeySession(opts: KeySessionOptions) {
  const [unlockedKeyIds, setUnlockedKeyIds] = useState<Set<string>>(new Set());
  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Created exactly once per panel: a second store would have its own map
  // and generation, and locks routed to one would miss the other.
  // `onActivity` goes through a cell because resetLockTimer's identity changes.
  const [{ store, setOnActivity }] = useState(() => {
    let onActivity: () => void = () => undefined;
    return {
      setOnActivity: (fn: () => void): void => {
        onActivity = fn;
      },
      store: createKeySessionStore({
        dropHandle,
        updateLastUsed,
        onUnlockedChanged: setUnlockedKeyIds,
        onActivity: () => onActivity(),
      }),
    };
  });

  const doLockAll = useCallback(() => store.lockAll(), [store]);

  const resetLockTimer = useCallback(() => {
    if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    if (!opts.autoLockEnabled) return;
    lockTimerRef.current = setTimeout(
      doLockAll,
      opts.autoLockMinutes * 60 * 1000,
    );
  }, [opts.autoLockEnabled, opts.autoLockMinutes, doLockAll]);

  useEffect(() => {
    setOnActivity(resetLockTimer);
  }, [setOnActivity, resetLockTimer]);

  const lockAllIfNoCache = useCallback(() => {
    if (opts.neverCacheKeys) doLockAll();
  }, [opts.neverCacheKeys, doLockAll]);

  useEffect(() => {
    return () => {
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    };
  }, []);

  // Re-arm so changed auto-lock settings apply to already-unlocked keys.
  useEffect(() => {
    if (store.size() > 0) {
      resetLockTimer();
    }
  }, [opts.autoLockMinutes, opts.autoLockEnabled, resetLockTimer, store]);

  const unlocking = useRef(false);

  const unlockWithPassword = useCallback(
    async (blob: ProtectedKeyBlob, password: string): Promise<boolean> => {
      if (unlocking.current) return false;

      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "password") return false;

      // SSH identities use their own AAD prefix and store; the PGP unlock
      // would fail the AAD check and report "Wrong password".
      if (storedKeyKind(blob) === "ssh") {
        unlocking.current = true;
        try {
          return await store.unlock(blob.keyId, "ssh", () =>
            openSshIdentity(blob, password),
          );
        } catch {
          return false;
        } finally {
          unlocking.current = false;
        }
      }

      const passwordBytes = new TextEncoder().encode(password);
      unlocking.current = true;
      try {
        return await store.unlock(blob.keyId, "pgp", () =>
          wasmApi.unlockWithPassword(
            fromBase64(encrypted.ciphertext),
            fromBase64(encrypted.iv),
            fromBase64(encrypted.salt),
            blob.keyId,
            passwordBytes,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
          ),
        );
      } catch {
        return false;
      } finally {
        passwordBytes.fill(0);
        unlocking.current = false;
      }
    },
    [store],
  );

  const passkeyAbortRef = useRef<AbortController | null>(null);

  const masterReseal = opts.masterReseal;

  const unlockWithPasskey = useCallback(
    async (blob: ProtectedKeyBlob): Promise<boolean | "cancelled"> => {
      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "passkey") return false;
      const kind = storedKeyKind(blob);

      // The only master-migration step: this ceremony also evaluates the
      // master salt, and the key is re-sealed under it.
      const reseal =
        masterReseal && needsMasterReseal(blob, masterReseal.master)
          ? masterReseal
          : null;

      // Ceremony runs here for both engines so both get abort + second salt.
      passkeyAbortRef.current?.abort();
      const ac = new AbortController();
      passkeyAbortRef.current = ac;

      let prfOutput: Uint8Array | undefined;
      let secondOutput: Uint8Array | undefined;
      try {
        const stored = await store.unlock(blob.keyId, kind, async () => {
          ({ prfOutput, secondOutput } = await authenticateAndGetPrf(
            encrypted.credentialId,
            fromBase64(encrypted.prfSalt),
            ac.signal,
            reseal ? fromBase64(reseal.master.prfSalt) : undefined,
          ));
          const ciphertext = fromBase64(encrypted.ciphertext);
          const iv = fromBase64(encrypted.iv);
          const storedSecret = fromBase64(encrypted.storedSecret);
          const first = prfOutput;
          const second = secondOutput;
          // Re-seal INSIDE the open (see `openThenReseal`).
          return openThenReseal(
            () =>
              kind === "ssh"
                ? wasmApi.unlockSshIdentityWithPrf(
                    ciphertext,
                    iv,
                    first,
                    storedSecret,
                    blob.keyId,
                  )
                : wasmApi.unlockWithPrf(
                    ciphertext,
                    iv,
                    first,
                    storedSecret,
                    blob.keyId,
                  ),
            reseal && second
              ? async (handle) =>
                  reseal.replaceProtection(
                    blob.keyId,
                    await resealUnderMaster(
                      blob,
                      handle,
                      reseal.master,
                      second,
                    ),
                  )
              : null,
          );
        });
        return stored;
      } catch (e) {
        if (ac.signal.aborted) return "cancelled";
        const name = e instanceof Error ? e.name : "";
        if (name === "NotAllowedError" || name === "AbortError") {
          return "cancelled";
        }
        return false;
      } finally {
        prfOutput?.fill(0);
        secondOutput?.fill(0);
      }
    },
    [store, masterReseal],
  );

  /**
   * Open every master-sealed blob off the master PRF output. `loadBlobs`
   * is awaited inside the batch so the generation check covers the read.
   * `prfOutput` is caller-owned; the caller zeroes it.
   */
  const unlockAllWithMasterPrf = useCallback(
    (
      loadBlobs: () => Promise<ProtectedKeyBlob[]>,
      prfOutput: Uint8Array,
    ): Promise<number> =>
      store.unlockMany(async () =>
        (await loadBlobs()).map((blob) => ({
          keyId: blob.keyId,
          kind: storedKeyKind(blob),
          open: () => openWithMasterPrf(blob, prfOutput),
        })),
      ),
    [store],
  );

  const lock = useCallback((keyId: string) => store.lock(keyId), [store]);

  const getKeyHandle = useCallback(
    (keyId: string): number | null => store.getHandle(keyId),
    [store],
  );

  const isUnlocked = useCallback(
    (keyId: string): boolean => {
      return unlockedKeyIds.has(keyId);
    },
    [unlockedKeyIds],
  );

  // An already-open handle still goes through the funnel for INVARIANT 2.
  const cacheKeyHandle = useCallback(
    async (keyId: string, handle: number, kind: StoredKeyKind = "pgp") => {
      await store.unlock(keyId, kind, () => Promise.resolve(handle));
    },
    [store],
  );

  return useMemo(
    () => ({
      unlockWithPassword,
      unlockWithPasskey,
      unlockAllWithMasterPrf,
      lock,
      lockAll: doLockAll,
      lockAllIfNoCache,
      resetLockTimer,
      getKeyHandle,
      isUnlocked,
      unlockedKeyIds,
      cacheKeyHandle,
    }),
    [
      unlockWithPassword,
      unlockWithPasskey,
      unlockAllWithMasterPrf,
      lock,
      doLockAll,
      lockAllIfNoCache,
      resetLockTimer,
      getKeyHandle,
      isUnlocked,
      unlockedKeyIds,
      cacheKeyHandle,
    ],
  );
}
