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
export interface KeyHandleEntry {
  handle: number;
  kind: StoredKeyKind;
}

/** Release one handle back to the store it came from. Exported for the
 *  unit test that pins the kind-aware dispatch: handing an SSH index to
 *  the PGP store is the failure this switch exists to prevent. */
export function dropHandle(entry: KeyHandleEntry): Promise<void> {
  return entry.kind === "ssh"
    ? closeSshIdentity(entry.handle)
    : wasmApi.dropKey(entry.handle);
}

/** Everything {@link createKeySessionStore} needs from the outside
 *  world. Injected rather than imported so the core is unit-testable
 *  without wasm, IndexedDB or a React renderer. */
export interface KeySessionStoreDeps {
  dropHandle: (entry: KeyHandleEntry) => Promise<void>;
  updateLastUsed: (keyId: string) => Promise<void>;
  /** The set of unlocked ids changed. Mirrors it into React state. */
  onUnlockedChanged: (unlockedKeyIds: Set<string>) => void;
  /** A key was unlocked or used: re-arm the inactivity timer. */
  onActivity: () => void;
}

export interface KeySessionStore {
  /**
   * The ONLY way a handle gets into the map. `open` is the call that
   * actually produces the handle (a wasm unlock, a WebAuthn ceremony,
   * or just a handle someone else already opened); the store brackets
   * it with the lock-generation check, so no unlock path can store a
   * handle without being generation-checked. Resolves `true` if the
   * handle was stored, `false` if a lock intervened and it was dropped
   * instead. Rejects if `open` rejects -- callers classify that.
   */
  unlock: (
    keyId: string,
    kind: StoredKeyKind,
    open: () => Promise<number>,
  ) => Promise<boolean>;
  lock: (keyId: string) => void;
  lockAll: () => void;
  getHandle: (keyId: string) => number | null;
  /** Live handle count. Used to decide whether the timer needs re-arming. */
  size: () => number;
}

/**
 * React-free core of {@link useKeySession}: owns the handle map, the
 * lock generation, and the two invariants that keep a decrypted key
 * from outliving a lock.
 *
 * INVARIANT 1 -- no unlock survives a lock. Every lock bumps
 * `generation`. An unlock captures the generation before it awaits and
 * re-checks it before inserting; if it moved, the handle is dropped
 * instead of stored. This matters because an unlock can await for
 * *seconds* on a user-interactive WebAuthn ceremony, during which the
 * OS lockscreen (or the idle timer, or tab-away) can lock the panel
 * with an EMPTY map -- so `lockAll` has nothing to drop, and the
 * ceremony then completes and re-populates the store behind the lock
 * screen. With `autoLockEnabled` off nothing would ever drop it again.
 * The check lives inside `unlock` rather than at each call site
 * precisely so a future unlock path cannot forget it: getting a handle
 * into the map means going through this funnel.
 *
 * A per-key lock bumps the global generation too. That is deliberately
 * conservative -- it also cancels an in-flight unlock of a DIFFERENT
 * key -- but the failure mode is a re-prompt, versus a live key behind
 * a lock screen.
 *
 * INVARIANT 2 -- the map is the only reference to a live handle.
 * Overwriting an entry drops the one it replaces first. Without that
 * the old handle is no longer reachable from the map, so `lock`,
 * `lockAll` and every lock event are structurally incapable of ever
 * dropping it: the key stays decrypted until the panel closes.
 * Reachable through `cacheKeyHandle` -- re-importing or updating a key
 * that is currently unlocked hands us a fresh handle for a keyId
 * already in the map.
 */
export function createKeySessionStore(
  deps: KeySessionStoreDeps,
): KeySessionStore {
  const handles = new Map<string, KeyHandleEntry>();
  let generation = 0;

  const publish = (): void => deps.onUnlockedChanged(new Set(handles.keys()));

  /** Invalidate every unlock currently in flight. */
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

    // INVARIANT 1. The app is showing a lock screen (or has locked this
    // key); the handle we just opened must not become live.
    if (startedAt !== generation) {
      void deps.dropHandle({ handle, kind });
      return false;
    }

    // INVARIANT 2. `handle !== previous.handle` guard: a store that
    // handed back the same index (a re-cache of what we already hold)
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

  const getHandle = (keyId: string): number | null => {
    const entry = handles.get(keyId);
    if (entry === undefined) return null;
    // "Idle" should mean idle since last cryptographic use, not idle
    // since unlock. Every encrypt/decrypt/sign call goes through here,
    // so reset the lock timer on every key access.
    deps.onActivity();
    return entry.handle;
  };

  return { unlock, lock, lockAll, getHandle, size: () => handles.size };
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
 *
 * The handle bookkeeping itself lives in {@link createKeySessionStore};
 * this hook is the React shell around it (state mirror + auto-lock timer).
 */
export function useKeySession(opts: KeySessionOptions) {
  const [unlockedKeyIds, setUnlockedKeyIds] = useState<Set<string>>(new Set());
  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The store outlives every render, so it cannot close over
  // `resetLockTimer` directly -- that callback's identity changes
  // whenever the auto-lock preferences do. It calls through a cell the
  // effect below keeps pointed at the current one.
  //
  // `useState` with a lazy initialiser, not `useRef`: both must be
  // created exactly once for the life of the panel. A second store
  // would hold a second map and a second generation counter, and locks
  // routed to one would not touch the other.
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

  // Nothing calls `onActivity` before the first effects flush -- it
  // fires from unlocks and key access, both user-driven -- so an effect
  // is soon enough to publish the current timer callback.
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

  // If `autoLockMinutes` or `autoLockEnabled` changes while keys are
  // unlocked, the existing setTimeout is still scheduled at the OLD
  // duration (or running at all). Re-arm under the new settings so
  // the change takes effect immediately.
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

      // An SSH identity is sealed under its own AAD prefix and belongs in
      // SSH_KEY_STORE, so it has its own unlock export. Unlocking it via
      // `unlockWithPassword` would fail the AAD check even with the right
      // password -- which the UI would report as "Wrong password".
      if (storedKeyKind(blob) === "ssh") {
        unlocking.current = true;
        try {
          // `false` here means a lock landed mid-unlock and the handle
          // was dropped; the key is genuinely not unlocked, so reporting
          // failure is honest (the lock screen is up by then anyway).
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

  const unlockWithPasskey = useCallback(
    async (blob: ProtectedKeyBlob): Promise<boolean | "cancelled"> => {
      const encrypted = encryptedBlobFromProtected(blob);
      if (encrypted.method !== "passkey") return false;

      // `openSshIdentity` runs the WebAuthn ceremony itself and takes no
      // AbortSignal, so an SSH unlock cannot be pre-empted the way the
      // PGP one is below, and a ceremony the USER dismissed is only
      // distinguishable by the error the browser throws. That covers the
      // common "changed my mind" case; a ceremony superseded by a second
      // unlock still reports as a plain failure. A ceremony superseded by
      // a LOCK is handled inside `store.unlock`, which drops the handle
      // the ceremony produced rather than storing it.
      if (storedKeyKind(blob) === "ssh") {
        try {
          return await store.unlock(blob.keyId, "ssh", () =>
            openSshIdentity(blob),
          );
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
        return await store.unlock(blob.keyId, "pgp", async () => {
          ({ prfOutput } = await authenticateAndGetPrf(
            encrypted.credentialId,
            fromBase64(encrypted.prfSalt),
            ac.signal,
          ));

          return await wasmApi.unlockWithPrf(
            fromBase64(encrypted.ciphertext),
            fromBase64(encrypted.iv),
            prfOutput,
            fromBase64(encrypted.storedSecret),
            blob.keyId,
          );
        });
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
    [store],
  );

  const lock = useCallback((keyId: string) => store.lock(keyId), [store]);

  // Deliberately still `(keyId) => number | null`: a caller that needs to
  // know WHICH engine's handle it is holds the blob it came from and can
  // read `storedKeyKind` off that. Widening the return type here would
  // push a second thing to unpack onto every existing call site to say
  // something they already know.
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

  // A handle someone else already opened (a fresh import, or a key
  // re-protected while unlocked). It goes through the same funnel as a
  // real unlock: the generation window is degenerate here -- we hold the
  // handle already -- but the overwrite-drops-the-old-handle rule is
  // exactly the one this path used to violate.
  const cacheKeyHandle = useCallback(
    async (keyId: string, handle: number, kind: StoredKeyKind = "pgp") => {
      await store.unlock(keyId, kind, () => Promise.resolve(handle));
    },
    [store],
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
    cacheKeyHandle,
  };
}
