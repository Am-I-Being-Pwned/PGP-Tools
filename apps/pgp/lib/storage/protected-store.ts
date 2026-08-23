/**
 * Generic CRUD over a store of protected key blobs.
 *
 * Every key type we hold (PGP certs, CRX signing keys, whatever comes
 * next) persists the same way: a JSON array of self-protected blobs,
 * sealed as one encrypted envelope under the master session and
 * domain-separated by its own storage key (`encrypted-store.ts`), keyed
 * within the array by a stable id. This wraps that with the read-modify-
 * write shape all of them need, so a new key type describes its store
 * instead of reimplementing it.
 *
 * The parts that are NOT generic stay with the caller: a store may reject
 * an item before it is ever offered here (CRX checks that a blob's public
 * key hashes to its claimed extension id), and may impose its own
 * precondition on mutating (see {@link MutationGuard}).
 *
 * Serialization is not optional. Every mutation runs the whole
 * load-modify-save under the store's `withLock`, because
 * `loadEncryptedArray` + `saveEncryptedArray` rewrites the entire array:
 * two interleaved mutations would silently drop one side's write.
 */

import type { EncryptedStore } from "./encrypted-store";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { removeItem, withLock } from "./engine";

export interface ProtectedStoreDescriptor<T> extends EncryptedStore<T> {
  /** Stable identity of an item — the field callers address it by
   *  (`keyId` for PGP certs, `extensionId` for CRX keys). Also what
   *  `put` de-duplicates on. */
  idOf: (item: T) => string;
}

/**
 * Precondition checked inside the lock, immediately before the read.
 * Throw to fail the mutation loudly; return `false` to skip it silently.
 *
 * This exists because `loadEncryptedArray` returns `[]` while the vault
 * is locked, which is indistinguishable from an empty store — so a
 * read-modify-write that runs without a session would persist an empty
 * array over every stored key. Stores whose mutations can be reached
 * while locked must pass one.
 */
export type MutationGuard = () => Promise<boolean>;

export interface MutateOptions {
  guard?: MutationGuard;
}

export interface UpdateOptions extends MutateOptions {
  /** Called (inside the lock) when no item has the given id. Default is
   *  to no-op. A store whose caller reports success to the user should
   *  pass one that throws — see `updateRevocationCertificate`. */
  onMissing?: (id: string) => never;
}

export interface ProtectedStore<T> {
  /** Every stored item. `[]` while the vault is locked. */
  getAll(): Promise<T[]>;
  /** One-time upgrade of the stored blob to canonical padding and to the
   *  domain-bound sealing envelope. */
  normalize(): Promise<void>;
  /** Insert `item`, replacing any existing item with the same id. */
  put(item: T, opts?: MutateOptions): Promise<void>;
  /** Delete by id. Removes the storage entry entirely once empty, rather
   *  than leaving a sealed empty array behind. */
  remove(id: string, opts?: MutateOptions): Promise<void>;
  /** Mutate one item in place and save. `apply` runs under the lock on
   *  the freshly-loaded item, so it never writes back stale metadata. */
  update(
    id: string,
    apply: (item: T) => void,
    opts?: UpdateOptions,
  ): Promise<void>;
}

export function createProtectedStore<T>(
  descriptor: ProtectedStoreDescriptor<T>,
): ProtectedStore<T> {
  const { storageKey, idOf } = descriptor;
  const load = () => loadEncryptedArray(descriptor);
  const save = (items: T[]) => saveEncryptedArray(descriptor, items);

  /** Serialize a read-modify-write, running the store's precondition
   *  inside the lock so it can't be overtaken between check and write. */
  const mutate = (
    opts: MutateOptions | undefined,
    fn: (items: T[]) => Promise<void>,
  ): Promise<void> =>
    withLock(storageKey, async () => {
      if (opts?.guard && !(await opts.guard())) return;
      await fn(await load());
    });

  return {
    getAll: load,

    normalize: () => normalizePadding(descriptor),

    put: (item, opts) =>
      mutate(opts, (items) =>
        save([...items.filter((i) => idOf(i) !== idOf(item)), item]),
      ),

    remove: (id, opts) =>
      mutate(opts, async (items) => {
        const updated = items.filter((i) => idOf(i) !== id);
        if (updated.length === 0) {
          await removeItem(storageKey);
        } else {
          await save(updated);
        }
      }),

    update: (id, apply, opts) =>
      mutate(opts, async (items) => {
        const item = items.find((i) => idOf(i) === id);
        if (!item) {
          opts?.onMissing?.(id);
          return;
        }
        apply(item);
        await save(items);
      }),
  };
}
