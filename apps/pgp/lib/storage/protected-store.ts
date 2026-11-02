/**
 * Generic CRUD over a store of protected key blobs: a JSON array sealed as
 * one envelope (`encrypted-store.ts`), keyed by a stable id. Item
 * validation and mutation preconditions stay with the caller.
 *
 * Every mutation runs load-modify-save under the store's `withLock`: the
 * whole array is rewritten, so interleaved mutations would drop a write.
 */

import type { EncryptedStore } from "./encrypted-store";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { withLock } from "./engine";

export interface ProtectedStoreDescriptor<T> extends EncryptedStore<T> {
  /** Stable id (`keyId` / `extensionId`); also what `put` de-duplicates on. */
  idOf: (item: T) => string;
}

/**
 * Precondition checked inside the lock, before the read. Throw to fail,
 * return `false` to skip. Required for stores mutable while locked: a
 * locked load returns `[]`, and saving that would wipe every key.
 */
export type MutationGuard = () => Promise<boolean>;

export interface MutateOptions {
  guard?: MutationGuard;
}

export interface UpdateOptions extends MutateOptions {
  /** Called (inside the lock) when no item has the id; default no-op. Pass
   *  a thrower when the caller reports success to the user. */
  onMissing?: (id: string) => never;
}

export interface ProtectedStore<T> {
  /** Every stored item. `[]` while the vault is locked. */
  getAll(): Promise<T[]>;
  /** One-time upgrade to canonical padding and the domain-bound envelope. */
  normalize(): Promise<void>;
  /** Insert `item`, replacing any existing item with the same id. */
  put(item: T, opts?: MutateOptions): Promise<void>;
  /** Delete by id. An emptied store is saved as a sealed EMPTY array, never
   *  removed: a missing store is what a deletion attack looks like
   *  (`integrity.ts`). */
  remove(id: string, opts?: MutateOptions): Promise<void>;
  /** Mutate one item under the lock on a freshly loaded copy. */
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

  /** Runs the precondition inside the lock so it can't be overtaken. */
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
      mutate(opts, (items) => save(items.filter((i) => idOf(i) !== id))),

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
