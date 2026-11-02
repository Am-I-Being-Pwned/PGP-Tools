/**
 * Live views of the sealed list stores. Same-panel only: other windows'
 * writes are picked up on explicit refresh (reading mid-way through a
 * chunked write could report it unreadable).
 */

type Listener = () => void;

const changeListeners = new Map<string, Set<Listener>>();

export function notifyStoreChanged(storageKey: string): void {
  for (const l of changeListeners.get(storageKey) ?? []) l();
}

function onStoreChanged(storageKey: string, listener: Listener): () => void {
  let set = changeListeners.get(storageKey);
  if (!set) changeListeners.set(storageKey, (set = new Set()));
  set.add(listener);
  return () => set.delete(listener);
}

export interface ListState<T> {
  items: T[];
  loading: boolean;
  /** NOT the same as empty: an unreadable keyring must never show as "no keys". */
  error: Error | null;
}

export interface LiveList<T> {
  get: () => ListState<T>;
  subscribe: (listener: Listener) => () => void;
  refresh: () => Promise<void>;
}

export function createLiveList<T>(
  storageKey: string,
  load: () => Promise<T[]>,
): LiveList<T> {
  let state: ListState<T> = { items: [], loading: true, error: null };
  let loaded = false;
  let stale = false;
  let generation = 0;
  const listeners = new Set<Listener>();

  const set = (next: ListState<T>) => {
    state = next;
    for (const l of listeners) l();
  };

  async function refresh(): Promise<void> {
    const gen = ++generation;
    let next: ListState<T>;
    try {
      next = { items: await load(), loading: false, error: null };
    } catch (e) {
      next = {
        items: [],
        loading: false,
        error: e instanceof Error ? e : new Error(String(e)),
      };
    }
    // A slower, older read must not overwrite a newer one.
    if (gen !== generation) return;
    loaded = true;
    stale = false;
    if (!state.loading && sameState(state, next)) return;
    set(next);
  }

  onStoreChanged(storageKey, () => {
    if (listeners.size > 0) void refresh();
    else stale = true;
  });

  return {
    get: () => state,
    subscribe: (listener) => {
      listeners.add(listener);
      if (!loaded || stale) void refresh();
      return () => listeners.delete(listener);
    },
    refresh,
  };
}

function sameState<T>(a: ListState<T>, b: ListState<T>): boolean {
  return (
    a.error?.message === b.error?.message &&
    a.items.length === b.items.length &&
    JSON.stringify(a.items) === JSON.stringify(b.items)
  );
}
