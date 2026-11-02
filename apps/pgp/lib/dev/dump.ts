/** DEV-ONLY: reachable only from Settings' Developer section, which is
 *  gated on `import.meta.env.DEV` and tree-shaken from production. */

export interface StorageDump {
  local: Record<string, unknown>;
  sync: Record<string, unknown>;
  session: Record<string, unknown>;
}

/** Sealed stores come back as their at-rest ciphertext, by design. */
export async function dumpAllStorage(): Promise<StorageDump> {
  const [local, sync, session] = await Promise.all([
    chrome.storage.local.get(null),
    chrome.storage.sync.get(null),
    chrome.storage.session.get(null),
  ]);
  return { local, sync, session };
}

/** Clear and repopulate each area present; reload the panel afterwards. */
export async function restoreAllStorage(
  dump: Partial<StorageDump>,
): Promise<void> {
  if (dump.local) {
    await chrome.storage.local.clear();
    await chrome.storage.local.set(dump.local);
  }
  if (dump.sync) {
    await chrome.storage.sync.clear();
    await chrome.storage.sync.set(dump.sync);
  }
  if (dump.session) {
    await chrome.storage.session.clear();
    await chrome.storage.session.set(dump.session);
  }
}

export async function clearAllStorage(): Promise<void> {
  await Promise.all([
    chrome.storage.local.clear(),
    chrome.storage.sync.clear(),
    chrome.storage.session.clear(),
  ]);
}

export function isStorageDump(v: unknown): v is Partial<StorageDump> {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  const areas = ["local", "sync", "session"] as const;
  return (
    areas.some((a) => a in o) &&
    areas.every((a) => !(a in o) || (typeof o[a] === "object" && o[a] !== null))
  );
}
