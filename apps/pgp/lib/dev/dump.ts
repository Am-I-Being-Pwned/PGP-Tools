/**
 * DEV-ONLY debugging helpers. Everything here is reachable only from the
 * Developer section of Settings, which is itself gated behind
 * `import.meta.env.DEV` and tree-shaken out of production builds.
 */

export interface StorageDump {
  local: Record<string, unknown>;
  sync: Record<string, unknown>;
  session: Record<string, unknown>;
}

/** Read every key from all three browser.storage areas. The keyring and
 *  contacts entries come back as their at-rest ciphertext (base64), which
 *  is the point -- you're inspecting what actually landed on disk. */
export async function dumpAllStorage(): Promise<StorageDump> {
  const [local, sync, session] = await Promise.all([
    browser.storage.local.get(null),
    browser.storage.sync.get(null),
    browser.storage.session.get(null),
  ]);
  return { local, sync, session };
}

/**
 * Overwrite browser.storage with a previously-dumped snapshot: each area
 * is cleared then repopulated. Used to rewind to a known state (e.g. a
 * pre-migration dump) before exercising a migration. The running panel
 * still holds the old state in memory, so reload it afterwards.
 */
export async function restoreAllStorage(
  dump: Partial<StorageDump>,
): Promise<void> {
  if (dump.local) {
    await browser.storage.local.clear();
    await browser.storage.local.set(dump.local);
  }
  if (dump.sync) {
    await browser.storage.sync.clear();
    await browser.storage.sync.set(dump.sync);
  }
  if (dump.session) {
    await browser.storage.session.clear();
    await browser.storage.session.set(dump.session);
  }
}

/** Wipe all three storage areas -- simulate a fresh install. */
export async function clearAllStorage(): Promise<void> {
  await Promise.all([
    browser.storage.local.clear(),
    browser.storage.sync.clear(),
    browser.storage.session.clear(),
  ]);
}

/** Validate a parsed object looks like a storage dump before restoring. */
export function isStorageDump(v: unknown): v is Partial<StorageDump> {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  const areas = ["local", "sync", "session"] as const;
  // At least one known area, and every present area is a plain object.
  return (
    areas.some((a) => a in o) &&
    areas.every((a) => !(a in o) || (typeof o[a] === "object" && o[a] !== null))
  );
}
