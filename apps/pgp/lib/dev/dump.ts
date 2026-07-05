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

/** Read every key from all three chrome.storage areas. The keyring and
 *  contacts entries come back as their at-rest ciphertext (base64), which
 *  is the point -- you're inspecting what actually landed on disk. */
export async function dumpAllStorage(): Promise<StorageDump> {
  const [local, sync, session] = await Promise.all([
    chrome.storage.local.get(null),
    chrome.storage.sync.get(null),
    chrome.storage.session.get(null),
  ]);
  return { local, sync, session };
}
