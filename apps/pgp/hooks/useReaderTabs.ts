import { useCallback, useEffect, useRef } from "react";

import type { ReaderMessage, ReaderSigner } from "../lib/reader-protocol";
import * as wasmApi from "../lib/pgp/wasm";
import {
  isReaderNonce,
  newReaderNonce,
  READER_PORT_PREFIX,
} from "../lib/reader-protocol";

interface Reader {
  /** The message, sealed under the in-WASM draft key -- the same key the
   *  workspace draft crosses a master lock under. Never plaintext here. */
  sealed: Uint8Array;
  signer: ReaderSigner;
  /** Every tab showing this message. Usually one, but a duplicated tab
   *  connects with the same nonce, and each copy must be locked too. */
  ports: Set<chrome.runtime.Port>;
}

const LOCKED: ReaderMessage = { type: "locked" };

/**
 * The panel's side of Reply's reader tabs (see lib/reader-protocol).
 *
 * The panel owns every message a reader shows. It is sealed the moment
 * Reply is pressed and opened again only to post it to connected tabs
 * while the vault is `unlocked`; locking tells every tab to drop it, and
 * unlocking sends it again. When the last tab for a message closes, the
 * sealed copy is zeroed and dropped. Closing the panel disconnects every
 * port (the tabs clear and close themselves) and the draft key dies with
 * the page, so nothing survives either.
 */
export function useReaderTabs(unlocked: boolean) {
  const readers = useRef(new Map<string, Reader>());
  const unlockedRef = useRef(unlocked);

  const drop = useCallback((nonce: string) => {
    const reader = readers.current.get(nonce);
    if (!reader) return;
    reader.sealed.fill(0);
    readers.current.delete(nonce);
  }, []);

  /** Unseal and post to every connected tab. The plaintext exists here
   *  only for the call. */
  const show = useCallback(async (reader: Reader) => {
    if (reader.ports.size === 0) return;
    let bytes: Uint8Array | null = null;
    try {
      bytes = await wasmApi.decryptDraft(reader.sealed);
      // Re-check after the await: a lock may have landed meanwhile
      // (`lockNow` flips this synchronously, before the lock's own awaits).
      if (!unlockedRef.current) return;
      const message: ReaderMessage = {
        type: "show",
        signer: reader.signer,
        text: new TextDecoder().decode(bytes),
      };
      for (const port of reader.ports) port.postMessage(message);
    } catch {
      /* a tab went away mid-post, or the draft key went with a reload */
    } finally {
      bytes?.fill(0);
    }
  }, []);

  /** Clear every reader now. Called first thing in the master lock, so
   *  the tabs clear with the panel rather than a render later, and no
   *  `show` in flight can post after it. */
  const lockNow = useCallback(() => {
    unlockedRef.current = false;
    for (const reader of readers.current.values()) {
      for (const port of reader.ports) port.postMessage(LOCKED);
    }
  }, []);

  useEffect(() => {
    const onConnect = (port: chrome.runtime.Port) => {
      if (!port.name.startsWith(READER_PORT_PREFIX)) return;
      const nonce = port.name.slice(READER_PORT_PREFIX.length);
      // Not ours (another panel window's reader, or a forged name):
      // leave it alone, so the panel that does own it can answer.
      const reader = isReaderNonce(nonce) ? readers.current.get(nonce) : null;
      if (!reader) return;
      reader.ports.add(port);
      port.onDisconnect.addListener(() => {
        reader.ports.delete(port);
        // The last tab closed: the message has nowhere left to go.
        if (reader.ports.size === 0) drop(nonce);
      });
      if (unlockedRef.current) void show({ ...reader, ports: new Set([port]) });
      else port.postMessage(LOCKED);
    };
    chrome.runtime.onConnect.addListener(onConnect);
    return () => chrome.runtime.onConnect.removeListener(onConnect);
  }, [show, drop]);

  // Unlock: every tab gets the message back. (Lock is `lockNow`, and
  // this repeats it for any path that locks without calling it.)
  useEffect(() => {
    if (!unlocked) {
      lockNow();
      return;
    }
    unlockedRef.current = true;
    for (const reader of readers.current.values()) void show(reader);
  }, [unlocked, show, lockNow]);

  // The panel going away takes the draft key with it; zero the sealed
  // bytes anyway rather than leave them to the collector.
  useEffect(() => {
    const all = readers.current;
    return () => {
      for (const reader of all.values()) reader.sealed.fill(0);
      all.clear();
    };
  }, []);

  /** Seal `text` and open a reader tab for it. The caller drops its own
   *  copy; from here the panel holds only the sealed bytes. */
  const open = useCallback(
    async (text: string, signer: ReaderSigner) => {
      await wasmApi.initDraftSessionIfUnset();
      const bytes = new TextEncoder().encode(text);
      let sealed: Uint8Array;
      try {
        sealed = await wasmApi.encryptDraft(bytes);
      } finally {
        bytes.fill(0);
      }
      const nonce = newReaderNonce();
      readers.current.set(nonce, { sealed, signer, ports: new Set() });
      try {
        await chrome.tabs.create({
          url: chrome.runtime.getURL(`reader.html#${nonce}`),
        });
      } catch (e) {
        drop(nonce);
        throw e;
      }
    },
    [drop],
  );

  return { open, lockNow };
}
