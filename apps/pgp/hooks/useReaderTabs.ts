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
  port: chrome.runtime.Port | null;
}

/**
 * The panel's side of Reply's reader tabs (see lib/reader-protocol).
 *
 * The panel owns every message a reader shows. It is sealed the moment
 * Reply is pressed and opened again only to post it to a connected tab
 * while the vault is `unlocked`; locking tells every tab to drop it, and
 * unlocking sends it again. Closing the tab drops the sealed copy;
 * closing the panel disconnects every port (the tabs clear themselves)
 * and takes the draft key with it, so nothing survives either.
 */
export function useReaderTabs(unlocked: boolean) {
  const readers = useRef(new Map<string, Reader>());
  const unlockedRef = useRef(unlocked);

  /** Unseal and post. The plaintext exists here only for the call. */
  const show = useCallback(async (reader: Reader) => {
    const port = reader.port;
    if (!port) return;
    let bytes: Uint8Array | null = null;
    try {
      bytes = await wasmApi.decryptDraft(reader.sealed);
      // Re-check after the await: a lock may have landed meanwhile.
      if (!unlockedRef.current || reader.port !== port) return;
      const message: ReaderMessage = {
        type: "show",
        signer: reader.signer,
        text: new TextDecoder().decode(bytes),
      };
      port.postMessage(message);
    } catch {
      /* tab gone, or the draft key went with a panel reload */
    } finally {
      bytes?.fill(0);
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
      reader.port = port;
      port.onDisconnect.addListener(() => {
        // The tab closed: the message has nowhere left to go.
        if (reader.port !== port) return;
        reader.sealed.fill(0);
        readers.current.delete(nonce);
      });
      if (unlockedRef.current) void show(reader);
      else port.postMessage({ type: "locked" } satisfies ReaderMessage);
    };
    chrome.runtime.onConnect.addListener(onConnect);
    return () => chrome.runtime.onConnect.removeListener(onConnect);
  }, [show]);

  // Lock: every tab drops its text. Unlock: every tab gets it back.
  useEffect(() => {
    unlockedRef.current = unlocked;
    for (const reader of readers.current.values()) {
      if (!reader.port) continue;
      if (unlocked) void show(reader);
      else reader.port.postMessage({ type: "locked" } satisfies ReaderMessage);
    }
  }, [unlocked, show]);

  /** Seal `text` and open a reader tab for it. The caller drops its own
   *  copy; from here the panel holds only the sealed bytes. */
  const open = useCallback(async (text: string, signer: ReaderSigner) => {
    await wasmApi.initDraftSessionIfUnset();
    const bytes = new TextEncoder().encode(text);
    let sealed: Uint8Array;
    try {
      sealed = await wasmApi.encryptDraft(bytes);
    } finally {
      bytes.fill(0);
    }
    const nonce = newReaderNonce();
    readers.current.set(nonce, { sealed, signer, port: null });
    await chrome.tabs.create({
      url: chrome.runtime.getURL(`reader.html#${nonce}`),
    });
  }, []);

  return { open };
}
