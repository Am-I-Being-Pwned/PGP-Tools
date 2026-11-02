import { useCallback, useEffect, useRef } from "react";

import * as wasmApi from "~/lib/pgp/wasm";
import {
  isReaderNonce,
  newReaderNonce,
  READER_PORT_PREFIX,
  type ReaderMessage,
  type ReaderSigner,
} from "~/lib/reader-protocol";

interface Reader {
  /** Sealed under the in-WASM draft key. Never plaintext here. */
  sealed: Uint8Array;
  signer: ReaderSigner;
  /** A duplicated tab reuses the nonce; every copy must be locked too. */
  ports: Set<chrome.runtime.Port>;
}

const LOCKED: ReaderMessage = { type: "locked" };

/** Whether `sender` is our own reader page for `nonce`. Belt to the
 *  nonce's braces: any other sender gets no answer even with the name. */
export function isOwnReaderSender(
  sender: chrome.runtime.MessageSender | undefined,
  nonce: string,
  extensionId: string,
  readerUrl: string,
): boolean {
  if (sender?.id !== extensionId || !sender.url) return false;
  let url: URL;
  let expected: URL;
  try {
    url = new URL(sender.url);
    expected = new URL(readerUrl);
  } catch {
    return false;
  }
  // Not `origin`: some URL implementations give chrome-extension: an
  // opaque "null" origin, equal for every extension.
  return (
    url.protocol === expected.protocol &&
    url.host === expected.host &&
    url.pathname === expected.pathname &&
    url.search === "" &&
    url.hash === `#${nonce}`
  );
}

/**
 * Panel side of Reply's reader tabs (lib/reader-protocol). Messages are
 * sealed on Reply and unsealed only to post while unlocked; lock tells
 * every tab to drop it. The sealed copy is zeroed when its last tab closes.
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

  /** Plaintext exists only for the duration of this call. */
  const show = useCallback(async (reader: Reader) => {
    if (reader.ports.size === 0) return;
    let bytes: Uint8Array | null = null;
    try {
      bytes = await wasmApi.decryptDraft(reader.sealed);
      // A lock may have landed during the await (`lockNow` is synchronous).
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

  /** Called first in the master lock so no in-flight `show` posts after. */
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
      // Not ours: leave it for the panel that owns it.
      const reader = isReaderNonce(nonce) ? readers.current.get(nonce) : null;
      if (!reader) return;
      const fromReader = isOwnReaderSender(
        port.sender,
        nonce,
        chrome.runtime.id,
        chrome.runtime.getURL("reader.html"),
      );
      if (!fromReader) return;
      reader.ports.add(port);
      port.onDisconnect.addListener(() => {
        reader.ports.delete(port);
        if (reader.ports.size === 0) drop(nonce);
      });
      if (unlockedRef.current) void show({ ...reader, ports: new Set([port]) });
      else port.postMessage(LOCKED);
    };
    chrome.runtime.onConnect.addListener(onConnect);
    return () => chrome.runtime.onConnect.removeListener(onConnect);
  }, [show, drop]);

  // Also repeats the lock for any path that locks without `lockNow`.
  useEffect(() => {
    if (!unlocked) {
      lockNow();
      return;
    }
    unlockedRef.current = true;
    for (const reader of readers.current.values()) void show(reader);
  }, [unlocked, show, lockNow]);

  useEffect(() => {
    const all = readers.current;
    return () => {
      for (const reader of all.values()) reader.sealed.fill(0);
      all.clear();
    };
  }, []);

  /** Seal `text` and open a reader tab; the caller drops its own copy. */
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
