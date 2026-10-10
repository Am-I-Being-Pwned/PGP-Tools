import { useCallback, useEffect, useRef } from "react";

import type {
  GmailFramePanelMessage,
  GmailFrameSigner,
} from "../lib/gmail/frame-protocol";
import type { GmailPanelPong } from "../lib/gmail/protocol";
import type { PublicContactKey } from "../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import {
  GMAIL_PANEL_READY,
  isGmailFramePort,
  isGmailFrameReadRequest,
} from "../lib/gmail/frame-protocol";
import * as pgpOps from "../lib/pgp/operations";
import { isPgpRecord } from "../lib/storage/key-kind";

interface FrameEntry {
  port: chrome.runtime.Port;
  kind: "message" | "signed";
  text: string;
  /** Bumped per answer, so a slow one cannot land over a newer one. */
  gen: number;
  /** What this frame was last told. A frame that is `shown` keeps its
   *  text across key changes; one told `locked` is retried on them. */
  last: GmailFramePanelMessage["type"] | null;
}

const LOCKED: GmailFramePanelMessage = { type: "locked" };

/**
 * The panel's side of the Gmail add-on's inline reader frames (see
 * lib/gmail/frame-protocol). Each frame connects with the armored block
 * it was given; this answers with the message -- decrypted or verified
 * HERE, the only realm with keys -- or with why it cannot.
 *
 * THE §15 RULES APPLY, UNCHANGED: a decrypt for a frame is unattended,
 * so it runs only when the key the message is for ALREADY has an open
 * handle. A closed key, a locked vault, a password-only message: the
 * frame is told `locked` (it offers "Unlock to read", which opens the
 * panel on the block through the pending-op channel, where the normal
 * prompts run) or `failed`. Nothing here ever starts a ceremony or asks
 * for a secret, and nothing is written anywhere. Verify needs no secret
 * and always runs. Locking tells every frame to drop its text at once;
 * unlocking, and any key opening, answers the waiting ones again.
 *
 * The plaintext exists here only for the call that posts it: it is not
 * kept, not sealed, not put in React state. The armor (ciphertext) is
 * kept per port so an unlock can answer again.
 */
export function useGmailFrames(opts: {
  /** The vault is open and the workspace mounted (`canRoutePendingOp`). */
  unlocked: boolean;
  /** Stores still being read / keys still opening: wait, so a verdict
   *  is not reached against an empty contact list. */
  settling: boolean;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  getKeyHandle: (keyId: string) => number | null;
  /** Changes whenever a key opens or closes: the trigger to answer
   *  frames that were told `locked`. */
  unlockedKeyIds: ReadonlySet<string>;
  /** "Never cache keys": handles are dropped after every operation, so
   *  an unattended decrypt never qualifies (§15) -- including one that
   *  would piggyback on a key the user just opened for something else. */
  neverCacheKeys: boolean;
}) {
  const {
    unlocked,
    settling,
    myKeys,
    contacts,
    getKeyHandle,
    unlockedKeyIds,
    neverCacheKeys,
  } = opts;
  const frames = useRef(new Map<chrome.runtime.Port, FrameEntry>());
  const unlockedRef = useRef(unlocked);
  const settlingRef = useRef(settling);
  useEffect(() => {
    settlingRef.current = settling;
  }, [settling]);

  const signerFor = useCallback(
    (signerKeyId: string | null): GmailFrameSigner | null => {
      if (!signerKeyId) return null;
      const hex = signerKeyId.toUpperCase();
      const found =
        contacts.find((c) => c.keyId.toUpperCase().endsWith(hex)) ??
        myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex));
      return found ? { keyId: found.keyId, userIds: found.userIds } : null;
    },
    [contacts, myKeys],
  );

  const post = useCallback((entry: FrameEntry, msg: GmailFramePanelMessage) => {
    entry.last = msg.type;
    try {
      entry.port.postMessage(msg);
    } catch {
      /* the frame went away */
    }
  }, []);

  /** Work out what this frame should see, and tell it. */
  const answer = useCallback(
    async (entry: FrameEntry) => {
      const gen = ++entry.gen;
      // Still the newest answer for a port still connected, and the
      // vault still open: re-checked after every await, because a lock
      // can land meanwhile (`lockNow` flips the ref synchronously).
      const live = () =>
        frames.current.get(entry.port) === entry &&
        entry.gen === gen &&
        unlockedRef.current;
      if (!live()) {
        post(entry, LOCKED);
        return;
      }
      const verificationKeys = [
        ...myKeys.filter(isPgpRecord).map((k) => k.publicKeyArmored),
        ...contacts.map((c) => c.armoredPublicKey),
      ];
      try {
        if (entry.kind === "signed") {
          const r = await pgpOps.verify({
            signedMessage: entry.text,
            verificationPublicKeys: verificationKeys,
          });
          if (!live()) return;
          if (r.signatureStatus === "invalid") {
            post(entry, { type: "failed", reason: "bad-signature" });
            return;
          }
          post(entry, {
            type: "show",
            text: r.text,
            signature: r.signatureStatus === "valid" ? "valid" : "unknown",
            signer:
              r.signatureStatus === "valid" ? signerFor(r.signerKeyId) : null,
          });
          return;
        }
        const input = { kind: "armored" as const, armoredMessage: entry.text };
        const pgpKeys = myKeys.filter(isPgpRecord);
        const keyId =
          pgpKeys.length === 0
            ? null
            : await pgpOps.selectDecryptionKey(
                input,
                pgpKeys.map((k) => k.publicKeyArmored),
              );
        if (!live()) return;
        if (keyId === null) {
          const enc = await pgpOps.messageEncryption(input).catch(() => null);
          if (!live()) return;
          post(entry, {
            type: "failed",
            reason: enc?.password && !enc.publicKey ? "password" : "no-key",
          });
          return;
        }
        // The one §15 gate: an open handle, or nothing. Never a prompt.
        // Under never-cache, nothing: a handle open right now is open
        // for an operation the user asked for, not for this.
        const handle = neverCacheKeys ? null : getKeyHandle(keyId);
        if (handle === null) {
          post(entry, LOCKED);
          return;
        }
        const r = await pgpOps.decryptWithHandle({
          input,
          keyHandle: handle,
          verificationPublicKeys: verificationKeys,
        });
        if (!live()) return;
        if (r.signatureStatus === "invalid") {
          post(entry, { type: "failed", reason: "bad-signature" });
          return;
        }
        if (typeof r.data !== "string") {
          // A binary payload has no place in a reader; the panel can
          // save it.
          post(entry, { type: "failed", reason: "error" });
          return;
        }
        post(entry, {
          type: "show",
          text: r.data,
          signature:
            r.signatureStatus === "valid"
              ? "valid"
              : r.signatureStatus === "unknown_key"
                ? "unknown"
                : "unsigned",
          signer:
            r.signatureStatus === "valid" ? signerFor(r.signerKeyId) : null,
        });
      } catch {
        if (live()) post(entry, { type: "failed", reason: "error" });
      }
    },
    [post, signerFor, myKeys, contacts, getKeyHandle, neverCacheKeys],
  );

  /** Tell every frame to drop its text, now. Called first thing in the
   *  master lock, before anything is awaited. */
  const lockNow = useCallback(() => {
    unlockedRef.current = false;
    for (const entry of frames.current.values()) {
      entry.gen++;
      post(entry, LOCKED);
    }
  }, [post]);

  // "Is a panel up?" from a Gmail tab's content script (so a compose
  // window in a PGP thread can turn encryption on by itself). Answered
  // only from a page of this extension; the worker stays silent, so no
  // answer means no panel. Nothing travels but the question and a bit.
  useEffect(() => {
    const onMessage = (
      msg: unknown,
      sender: chrome.runtime.MessageSender,
      sendResponse: (r: GmailPanelPong) => void,
    ): boolean | undefined => {
      if ((msg as { type?: unknown } | null)?.type !== "GMAIL_PANEL_PING") {
        return undefined;
      }
      if (sender.id !== chrome.runtime.id || !sender.tab) return undefined;
      sendResponse({ type: "GMAIL_PANEL_PONG", unlocked: unlockedRef.current });
      return undefined;
    };
    chrome.runtime.onMessage.addListener(onMessage);
    return () => chrome.runtime.onMessage.removeListener(onMessage);
  }, []);

  useEffect(() => {
    const onConnect = (port: chrome.runtime.Port) => {
      if (!isGmailFramePort(port)) return;
      const entry: FrameEntry = {
        port,
        kind: "message",
        text: "",
        gen: 0,
        last: null,
      };
      frames.current.set(port, entry);
      port.onMessage.addListener((raw: unknown) => {
        if (!isGmailFrameReadRequest(raw)) return;
        entry.kind = raw.kind;
        entry.text = raw.text;
        if (settlingRef.current) {
          // Answered by the effect below once the vault has settled.
          entry.last = null;
          return;
        }
        void answer(entry);
      });
      port.onDisconnect.addListener(() => {
        entry.gen++;
        frames.current.delete(port);
      });
    };
    chrome.runtime.onConnect.addListener(onConnect);
    return () => chrome.runtime.onConnect.removeListener(onConnect);
  }, [answer]);

  // Lock: every frame clears. Unlock, or keys opening or arriving: every
  // frame that is not showing its message is answered again. (A frame
  // already `shown` keeps what it has; nothing it shows changed.)
  useEffect(() => {
    if (!unlocked) {
      lockNow();
      return;
    }
    unlockedRef.current = true;
    if (settling) return;
    void chrome.runtime
      .sendMessage({ type: GMAIL_PANEL_READY })
      .catch(() => undefined);
    for (const entry of frames.current.values()) {
      if (entry.text === "" || entry.last === "show") continue;
      void answer(entry);
    }
  }, [unlocked, settling, unlockedKeyIds, myKeys, contacts, answer, lockNow]);

  useEffect(() => {
    const all = frames.current;
    return () => {
      for (const entry of all.values()) entry.port.disconnect();
      all.clear();
    };
  }, []);

  return { lockNow };
}
