import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  GmailAddRecipientsRequest,
  GmailAddRecipientsResponse,
  GmailAttachRequest,
  GmailAttachResponse,
  GmailComposeTarget,
  GmailFile,
  GmailFillResponse,
  GmailInsertRequest,
  GmailInsertResponse,
} from "../../lib/gmail/protocol";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import {
  bytesToBase64,
  gmailComposeUrl,
  gmailOrigins,
  isArmoredMessageOnly,
  isEncryptedFileBytes,
  isGmailFileList,
} from "../../lib/gmail/protocol";
import {
  addressesToAdd,
  matchRecipients,
  uncoveredRecipients,
} from "../../lib/gmail/recipients";
import { sendToGmailTab } from "../../lib/gmail/send-to-tab";

/**
 * The Gmail draft the workspace is currently writing for, if any.
 *
 * Set by a pending op from a compose window's Encrypt button, cleared by
 * any other pending op (the user moved on to something else), by
 * dismissing it, or by a successful insert. Holds the target (tab +
 * compose id + addresses) -- never any message text.
 *
 * KEPT IN STEP WITH THE KEYRING. A key that arrives while the draft is
 * open (the strip's "Search for key", an import from the Keys tab, a
 * sync from another device) is matched against the draft's addresses and
 * selected, and the "no key for" warning is derived from the CURRENT
 * selection rather than the first match, so it clears and returns as the
 * user changes the recipients.
 */
export function useGmailCompose(opts: {
  pendingAction:
    | { id?: string; text: string; gmail?: GmailComposeTarget | null }
    | null
    | undefined;
  contacts: PublicContactKey[];
  myKeys: ProtectedKeyBlob[];
  /** Contacts are still loading; matching waits for the full list. */
  vaultSettling: boolean;
  selectedRecipientIds: string[];
  setSelectedRecipientIds: (ids: string[]) => void;
  resetOutput: () => void;
  /** Clears the message box and result. */
  resetAll: () => void;
  /** True while the panel is writing a Reply (set by `openReply`). The
   *  only state in which an empty Gmail draft JOINS what is in the panel
   *  rather than starting it fresh. Consumed by the next draft. */
  replyFlowRef: React.MutableRefObject<boolean>;
}) {
  const [target, setTarget] = useState<GmailComposeTarget | null>(null);
  // Contacts this draft has already auto-selected, so a later re-match
  // only ADDS newcomers and never re-adds one the user took out.
  const matchedRef = useRef<Set<string>>(new Set());
  // Whether the arriving draft replaces the box or joins what is there.
  // Joining is ONLY for the panel's own Reply flow: the user pressed
  // Reply on a decrypted message, then Encrypt on Gmail's (empty) reply
  // window, and the reply they are writing belongs in it. Anything else
  // in the panel -- a half-written note to someone else -- is NOT
  // carried into this draft, or it would go to the wrong people.
  const mergeRef = useRef(false);
  const [needsMatch, setNeedsMatch] = useState(false);
  // The App hands a fresh object every render while an op is pending;
  // act on each op once.
  const handledRef = useRef<string | undefined>(undefined);

  const { pendingAction, resetAll, replyFlowRef } = opts;
  useEffect(() => {
    if (!pendingAction) return;
    if (pendingAction.id !== undefined) {
      if (handledRef.current === pendingAction.id) return;
      handledRef.current = pendingAction.id;
    }
    // A keyboard mode command (no text, no draft) only switches mode; it
    // must not drop the draft the user is in the middle of writing.
    if (!pendingAction.gmail && pendingAction.text === "") return;
    const next = pendingAction.gmail ?? null;
    const merge =
      next !== null && pendingAction.text === "" && replyFlowRef.current;
    replyFlowRef.current = false;
    // An empty draft outside the Reply flow starts the panel clean. (A
    // draft WITH text has already replaced the box, in useWorkspaceState.)
    if (next !== null && pendingAction.text === "" && !merge) resetAll();
    setTarget(next);
    matchedRef.current = new Set();
    mergeRef.current = merge;
    setNeedsMatch(next !== null);
  }, [pendingAction, resetAll, replyFlowRef]);

  const {
    contacts,
    myKeys,
    vaultSettling,
    selectedRecipientIds,
    setSelectedRecipientIds,
    resetOutput,
  } = opts;
  const ownUserIds = useMemo(() => myKeys.flatMap((k) => k.userIds), [myKeys]);
  useEffect(() => {
    if (!target || vaultSettling) return;
    const { ids } = matchRecipients(target.recipients, contacts, ownUserIds);
    if (needsMatch) {
      // First match for this draft: it sets the selection.
      setNeedsMatch(false);
      matchedRef.current = new Set(ids);
      setSelectedRecipientIds(
        mergeRef.current
          ? [...new Set([...selectedRecipientIds, ...ids])]
          : ids,
      );
      // A changed recipient set invalidates any ciphertext on screen.
      resetOutput();
      return;
    }
    // Later: the contact list changed. Select only the newcomers.
    const fresh = ids.filter((id) => !matchedRef.current.has(id));
    if (fresh.length === 0) return;
    for (const id of fresh) matchedRef.current.add(id);
    setSelectedRecipientIds([...new Set([...selectedRecipientIds, ...fresh])]);
    resetOutput();
  }, [
    needsMatch,
    target,
    vaultSettling,
    contacts,
    ownUserIds,
    selectedRecipientIds,
    setSelectedRecipientIds,
    resetOutput,
  ]);

  const missing = useMemo(() => {
    if (!target) return [];
    const selected = [...contacts, ...myKeys].filter((k) =>
      selectedRecipientIds.includes(k.keyId),
    );
    return uncoveredRecipients(target.recipients, selected, ownUserIds);
  }, [target, contacts, myKeys, selectedRecipientIds, ownUserIds]);

  const dismiss = useCallback(() => setTarget(null), []);

  const sendToDraft = useCallback(
    async <Res extends { ok: boolean }>(
      to: GmailComposeTarget,
      request:
        GmailInsertRequest | GmailAddRecipientsRequest | GmailAttachRequest,
    ): Promise<Res | { ok: false; error: "compose-gone" }> =>
      (await sendToGmailTab<Res>(to.tabId, request, to.documentId)) ?? {
        ok: false,
        error: "compose-gone",
      },
    [],
  );

  // A recipient picked HERE joins the draft's To line in Gmail, so the
  // panel and the draft agree on who the message is for. Addresses only,
  // and only for keys the draft does not already address. Each address
  // is tried once per draft: a failure (no To box we recognise) is not
  // retried on every render.
  const triedRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    triedRef.current = new Set();
  }, [target?.composeId]);
  useEffect(() => {
    if (!target || needsMatch || vaultSettling) return;
    const selected = contacts.filter((c) =>
      selectedRecipientIds.includes(c.keyId),
    );
    const toAdd = addressesToAdd(target.recipients, selected).filter(
      (a) => !triedRef.current.has(a),
    );
    if (toAdd.length === 0) return;
    for (const a of toAdd) triedRef.current.add(a);
    void sendToDraft<GmailAddRecipientsResponse>(target, {
      type: "GMAIL_ADD_RECIPIENTS",
      composeId: target.composeId,
      addresses: toAdd,
    }).then((res) => {
      if (!res.ok) return;
      setTarget((t) =>
        t?.composeId === target.composeId
          ? { ...t, recipients: [...new Set([...t.recipients, ...toAdd])] }
          : t,
      );
    });
  }, [
    target,
    needsMatch,
    vaultSettling,
    contacts,
    selectedRecipientIds,
    sendToDraft,
  ]);

  /**
   * Send ciphertext back to the draft. Refuses anything but one armored
   * PGP MESSAGE block BEFORE it leaves the panel; the content script
   * checks the same thing again before it touches Gmail's DOM.
   */
  const insert = useCallback(
    async (
      armored: string,
      opts: { send?: boolean } = {},
    ): Promise<GmailInsertResponse> => {
      if (!target || !isArmoredMessageOnly(armored)) {
        return { ok: false, error: "invalid" };
      }
      const res = await sendToDraft<GmailInsertResponse>(target, {
        type: "GMAIL_INSERT",
        composeId: target.composeId,
        armored,
        ...(opts.send ? { send: true } : {}),
      });
      if (res.ok) setTarget(null);
      return res;
    },
    [target, sendToDraft],
  );

  /**
   * Encrypted files for the draft: each checked to be ciphertext
   * (`isEncryptedFileBytes`) BEFORE it leaves the panel, and again by
   * the content script before it is dropped on Gmail's compose box.
   */
  const attach = useCallback(
    async (files: FileResult[]): Promise<GmailAttachResponse> => {
      const payload = toGmailFiles(files);
      if (!target || !payload) return { ok: false, error: "invalid" };
      const res = await sendToDraft<GmailAttachResponse>(target, {
        type: "GMAIL_ATTACH",
        composeId: target.composeId,
        files: payload,
      });
      if (res.ok) setTarget(null);
      return res;
    },
    [target, sendToDraft],
  );

  /**
   * "Add to Gmail" with no draft to go back to: open Gmail's own compose
   * window addressed to `to`, then write the ciphertext into its body
   * (or drop the encrypted files on it).
   *
   * The tab is one the panel just created, and the body is written only
   * while that tab is still on Gmail's origin, only into a lone EMPTY
   * compose window (the content script refuses otherwise), and only as
   * armored PGP MESSAGE blocks or encrypted files -- checked here and
   * again there.
   */
  const openNew = useCallback(
    async (
      payload: { armored: string } | { files: FileResult[] },
      to: string[],
    ): Promise<GmailFillResponse> => {
      const origin = gmailOrigins()[0];
      const files = "files" in payload ? toGmailFiles(payload.files) : null;
      if (
        !origin ||
        ("armored" in payload
          ? !isArmoredMessageOnly(payload.armored)
          : files === null)
      ) {
        return { ok: false, error: "invalid" };
      }
      const tab = await chrome.tabs.create({
        url: gmailComposeUrl(origin, to),
        active: true,
      });
      const tabId = tab.id;
      if (tabId === undefined) return { ok: false, error: "compose-gone" };
      // Gmail takes a while to draw a compose window, and the content
      // script only starts once the page settles: knock until it answers.
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        const now = await chrome.tabs.get(tabId).catch(() => null);
        if (!now) return { ok: false, error: "compose-gone" };
        const onGmail =
          now.url !== undefined && new URL(now.url).origin === origin;
        if (onGmail && now.status === "complete") {
          const res = await sendToGmailTab<GmailFillResponse>(
            tabId,
            files
              ? { type: "GMAIL_FILL", files }
              : {
                  type: "GMAIL_FILL",
                  armored: (payload as { armored: string }).armored,
                },
          );
          if (res) return res;
        }
        await new Promise((r) => setTimeout(r, 400));
      }
      return { ok: false, error: "compose-gone" };
    },
    [],
  );

  return { target, missing, dismiss, insert, attach, openNew };
}

/** Results as the wire carries them, or null if any is not ciphertext
 *  (then NONE goes: half a set attached is worse than none). */
function toGmailFiles(files: FileResult[]): GmailFile[] | null {
  if (!files.every((f) => isEncryptedFileBytes(f.data))) return null;
  const out = files.map((f) => ({ name: f.name, data: bytesToBase64(f.data) }));
  return isGmailFileList(out) ? out : null;
}
