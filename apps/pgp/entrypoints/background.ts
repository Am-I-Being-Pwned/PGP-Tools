import "../lib/network-lockdown";

import type { OperationAction, PendingOperation } from "../lib/messages";
import {
  MENU_DECRYPT,
  MENU_ENCRYPT,
  MENU_IMPORT_KEY,
  MENU_SIGN,
  MENU_VERIFY,
} from "../lib/constants";

export default defineBackground(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
      id: MENU_ENCRYPT,
      title: "Encrypt selection with PGP",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: MENU_DECRYPT,
      title: "Decrypt selection with PGP",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: MENU_SIGN,
      title: "Sign selection with PGP",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: MENU_VERIFY,
      title: "Verify PGP signature",
      contexts: ["selection"],
    });

    chrome.contextMenus.create({
      id: MENU_IMPORT_KEY,
      title: "Import PGP key from link",
      contexts: ["link"],
      targetUrlPatterns: [
        "*://*/*.asc",
        "*://*/*.asc?*",
        "*://*/*.gpg",
        "*://*/*.pub",
        "*://*/*.key",
        "*://*/*.pgp",
      ],
    });
  });

  const menuIdToAction: Partial<Record<string, OperationAction>> = {
    [MENU_ENCRYPT]: "encrypt",
    [MENU_DECRYPT]: "decrypt",
    [MENU_SIGN]: "sign",
    [MENU_VERIFY]: "verify",
  };

  let pendingQueue: PendingOperation | null = null;

  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    if (
      typeof message === "object" &&
      message !== null &&
      (message as { type: string }).type === "SIDEPANEL_READY"
    ) {
      if (pendingQueue) {
        chrome.runtime.sendMessage(pendingQueue).catch(() => {
          /* noop */
        });
        pendingQueue = null;
      }
    }
  });

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab?.id) return;
    const tabId = tab.id;

    void (async () => {
      if (info.menuItemId === MENU_IMPORT_KEY && info.linkUrl) {
        await chrome.sidePanel.open({ tabId });

        let armoredKey: string | undefined;
        let error: string | undefined;
        try {
          const resp = await fetch(info.linkUrl, { redirect: "error" });
          if (!resp.ok) {
            error = `HTTP ${resp.status}`;
          } else {
            const text = await resp.text();
            if (text.includes("PUBLIC KEY") || text.includes("PRIVATE KEY")) {
              armoredKey = text;
            } else {
              error = "File doesn't contain a PGP key";
            }
          }
        } catch {
          error =
            "Couldn't fetch - download the file and drop it on the Keys tab";
        }

        const msg = {
          type: "IMPORT_KEY_FROM_LINK" as const,
          url: info.linkUrl,
          armoredKey,
          error,
        };

        let delay = 100;
        const trySend = (attemptsLeft: number) => {
          chrome.runtime.sendMessage(msg).catch(() => {
            if (attemptsLeft > 0) {
              setTimeout(() => trySend(attemptsLeft - 1), delay);
              delay = Math.min(delay * 1.5, 1000);
            }
          });
        };
        trySend(8);
        return;
      }

      if (!info.selectionText) return;

      const action = menuIdToAction[info.menuItemId as string];
      if (!action) return;

      const operation: PendingOperation = {
        type: "PENDING_OPERATION",
        id: crypto.randomUUID(),
        action,
        text: info.selectionText,
        sourceTabId: tabId,
      };

      await chrome.sidePanel.open({ tabId });

      pendingQueue = operation;

      let delay = 100;
      const trySend = (attemptsLeft: number) => {
        if (!pendingQueue) return;
        chrome.runtime
          .sendMessage(operation)
          .then(() => {
            pendingQueue = null;
          })
          .catch(() => {
            if (attemptsLeft > 0) {
              setTimeout(() => trySend(attemptsLeft - 1), delay);
              delay = Math.min(delay * 1.5, 1000);
            }
          });
      };
      trySend(8);
    })();
  });
});
