import "../lib/network-lockdown";

import type { OperationAction, PendingOperation } from "../lib/messages";
import {
  MENU_DECRYPT,
  MENU_ENCRYPT,
  MENU_SIGN,
  MENU_VERIFY,
} from "../lib/constants";

export default defineBackground(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  chrome.runtime.onInstalled.addListener((details) => {
    // First install: open the welcome page in a new tab. The page
    // hosts a single "click here to get started" button -- that
    // click is the user gesture that lets it call sidePanel.open()
    // (which we cannot do directly from `onInstalled`). The side
    // panel UI is never rendered in a tab.
    if (details.reason === "install") {
      void chrome.tabs.create({
        url: chrome.runtime.getURL("welcome.html"),
      });
    }

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
