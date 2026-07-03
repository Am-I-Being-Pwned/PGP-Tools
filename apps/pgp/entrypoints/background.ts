import "../lib/network-lockdown";

import type { PendingOperation } from "../lib/messages";
import { recoverArmorIfNeeded } from "../lib/armor-recovery";
import { classifyAction } from "../lib/classify-action";
import { MENU_OPEN_IN_PGP, SESSION_PENDING_OP } from "../lib/constants";

export default defineBackground(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === "install") {
      void chrome.tabs.create({
        url: chrome.runtime.getURL("welcome.html"),
      });
    }

    // Single top-level item. Action is decided at click time so Chrome
    // never has more than one item to group into a submenu.
    chrome.contextMenus.create({
      id: MENU_OPEN_IN_PGP,
      title: "Open in PGP Tools",
      contexts: ["selection"],
    });
  });

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab?.id || !info.selectionText) return;
    if (info.menuItemId !== MENU_OPEN_IN_PGP) return;
    const tabId = tab.id;

    // Chrome's info.selectionText collapses all whitespace into single
    // spaces, which destroys armored PGP blocks. Reconstruct the line
    // breaks before persisting so downstream consumers (parser, import
    // dialog, decrypt) receive valid armor.
    const text = recoverArmorIfNeeded(info.selectionText);

    const operation: PendingOperation = {
      type: "PENDING_OPERATION",
      id: crypto.randomUUID(),
      action: classifyAction(text),
      text,
      sourceTabId: tabId,
      createdAt: Date.now(),
    };

    // sidePanel.open MUST be called synchronously inside the click
    // handler -- Chrome rejects it as a non-gesture if anything
    // awaits before it.
    chrome.sidePanel.open({ tabId }).catch(() => {
      /* sidepanel already open in this tab -- harmless */
    });
    // The in-flight storage write keeps the MV3 service worker alive
    // until it commits; the side panel reads the op on mount.
    void chrome.storage.session.set({ [SESSION_PENDING_OP]: operation });
  });
});
