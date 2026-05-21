import "../lib/network-lockdown";

import type { OperationAction, PendingOperation } from "../lib/messages";
import { MENU_OPEN_IN_PGP, SESSION_PENDING_OP } from "../lib/constants";
import { recoverArmorIfNeeded } from "../lib/armor-recovery";

/** Classify the selected text by PGP armor header to decide which
 *  action the side panel should take. Substring checks only -- no
 *  parsing here, the side panel re-validates. */
function classifyAction(text: string): OperationAction {
  if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
    return "import-public";
  }
  if (text.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
    return "import-private";
  }
  if (text.includes("-----BEGIN PGP MESSAGE-----")) return "decrypt";
  if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) return "verify";
  return "encrypt";
}

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

  // Async listener: returning a Promise keeps the MV3 service worker
  // alive until the storage write commits. Without this, the SW could
  // be killed after the sync portion of the handler returns, leaving
  // chrome.storage.session.set in-flight and the side panel mounting
  // to an empty store.
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
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
    await chrome.storage.session.set({ [SESSION_PENDING_OP]: operation });
  });
});
