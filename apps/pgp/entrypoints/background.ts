import "../lib/network-lockdown";

import type { Browser } from "wxt/browser";

import type { OperationAction, PendingOperation } from "../lib/messages";
import { recoverArmorIfNeeded } from "../lib/armor-recovery";
import { classifyAction } from "../lib/classify-action";
import { MENU_OPEN_IN_PGP, SESSION_PENDING_OP } from "../lib/constants";
import { commandToMode } from "../lib/mode-commands";
import { installActionOpener, openSidePanel } from "../lib/side-panel";

/**
 * Open the side panel and hand it a pending operation. Shared by the
 * context-menu and keyboard-command paths; both are user gestures, and
 * both MUST call this synchronously inside their event handler --
 * Chrome rejects sidePanel.open as a non-gesture if anything awaits
 * first.
 */
function openPanelWithOperation(
  action: OperationAction,
  text: string,
  tab: Browser.tabs.Tab | undefined,
): void {
  const operation: PendingOperation = {
    type: "PENDING_OPERATION",
    id: crypto.randomUUID(),
    action,
    text,
    sourceTabId: tab?.id ?? browser.tabs.TAB_ID_NONE,
    createdAt: Date.now(),
  };

  const target =
    tab?.id !== undefined
      ? { tabId: tab.id }
      : { windowId: tab?.windowId ?? browser.windows.WINDOW_ID_CURRENT };
  openSidePanel(target).catch(() => {
    /* sidepanel already open in this tab -- harmless */
  });
  // The in-flight storage write keeps the MV3 service worker alive
  // until it commits; the side panel reads the op on mount (or via
  // its storage.onChanged listener when already open).
  void browser.storage.session.set({ [SESSION_PENDING_OP]: operation });
}

export default defineBackground(() => {
  installActionOpener();

  browser.runtime.onInstalled.addListener((details) => {
    if (details.reason === "install") {
      void browser.tabs.create({
        url: browser.runtime.getURL("/welcome.html"),
      });
    }

    // Single top-level item. Action is decided at click time so Chrome
    // never has more than one item to group into a submenu.
    browser.contextMenus.create({
      id: MENU_OPEN_IN_PGP,
      title: "Open in PGP Tools",
      contexts: ["selection"],
    });
  });

  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab?.id || !info.selectionText) return;
    if (info.menuItemId !== MENU_OPEN_IN_PGP) return;

    // Chrome's info.selectionText collapses all whitespace into single
    // spaces, which destroys armored PGP blocks. Reconstruct the line
    // breaks before persisting so downstream consumers (parser, import
    // dialog, decrypt) receive valid armor.
    const text = recoverArmorIfNeeded(info.selectionText);

    openPanelWithOperation(classifyAction(text), text, tab);
  });

  // Browser-global mode shortcuts (Alt+Shift+E/D/S; Verify is bound by
  // the user in chrome://extensions/shortcuts). Same pending-op channel
  // as the context menu, but with empty text: the panel switches mode
  // without touching the current input.
  browser.commands.onCommand.addListener((command, tab) => {
    const mode = commandToMode(command);
    if (!mode) return;
    openPanelWithOperation(mode, "", tab);
  });
});
