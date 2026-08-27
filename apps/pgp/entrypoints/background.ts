import "../lib/network-lockdown";

import type {
  GithubKeysRequest,
  GithubKeysResponse,
  KeyserverKeyRequest,
  KeyserverKeyResponse,
  OperationAction,
  PendingOperation,
} from "../lib/messages";
import { recoverArmorIfNeeded } from "../lib/armor-recovery";
import { classifyAction } from "../lib/classify-action";
import { MENU_OPEN_IN_PGP, SESSION_PENDING_OP } from "../lib/constants";
import { fetchGithubKeys } from "../lib/github/fetch-keys";
import { isGithubUsername } from "../lib/github/username";
import { fetchKeyserverKey } from "../lib/keyserver/fetch-key";
import { isKeyserverQuery } from "../lib/keyserver/query";
import { commandToMode } from "../lib/mode-commands";
import { sweepStalePendingOp } from "../lib/pending-op";

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
  tab: chrome.tabs.Tab | undefined,
): void {
  const operation: PendingOperation = {
    type: "PENDING_OPERATION",
    id: crypto.randomUUID(),
    action,
    text,
    sourceTabId: tab?.id ?? chrome.tabs.TAB_ID_NONE,
    createdAt: Date.now(),
  };

  const target =
    tab?.id !== undefined
      ? { tabId: tab.id }
      : { windowId: tab?.windowId ?? chrome.windows.WINDOW_ID_CURRENT };
  chrome.sidePanel.open(target).catch(() => {
    /* sidepanel already open in this tab -- harmless */
  });
  // The in-flight storage write keeps the MV3 service worker alive
  // until it commits; the side panel reads the op on mount (or via
  // its storage.onChanged listener when already open).
  //
  // `text` is the user's raw selection and goes in UNSEALED. That is not
  // an oversight: the worker has no wasm instance, so it has no draft
  // key (or any other key) to seal with, and it is the party that holds
  // the plaintext anyway -- sealing here would defend against nobody who
  // is not already holding it. What bounds the exposure is lifetime, so
  // see `sweepStalePendingOp` for the path where the panel never opens
  // to consume it.
  void chrome.storage.session.set({ [SESSION_PENDING_OP]: operation });
}

/**
 * Handle a GitHub SSH-key lookup for the side panel.
 *
 * Why this one is a message and not the `chrome.storage.session` channel
 * `openPanelWithOperation` uses: that channel is one-way (worker tells
 * panel something happened). This is a request that needs a reply, and
 * the panel needs to know which reply belongs to which request.
 *
 * Why the network call lives in the worker at all: the manifest CSP has
 * to be widened for api.github.com, and doing that for the worker only
 * lets the side panel keep the exact `connect-src 'self'` it had before
 * (see the meta CSP in sidepanel/index.html).
 *
 * The username is re-validated here even though the panel validates too:
 * the panel is the untrusted side of this boundary. Anything that can
 * send a runtime message -- a compromised panel, a future entrypoint --
 * reaches this function, and without the check `username` is a path
 * fragment and this becomes an arbitrary GET.
 */
async function handleGithubKeysRequest(
  message: GithubKeysRequest,
): Promise<GithubKeysResponse> {
  const { username } = message;
  if (!isGithubUsername(username)) {
    return { ok: false, error: "invalid-username" };
  }

  const result = await fetchGithubKeys(username);
  if (!result.ok) {
    return { ok: false, error: result.error, resetAt: result.resetAt };
  }
  // `omitted` travels with the lines: the panel cannot tell a truncated
  // list from a complete one by looking at it.
  return { ok: true, username, lines: result.lines, omitted: result.omitted };
}

/**
 * Handle a keys.openpgp.org key lookup for the side panel.
 *
 * The twin of {@link handleGithubKeysRequest}, and it is a twin on
 * purpose: two lookups that both take untrusted bytes off the network in
 * the worker should not have two different shapes for anyone auditing
 * them. Same message-not-session-channel reasoning, same
 * re-validate-at-the-boundary rule, same tagged-codes-never-prose rule.
 *
 * The query is re-derived here even though the panel derives it too: the
 * panel is the untrusted side of this boundary. Anything that can send a
 * runtime message reaches this function, and without the check `query`
 * is a path fragment and this becomes an arbitrary GET against
 * keys.openpgp.org.
 */
async function handleKeyserverKeyRequest(
  message: KeyserverKeyRequest,
): Promise<KeyserverKeyResponse> {
  const { query } = message;
  if (!isKeyserverQuery(query)) {
    return { ok: false, error: "invalid-query" };
  }

  const result = await fetchKeyserverKey(query);
  if (!result.ok) {
    return { ok: false, error: result.error, retryAt: result.retryAt };
  }
  return { ok: true, query, armored: result.armored, omitted: result.omitted };
}

export default defineBackground(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

  // Every worker start, not just onStartup/onInstalled: a pending op is
  // normally deleted by the side panel when it reads it, so the only
  // ones still here are the ones no panel ever collected. Cheap (one
  // session-storage read, which is memory), and it is the only thing
  // stopping an uncollected selection from outliving its TTL by the
  // whole browser session.
  void sweepStalePendingOp();

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
  chrome.commands.onCommand.addListener((command, tab) => {
    const mode = commandToMode(command);
    if (!mode) return;
    openPanelWithOperation(mode, "", tab);
  });

  // The app's first onMessage listener. Returning `true` keeps the
  // channel open for the async sendResponse; returning it only on the
  // message types we own leaves any future listener free to claim the
  // rest.
  chrome.runtime.onMessage.addListener(
    (message: unknown, _sender, sendResponse) => {
      if (typeof message !== "object" || message === null) return undefined;
      const type = (message as { type?: unknown }).type;

      // Both lookups answer the same way: a tagged code on every failure
      // path, including the rejection handler, so a thrown error can
      // never reach the panel as prose.
      if (type === "GITHUB_KEYS_REQUEST") {
        void handleGithubKeysRequest(message as GithubKeysRequest).then(
          sendResponse,
          () => {
            sendResponse({ ok: false, error: "server-error" });
          },
        );
        return true;
      }

      if (type === "KEYSERVER_KEY_REQUEST") {
        void handleKeyserverKeyRequest(message as KeyserverKeyRequest).then(
          sendResponse,
          () => {
            sendResponse({ ok: false, error: "server-error" });
          },
        );
        return true;
      }

      return undefined;
    },
  );
});
