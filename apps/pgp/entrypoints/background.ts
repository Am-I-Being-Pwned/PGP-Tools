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
import { menuMayActOn } from "../lib/context-menu";
import { fetchGithubKeys } from "../lib/github/fetch-keys";
import { isGithubUsername } from "../lib/github/username";
import { t } from "../lib/i18n";
import { fetchKeyserverKey } from "../lib/keyserver/fetch-key";
import { isKeyserverQuery } from "../lib/keyserver/query";
import { commandToMode } from "../lib/mode-commands";
import { sweepStalePendingOp } from "../lib/pending-op";

/**
 * Open the side panel and hand it a pending operation. MUST be called
 * synchronously in the gesture handler: Chrome rejects sidePanel.open as a
 * non-gesture if anything awaits first.
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
    ...(tab?.windowId !== undefined ? { windowId: tab.windowId } : {}),
    createdAt: Date.now(),
  };

  const target =
    tab?.id !== undefined
      ? { tabId: tab.id }
      : { windowId: tab?.windowId ?? chrome.windows.WINDOW_ID_CURRENT };
  chrome.sidePanel.open(target).catch(() => {
    /* sidepanel already open in this tab -- harmless */
  });
  // `text` goes in UNSEALED on purpose: the worker has no key to seal with
  // and already holds the plaintext. Exposure is bounded by lifetime
  // instead (`sweepStalePendingOp`).
  void chrome.storage.session.set({ [SESSION_PENDING_OP]: operation });
}

/**
 * GitHub SSH-key lookup for the side panel. The fetch lives in the worker
 * so only the worker's CSP is widened; the panel keeps `connect-src 'self'`
 * (sidepanel/index.html). The username is re-validated here because the
 * sender is untrusted: unchecked, it is a path fragment and this becomes an
 * arbitrary GET.
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
  // `omitted` travels with the lines: a truncated list looks complete.
  return { ok: true, username, lines: result.lines, omitted: result.omitted };
}

/**
 * keys.openpgp.org lookup; deliberately the same shape as
 * {@link handleGithubKeysRequest}, including re-validating `query` at this
 * untrusted boundary.
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

  // Every worker start: the only thing stopping an uncollected selection
  // from outliving its TTL by the whole browser session.
  void sweepStalePendingOp();

  chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === "install") {
      void chrome.tabs.create({
        url: chrome.runtime.getURL("welcome.html"),
      });
    }

    // No `documentUrlPatterns`: Chrome matches the FRAME URL, hiding the
    // item in webmail's about:blank/srcdoc frames. Never acting on the
    // extension's own pages (decrypted plaintext) is enforced per click
    // by `menuMayActOn`.
    chrome.contextMenus.create({
      id: MENU_OPEN_IN_PGP,
      title: t("app_menu_open_in_pgp_tools"),
      contexts: ["selection"],
    });
  });

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab?.id || !info.selectionText) return;
    if (info.menuItemId !== MENU_OPEN_IN_PGP) return;
    if (!menuMayActOn(info, chrome.runtime.getURL(""))) return;

    // selectionText collapses whitespace, destroying armor line breaks.
    const text = recoverArmorIfNeeded(info.selectionText);

    openPanelWithOperation(classifyAction(text), text, tab);
  });

  // Mode shortcuts: empty text, so the panel switches mode without
  // touching the current input.
  chrome.commands.onCommand.addListener((command, tab) => {
    const mode = commandToMode(command);
    if (!mode) return;
    openPanelWithOperation(mode, "", tab);
  });

  // Return `true` (async reply) only for message types we own.
  chrome.runtime.onMessage.addListener(
    (message: unknown, _sender, sendResponse) => {
      if (typeof message !== "object" || message === null) return undefined;
      const type = (message as { type?: unknown }).type;

      // Tagged code on every failure path, so a thrown error never
      // reaches the panel as prose.
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
