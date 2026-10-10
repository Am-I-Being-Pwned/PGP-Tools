import "../lib/network-lockdown";

import type { GmailOpenResponse } from "../lib/gmail/protocol";
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
import {
  GMAIL_FRAME_PAGE,
  isGmailFrameOpenRequest,
} from "../lib/gmail/frame-protocol";
import {
  gmailMatchPatterns,
  gmailOrigins,
  isGmailOpenRequest,
  sanitizeRecipients,
} from "../lib/gmail/protocol";
import { t } from "../lib/i18n";
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
  openPanel(tab).catch(() => {
    /* sidepanel already open in this tab -- harmless */
  });
  void writePendingOperation(action, text, tab);
}

/** The gesture-bound half of {@link openPanelWithOperation}: MUST be
 *  called synchronously inside the user's event. */
function openPanel(tab: chrome.tabs.Tab | undefined): Promise<void> {
  const target =
    tab?.id !== undefined
      ? { tabId: tab.id }
      : { windowId: tab?.windowId ?? chrome.windows.WINDOW_ID_CURRENT };
  return chrome.sidePanel.open(target);
}

function writePendingOperation(
  action: OperationAction,
  text: string,
  tab: chrome.tabs.Tab | undefined,
  gmail?: PendingOperation["gmail"],
  gmailAttachment?: PendingOperation["gmailAttachment"],
): Promise<void> {
  const operation: PendingOperation = {
    type: "PENDING_OPERATION",
    id: crypto.randomUUID(),
    action,
    text,
    sourceTabId: tab?.id ?? chrome.tabs.TAB_ID_NONE,
    createdAt: Date.now(),
    ...(gmail ? { gmail } : {}),
    ...(gmailAttachment ? { gmailAttachment } : {}),
  };
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
  return chrome.storage.session.set({ [SESSION_PENDING_OP]: operation });
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

// ── Gmail add-on ─────────────────────────────────────────────────────
//
// Off by default and entirely permission-driven: the content script is
// registered while the optional mail.google.com host permission is held
// and unregistered when it is not. There is no preference to keep in
// step -- the grant IS the switch, which is also what lets the worker
// decide without unlocking the vault (settings are encrypted).

const GMAIL_SCRIPT_ID = "pgp-tools-gmail";
const GMAIL_SCRIPT_FILE = "content-scripts/gmail.js";

/**
 * Make the registered content scripts match the permission. `inject`
 * also runs the script in Gmail tabs that are already open, so turning
 * the add-on on works without a reload.
 */
/** Last known grant, for the one decision that cannot wait for an
 *  async check: whether to open the panel inside a click. Null until the
 *  first sync of this worker's life answers. */
let gmailGranted: boolean | null = null;

/** Syncs run one after another: an add and a remove landing together
 *  must not interleave their register/unregister calls. */
let gmailSync: Promise<void> = Promise.resolve();

function syncGmailScript(inject: boolean): Promise<void> {
  gmailSync = gmailSync
    .then(() => doSyncGmailScript(inject))
    .catch(() => {
      /* next event or worker start tries again */
    });
  return gmailSync;
}

async function doSyncGmailScript(inject: boolean): Promise<void> {
  const matches = gmailMatchPatterns();
  if (matches.length === 0) return;
  const granted = await chrome.permissions.contains({ origins: matches });
  gmailGranted = granted;
  const registered = await chrome.scripting.getRegisteredContentScripts({
    ids: [GMAIL_SCRIPT_ID],
  });
  if (!granted) {
    if (registered.length > 0) {
      await chrome.scripting.unregisterContentScripts({
        ids: [GMAIL_SCRIPT_ID],
      });
    }
    return;
  }
  if (registered.length === 0) {
    await chrome.scripting.registerContentScripts([
      {
        id: GMAIL_SCRIPT_ID,
        matches,
        js: [GMAIL_SCRIPT_FILE],
        runAt: "document_idle",
        allFrames: false,
        persistAcrossSessions: true,
      },
    ]);
  }
  if (!inject) return;
  // Host permission alone lets `tabs.query` filter on these URLs; no
  // `tabs` permission involved. The script guards against running twice.
  const tabs = await chrome.tabs.query({ url: matches });
  for (const tab of tabs) {
    if (tab.id === undefined) continue;
    chrome.scripting
      .executeScript({ target: { tabId: tab.id }, files: [GMAIL_SCRIPT_FILE] })
      .catch(() => {
        /* a discarded or crashed tab; it picks the script up on load */
      });
  }
}

/**
 * Handle a click in Gmail: the banner's Decrypt / Verify / Import, or a
 * compose window's Encrypt.
 *
 * The sender is checked before anything else -- a GMAIL_OPEN from any
 * page other than Gmail's top frame is dropped, so the worker's one way
 * of opening the panel on page-supplied text stays tied to the origin
 * the user granted. Then the ACTION IS DERIVED, NOT TAKEN: the page says
 * what text it saw, `classifyAction` decides what that text is, and only
 * a decrypt, a verify or a public-key import is acted on. A private key
 * in an email is not something to route anywhere from a banner. A
 * compose request is always `encrypt`, whatever its draft looks like.
 *
 * `sidePanel.open` runs synchronously, inside the user's click: Chrome
 * carries the gesture across `runtime.sendMessage` from a content
 * script, but not across an await. That is why the permission check
 * comes after it -- a script left running in a tab after the user
 * revoked access gets an empty panel and a "turned off" note, never a
 * routed message.
 *
 * What reaches session storage is what the context menu already puts
 * there (T-PENDING-OP-AT-REST): armored text the page shows, or the
 * draft the user typed into Gmail's own box, plus addresses.
 */
function handleGmailOpen(
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (r: GmailOpenResponse) => void,
): void {
  const tab = sender.tab;
  if (
    !isGmailOpenRequest(message) ||
    sender.id !== chrome.runtime.id ||
    tab?.id === undefined ||
    sender.frameId !== 0 ||
    sender.origin === undefined ||
    !gmailOrigins().includes(sender.origin)
  ) {
    sendResponse({ ok: false, error: "invalid" });
    return;
  }

  // Known to be off: refuse without even opening the panel. (Unknown --
  // a worker woken by this very message -- falls through to the check
  // after the open below.)
  if (gmailGranted === false) {
    sendResponse({ ok: false, error: "not-enabled" });
    return;
  }

  let action: OperationAction;
  if (message.compose) {
    action = "encrypt";
  } else if (message.attachment) {
    // The bytes are fetched by the panel later and classified there;
    // until then an encrypted attachment is a decrypt.
    action = "decrypt";
  } else {
    action = classifyAction(message.text);
    if (
      action !== "decrypt" &&
      action !== "verify" &&
      action !== "import-public"
    ) {
      sendResponse({ ok: false, error: "invalid" });
      return;
    }
  }

  // Settled, never rejected, so the outcome can be read after the
  // permission check without an unhandled rejection in between. A
  // silent request (a compose window arming itself, no click behind it)
  // does not try: there is no gesture, and the panel it is for is
  // already up.
  const opened = message.silent
    ? Promise.resolve(true)
    : openPanel(tab).then(
        () => true,
        () => false,
      );
  void (async () => {
    const granted = await chrome.permissions.contains({
      origins: gmailMatchPatterns(),
    });
    if (!granted) {
      sendResponse({ ok: false, error: "not-enabled" });
      return;
    }
    // The cover's button: the panel up, nothing written.
    if (message.focus) {
      sendResponse(
        (await opened) ? { ok: true } : { ok: false, error: "panel-failed" },
      );
      return;
    }
    // Written even when the panel failed to open: the note in Gmail
    // tells the user to click the toolbar icon, and the panel that click
    // opens picks the op up (within PENDING_OP_TTL_MS, like any other).
    // The draft's document is stamped HERE, from what Chrome says sent
    // the click -- never from the page -- and the addresses are filtered
    // again. The insert is later pinned to this document.
    const compose = message.compose && {
      composeId: message.compose.composeId,
      recipients: sanitizeRecipients(message.compose.recipients),
      ...(sender.documentId ? { documentId: sender.documentId } : {}),
    };
    const attachment = message.attachment && {
      attachmentId: message.attachment.attachmentId,
      name: message.attachment.name,
      ...(sender.documentId ? { documentId: sender.documentId } : {}),
    };
    await writePendingOperation(action, message.text, tab, compose, attachment);
    sendResponse(
      (await opened) ? { ok: true } : { ok: false, error: "panel-failed" },
    );
  })().catch(() => sendResponse({ ok: false, error: "panel-failed" }));
}

/**
 * "Unlock to read" / "Open in PGP Tools" pressed inside an inline reader
 * frame (SECURITY.md §17). The frame is one of OUR pages, embedded in a
 * Gmail tab: the sender must be this extension, at the frame page's
 * URL, inside a tab and not its top frame. The text it carries is the
 * armored block the content script gave it -- ciphertext Gmail showed --
 * and it goes through exactly the path a banner click takes: action
 * derived from the text, decrypt / verify only, panel opened inside the
 * gesture, permission re-checked, pending op written.
 */
function handleGmailFrameOpen(
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (r: GmailOpenResponse) => void,
): void {
  const tab = sender.tab;
  const page = chrome.runtime.getURL(GMAIL_FRAME_PAGE);
  const url = sender.url ?? "";
  if (
    !isGmailFrameOpenRequest(message) ||
    sender.id !== chrome.runtime.id ||
    tab?.id === undefined ||
    sender.frameId === undefined ||
    sender.frameId === 0 ||
    !(url === page || url.startsWith(`${page}#`))
  ) {
    sendResponse({ ok: false, error: "invalid" });
    return;
  }
  if (gmailGranted === false) {
    sendResponse({ ok: false, error: "not-enabled" });
    return;
  }
  const action = classifyAction(message.text);
  if (action !== "decrypt" && action !== "verify") {
    sendResponse({ ok: false, error: "invalid" });
    return;
  }
  const opened = openPanel(tab).then(
    () => true,
    () => false,
  );
  void (async () => {
    const granted = await chrome.permissions.contains({
      origins: gmailMatchPatterns(),
    });
    if (!granted) {
      sendResponse({ ok: false, error: "not-enabled" });
      return;
    }
    await writePendingOperation(action, message.text, tab);
    sendResponse(
      (await opened) ? { ok: true } : { ok: false, error: "panel-failed" },
    );
  })().catch(() => sendResponse({ ok: false, error: "panel-failed" }));
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

  // Every worker start, like the sweep: cheap, and it repairs a
  // registration that drifted from the permission while we were asleep.
  void syncGmailScript(false);
  chrome.permissions.onAdded.addListener(() => void syncGmailScript(true));
  chrome.permissions.onRemoved.addListener(() => void syncGmailScript(false));

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
      title: t("app_menu_open_in_pgp_tools"),
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
    (message: unknown, sender, sendResponse) => {
      if (typeof message !== "object" || message === null) return undefined;
      const type = (message as { type?: unknown }).type;

      if (type === "GMAIL_OPEN") {
        handleGmailOpen(message, sender, sendResponse);
        return true;
      }
      if (type === "GMAIL_FRAME_OPEN") {
        handleGmailFrameOpen(message, sender, sendResponse);
        return true;
      }

      // Everything below is for the extension's own pages. Since the
      // Gmail add-on there is a content script that can reach this
      // listener too; it has no business asking for a key lookup.
      if (!sender.url?.startsWith(chrome.runtime.getURL(""))) {
        return undefined;
      }

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
