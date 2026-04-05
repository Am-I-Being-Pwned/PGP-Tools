import "../lib/network-lockdown";

import type {
  AutoDecryptDownload,
  ImportKeyFromLink,
  OperationAction,
  PendingOperation,
} from "../lib/messages";
import {
  MENU_DECRYPT,
  MENU_ENCRYPT,
  MENU_IMPORT_KEY,
  MENU_SIGN,
  MENU_VERIFY,
  STORAGE_PREFERENCES,
} from "../lib/constants";
import { toBase64 } from "../lib/encoding";

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
  let pendingDownloadMsg: AutoDecryptDownload | ImportKeyFromLink | null = null;

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
      if (pendingDownloadMsg) {
        chrome.runtime.sendMessage(pendingDownloadMsg).catch(() => {
          /* noop */
        });
        pendingDownloadMsg = null;
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

  // ── Auto-handle PGP downloads ──────────────────────────────────────

  const PGP_EXT_RE = /\.(gpg|pgp|asc|key|pub|sig)$/i;

  /** Send a message to the side panel. If panel isn't open, queue it
   *  and show a notification so the user knows to open the extension. */
  function sendToSidePanel(
    msg: AutoDecryptDownload | ImportKeyFromLink,
    fileName: string,
  ) {
    pendingDownloadMsg = msg;

    chrome.runtime
      .sendMessage(msg)
      .then(() => {
        pendingDownloadMsg = null;
      })
      .catch(() => {
        const isKey = msg.type === "IMPORT_KEY_FROM_LINK";
        const title = isKey
          ? "PGP key downloaded"
          : "Encrypted file downloaded";
        const body = `${fileName} - click the PGP Tools icon to ${isKey ? "import" : "decrypt"}`;

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- chrome.notifications may not be available
        chrome.notifications?.create(
          "pgp-download-" + Date.now(),
          {
            type: "basic",
            iconUrl: "icon/128.png",
            title,
            message: body,
          },
          () => {
            /* noop */
          },
        );
      });
  }

  async function isAutoDecryptEnabled(): Promise<boolean> {
    const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
    const prefs = result[STORAGE_PREFERENCES] as
      | Record<string, unknown>
      | undefined;
    return prefs?.autoDecryptDownloads === true;
  }

  const downloadUrls = new Map<number, string>();
  let downloadListenersRegistered = false;

  function registerDownloadListeners() {
    if (downloadListenersRegistered) return;
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- chrome.downloads may not be available with optional permissions
    if (!chrome.downloads?.onCreated) {
      return;
    }

    downloadListenersRegistered = true;

    chrome.downloads.onCreated.addListener((item) => {
      if (item.url) {
        downloadUrls.set(item.id, item.url);
      }
    });

    chrome.downloads.onChanged.addListener((delta) => {
      if (delta.state?.current === "interrupted") {
        downloadUrls.delete(delta.id);
        return;
      }
      void (async () => {
        if (delta.state?.current !== "complete") return;

        const url = downloadUrls.get(delta.id);
        downloadUrls.delete(delta.id);

        if (!(await isAutoDecryptEnabled())) return;

        const [item] = await chrome.downloads.search({ id: delta.id });
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- search result may be empty
        if (!item) return;

        const fullPath = item.filename;
        const urlPath = url ?? "";

        if (!PGP_EXT_RE.test(fullPath) && !PGP_EXT_RE.test(urlPath)) return;

        const fileName =
          fullPath.split("/").pop()?.split("\\").pop() ?? "download.gpg";

        if (!url) return;

        try {
          const resp = await fetch(url, { redirect: "error" });
          if (!resp.ok) {
            return;
          }

          const buffer = await resp.arrayBuffer();
          const text = new TextDecoder("utf-8", { fatal: false }).decode(
            new Uint8Array(buffer.slice(0, 1024)),
          );

          if (
            text.includes("BEGIN PGP PUBLIC KEY") ||
            text.includes("BEGIN PGP PRIVATE KEY")
          ) {
            const fullText = new TextDecoder().decode(buffer);
            sendToSidePanel(
              {
                type: "IMPORT_KEY_FROM_LINK",
                url,
                armoredKey: fullText,
              },
              fileName,
            );
          } else {
            sendToSidePanel(
              {
                type: "AUTO_DECRYPT_DOWNLOAD",
                fileName,
                contentBase64: toBase64(buffer),
              },
              fileName,
            );
          }
        } catch { /* download listener cleanup */ }
      })();
    });
  }

  registerDownloadListeners();

  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- onAdded may not be available
  chrome.permissions.onAdded?.addListener((perms) => {
    if (perms.permissions?.includes("downloads")) {
      registerDownloadListeners();
    }
  });

  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    if (
      typeof message === "object" &&
      message !== null &&
      (message as { type: string }).type === "REGISTER_DOWNLOAD_LISTENERS"
    ) {
      registerDownloadListeners();
    }
  });
});
