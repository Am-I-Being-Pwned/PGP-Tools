import { useCallback, useEffect, useState } from "react";

import { gmailMatchPatterns } from "../lib/gmail/protocol";

/**
 * Whether the Gmail add-on is on, which is exactly whether Chrome holds
 * the optional mail.google.com host permission. No preference mirrors
 * it: two sources of truth would disagree the first time the user
 * revoked access from chrome://extensions. The worker registers and
 * unregisters the content script off the same permission events.
 */
export function useGmailAccess() {
  /** null until the first read answers. */
  const [enabled, setEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    const origins = gmailMatchPatterns();
    const refresh = () => {
      void chrome.permissions.contains({ origins }).then(setEnabled);
    };
    refresh();
    chrome.permissions.onAdded.addListener(refresh);
    chrome.permissions.onRemoved.addListener(refresh);
    return () => {
      chrome.permissions.onAdded.removeListener(refresh);
      chrome.permissions.onRemoved.removeListener(refresh);
    };
  }, []);

  /**
   * MUST be called synchronously from the click: Chrome only shows the
   * permission prompt inside a user gesture. Resolves to whether access
   * was granted.
   */
  const enable = useCallback((): Promise<boolean> => {
    return chrome.permissions
      .request({ origins: gmailMatchPatterns() })
      .then((granted) => {
        setEnabled(granted);
        return granted;
      });
  }, []);

  /**
   * Revoking the permission only stops FUTURE injections: a copy already
   * running in an open Gmail tab would keep drawing banners and accepting
   * inserts. So first, while the permission still lets us find those
   * tabs, tell each copy to tear itself down.
   */
  const disable = useCallback(async (): Promise<void> => {
    const origins = gmailMatchPatterns();
    const tabs = await chrome.tabs.query({ url: origins }).catch(() => []);
    await Promise.all(
      tabs
        .filter((tab) => tab.id !== undefined)
        .map((tab) =>
          chrome.tabs
            .sendMessage(tab.id ?? chrome.tabs.TAB_ID_NONE, {
              type: "GMAIL_TEARDOWN",
            })
            .catch(() => undefined),
        ),
    );
    await chrome.permissions.remove({ origins });
    setEnabled(false);
  }, []);

  return { enabled, enable, disable };
}
