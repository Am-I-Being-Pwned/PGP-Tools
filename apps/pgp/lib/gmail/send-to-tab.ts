import type {
  GmailAddRecipientsRequest,
  GmailAttachRequest,
  GmailFetchAttachmentRequest,
  GmailFillRequest,
  GmailInsertRequest,
} from "./protocol";
import { gmailMatchPatterns } from "./protocol";

/** Everything the panel ever says to a Gmail tab's content script. */
export type GmailTabRequest =
  | GmailInsertRequest
  | GmailAddRecipientsRequest
  | GmailFillRequest
  | GmailAttachRequest
  | GmailFetchAttachmentRequest;

/**
 * THE ONE way the panel talks to a Gmail tab: insert, add-recipients,
 * fill, attach and fetch-attachment all go through it, which is why the
 * audit pins a single panel `tabs.sendMessage` site for them (the other
 * is Settings' teardown). Refuses when the add-on has been turned off.
 * Null when nothing answered (the tab closed, or its script has not
 * started yet) -- distinct from an answer that says no.
 *
 * `documentId` pins the message to the very document the click came
 * from, when there is one: a tab that has since navigated or reloaded
 * answers nothing.
 */
export async function sendToGmailTab<Res extends { ok: boolean }>(
  tabId: number,
  request: GmailTabRequest,
  documentId?: string,
): Promise<Res | null> {
  const granted = await chrome.permissions
    .contains({ origins: gmailMatchPatterns() })
    .catch(() => false);
  if (!granted) return null;
  try {
    const res: Res | undefined = await chrome.tabs.sendMessage<
      GmailTabRequest,
      Res | undefined
    >(tabId, request, documentId ? { documentId } : { frameId: 0 });
    return res ?? null;
  } catch {
    return null;
  }
}
