import {
  MailIcon,
  PlusIcon,
  SearchIcon,
  TriangleAlertIcon,
  XIcon,
} from "lucide-react";

import type { GmailComposeTarget } from "../../lib/gmail/protocol";
import { t, tn } from "../../lib/i18n";

/**
 * "You are writing a Gmail draft" -- the one line of context that makes
 * the panel's encrypt view read as Gmail's compose window, not a
 * separate tool. Says who the draft is addressed to, and loudly which of
 * them PGP Tools has no key for: encrypting to fewer people than the To
 * line names is the mistake this feature makes easiest, so it is the one
 * thing this strip refuses to be quiet about -- and each address carries
 * its own way out: "Search for key" looks it up. The list is live (see
 * `useGmailCompose`): a key that arrives drops its address from it.
 */
export function GmailComposeStrip({
  target,
  missing,
  onDismiss,
  onSearchKey,
  onAddKey,
}: {
  target: GmailComposeTarget;
  missing: string[];
  onDismiss: () => void;
  /** Look this address up (keys.openpgp.org) on the import page. Absent
   *  when online lookups are off in Settings. */
  onSearchKey?: (address: string) => void;
  /** The import page without a lookup: the fallback when searching is
   *  off. */
  onAddKey?: () => void;
}) {
  const to = target.recipients;
  return (
    <div
      className="border-border bg-muted/40 animate-in fade-in slide-in-from-top-1 rounded-md border text-xs duration-150 motion-reduce:animate-none"
      role="status"
    >
      <div className="flex items-start gap-2.5 p-2.5">
        <span className="bg-primary/15 text-primary mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full">
          <MailIcon className="h-3.5 w-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-foreground text-sm font-medium">
            {t("gmail_strip_title")}
          </p>
          <p className="text-muted-foreground truncate" title={to.join(", ")}>
            {to.length === 0
              ? t("gmail_strip_no_recipients")
              : t("gmail_strip_to", { addresses: to.join(", ") })}
          </p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label={t("gmail_strip_dismiss")}
          title={t("gmail_strip_dismiss")}
          className="text-muted-foreground hover:text-foreground hover:bg-muted -m-1 rounded p-1 transition-colors"
        >
          <XIcon className="h-3.5 w-3.5" />
        </button>
      </div>
      {missing.length > 0 && (
        <div className="border-t border-amber-500/30 bg-amber-500/10 px-2.5 py-2 text-amber-700 dark:text-amber-400">
          <p className="flex items-center gap-2">
            <TriangleAlertIcon className="h-3.5 w-3.5 shrink-0" />
            {tn("gmail_strip_missing", missing.length)}
          </p>
          <ul className="mt-1.5 space-y-1 pl-5.5">
            {missing.map((address) => (
              <li key={address} className="flex items-center gap-2">
                <span
                  className="text-foreground/90 min-w-0 flex-1 truncate"
                  title={address}
                >
                  {address}
                </span>
                {(onSearchKey ?? onAddKey) && (
                  <button
                    type="button"
                    onClick={() =>
                      onSearchKey ? onSearchKey(address) : onAddKey?.()
                    }
                    className="inline-flex shrink-0 items-center gap-1 rounded-full border border-amber-500/40 px-2 py-0.5 font-medium transition-colors hover:bg-amber-500/15"
                  >
                    {onSearchKey ? (
                      <SearchIcon className="h-3 w-3" />
                    ) : (
                      <PlusIcon className="h-3 w-3" />
                    )}
                    {onSearchKey
                      ? t("gmail_strip_search_key")
                      : t("gmail_strip_add_key")}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
