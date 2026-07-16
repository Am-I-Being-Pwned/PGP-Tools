import { Fragment, useEffect, useRef, useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  BadgeCheckIcon,
  CheckIcon,
  ChevronRightIcon,
  ClipboardIcon,
  HistoryIcon,
  LockIcon,
  LockOpenIcon,
  PenLineIcon,
  Trash2Icon,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { HistoryEntry, HistoryOp } from "../../lib/storage/history";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import {
  buildSnippet,
  entryMatchesQuery,
  splitHighlight,
} from "../../lib/history-search";
import {
  clearHistory,
  hasUnlimitedStorage,
  historyByteSize,
  loadHistory,
  resolveBudget,
} from "../../lib/storage/history";
import { formatFileSize } from "../../lib/utils/formatting";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { ConfirmPage } from "../shared/ConfirmPage";
import { SubPage } from "../shared/SubPage";

const OP_ICON: Record<HistoryOp, typeof LockIcon> = {
  encrypt: LockIcon,
  decrypt: LockOpenIcon,
  sign: PenLineIcon,
  verify: BadgeCheckIcon,
};

/** Small icon button that opens the history page. Self-contained so the
 *  WorkspaceView diff stays a single element. */
export function HistoryButton({ enabled }: { enabled: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="History"
        aria-label="History"
        className="text-muted-foreground hover:text-foreground ml-auto rounded p-1 transition-colors"
      >
        <HistoryIcon className="h-4 w-4" />
      </button>
      {open && <HistoryPage enabled={enabled} onClose={() => setOpen(false)} />}
    </>
  );
}

function entryTitle(entry: HistoryEntry): string {
  if (entry.op === "encrypt" && entry.recipients.length > 0) {
    return `To ${entry.recipients.map((r) => r.name || r.fingerprint.slice(-8)).join(", ")}`;
  }
  if (entry.files && entry.files.length > 0) {
    return entry.files.length === 1
      ? entry.files[0].name
      : `${entry.files.length} files`;
  }
  return entry.op.charAt(0).toUpperCase() + entry.op.slice(1);
}

/** Shared styling for highlighted match text; primary-tinted so it
 *  reads on both the light and pure-black dark themes. */
const MARK_CLASS = "bg-primary/25 text-foreground rounded-sm px-0.5";

/** Text with every case-insensitive occurrence of `query` wrapped in a
 *  styled <mark>. Falls back to plain text when the query is empty. */
function Highlighted({ text, query }: { text: string; query: string }) {
  return splitHighlight(text, query).map((seg, i) =>
    seg.match ? (
      <mark key={i} className={MARK_CLASS}>
        {seg.text}
      </mark>
    ) : (
      <Fragment key={i}>{seg.text}</Fragment>
    ),
  );
}

/** The first highlight inside expanded content: scrolls itself into
 *  view on mount so the evidence for the search hit is visible without
 *  manual scrolling through a long armored block. Keyed on the query by
 *  the caller so a query change re-scrolls. */
function FirstMark({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    ref.current?.scrollIntoView({ block: "nearest" });
  }, []);
  return (
    <mark ref={ref} className={MARK_CLASS}>
      {children}
    </mark>
  );
}

/** Expanded-content body with all matches highlighted; the first match
 *  auto-scrolls into view within the <pre>. */
function HighlightedContent({ text, query }: { text: string; query: string }) {
  let seenFirst = false;
  return splitHighlight(text, query).map((seg, i) => {
    if (!seg.match) return <Fragment key={i}>{seg.text}</Fragment>;
    if (!seenFirst) {
      seenFirst = true;
      return <FirstMark key={`${query}-${i}`}>{seg.text}</FirstMark>;
    }
    return (
      <mark key={i} className={MARK_CLASS}>
        {seg.text}
      </mark>
    );
  });
}

/** Full view of one history entry: metadata block, complete content
 *  (search-highlighted, first match scrolled into view), and Copy. */
function HistoryEntryPage({
  entry,
  search,
  onClose,
}: {
  entry: HistoryEntry;
  search: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const { copy } = useCopyToClipboard();
  const handleCopy = async () => {
    if (!entry.content) return;
    // No label: the button's own 2s check is the success feedback.
    if (!(await copy(entry.content))) return;
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  const Icon = OP_ICON[entry.op];

  return (
    <SubPage
      title={entryTitle(entry)}
      onClose={onClose}
      bodyClassName="flex h-full flex-col gap-3 p-3"
    >
      <div className="text-muted-foreground space-y-1 text-xs">
        <p className="flex items-center gap-1.5 capitalize">
          <Icon className="h-3.5 w-3.5" />
          {entry.op}
          {entry.signed && entry.op === "encrypt" ? " + sign" : ""}
          <span className="normal-case">
            {" · "}
            {new Date(entry.ts).toLocaleString()} (
            {formatDistanceToNow(entry.ts, { addSuffix: true })})
          </span>
        </p>
        {entry.recipients.length > 0 && (
          <p className="break-words">
            To{" "}
            {entry.recipients
              .map((r) =>
                r.name
                  ? `${r.name} (${r.fingerprint.slice(-8).toUpperCase()})`
                  : r.fingerprint.slice(-8).toUpperCase(),
              )
              .join(", ")}
          </p>
        )}
        {entry.files && entry.files.length > 0 && (
          <ul>
            {entry.files.map((f) => (
              <li key={f.name} className="truncate">
                {f.name} ({formatFileSize(f.size)})
              </li>
            ))}
          </ul>
        )}
      </div>

      {entry.content !== undefined ? (
        <>
          <pre className="bg-muted/30 min-h-0 flex-1 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">
            {search ? (
              <HighlightedContent text={entry.content} query={search} />
            ) : (
              entry.content
            )}
            {entry.truncated ? "\n[truncated]" : ""}
          </pre>
          <Button variant="outline" size="sm" onClick={() => void handleCopy()}>
            <span className="flex items-center gap-2">
              {copied ? (
                <CheckIcon className="h-4 w-4 text-green-400" />
              ) : (
                <ClipboardIcon className="h-4 w-4" />
              )}
              {copied ? "Copied" : "Copy"}
            </span>
          </Button>
        </>
      ) : (
        <p className="text-muted-foreground text-xs">
          Metadata only - content is not stored for this operation.
        </p>
      )}
    </SubPage>
  );
}

/**
 * Encrypted-history browser. Decrypted entries live ONLY in this
 * component's state: the page is mounted inside the masterUnlocked-gated
 * tree in App.tsx (under WorkspaceView), so a master lock unmounts it and
 * the plaintext leaves with the component -- nothing module-level holds
 * decrypted history (see lib/storage/history.ts).
 */
export function HistoryPage({
  enabled,
  onClose,
}: {
  enabled: boolean;
  onClose: () => void;
}) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [search, setSearch] = useState("");
  const [detailEntry, setDetailEntry] = useState<HistoryEntry | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [usage, setUsage] = useState<{ used: number; budget: number } | null>(
    null,
  );

  useEffect(() => {
    void (async () => {
      setEntries(await loadHistory());
      setUsage({
        used: await historyByteSize(),
        budget: resolveBudget(await hasUnlimitedStorage()),
      });
      setLoaded(true);
    })();
  }, []);

  const filtered = search
    ? entries.filter((e) => entryMatchesQuery(e, search))
    : entries;

  return (
    <>
      <SubPage
        title="History"
        onClose={onClose}
        bodyClassName="p-3"
        headerActions={
          entries.length > 0 ? (
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              title="Clear history"
              aria-label="Clear history"
              className="text-muted-foreground hover:text-destructive rounded p-1 transition-colors"
            >
              <Trash2Icon className="h-4 w-4" />
            </button>
          ) : undefined
        }
      >
        {entries.length > 0 && (
          <input
            type="text"
            placeholder="Search history..."
            aria-label="Search history"
            autoFocus
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              // Escape clears a non-empty query ONLY -- stop it here so
              // the surrounding slide-over (document-level listener)
              // doesn't also close; a second Escape on the now-empty
              // box falls through and closes the page.
              if (e.key === "Escape" && search !== "") {
                e.preventDefault();
                e.stopPropagation();
                setSearch("");
              }
            }}
            className={`${INPUT_CLASS} mb-2`}
          />
        )}

        {loaded && entries.length === 0 && (
          <div className="border-border bg-muted/30 rounded-lg border p-4 text-center">
            <p className="text-muted-foreground text-sm">
              {enabled
                ? "No history"
                : "History is off - enable it next to Sign"}
            </p>
          </div>
        )}

        {search && entries.length > 0 && filtered.length === 0 && (
          <p className="text-muted-foreground mt-2 text-center text-xs">
            No history matches "{search}"
          </p>
        )}

        <div className="space-y-2">
          {filtered.map((entry) => {
            const Icon = OP_ICON[entry.op];
            // Show WHY a row matched: a content hit renders a snippet
            // under the header. Recipient/file-name hits are already
            // visible, highlighted, in the title.
            const snippet =
              search && entry.content !== undefined
                ? buildSnippet(entry.content, search)
                : undefined;
            // decrypt/verify rows never store content (see history.ts);
            // mark them at a glance so users don't open expecting text.
            const metadataOnly =
              entry.content === undefined &&
              (!entry.files || entry.files.length === 0);
            return (
              <button
                key={entry.id}
                type="button"
                onClick={() => setDetailEntry(entry)}
                aria-label={`Open ${entryTitle(entry)}`}
                className="border-border hover:bg-muted/40 block w-full rounded-lg border p-2.5 text-left transition-colors"
              >
                <span className="flex w-full items-center gap-2">
                  <Icon className="text-muted-foreground h-4 w-4 shrink-0" />
                  <span className="min-w-0 flex-1 truncate text-sm">
                    {metadataOnly ? (
                      <span className="text-muted-foreground italic">
                        No content saved
                      </span>
                    ) : (
                      <Highlighted text={entryTitle(entry)} query={search} />
                    )}
                  </span>
                  <span className="text-muted-foreground shrink-0 text-xs whitespace-nowrap capitalize">
                    {entry.op}
                    {entry.signed && entry.op === "encrypt" ? " + sign" : ""}
                  </span>
                  <span className="text-muted-foreground shrink-0 text-xs whitespace-nowrap">
                    {formatDistanceToNow(entry.ts, { addSuffix: true })}
                  </span>
                  <ChevronRightIcon className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
                </span>
                {/* Content is the point of history: preview it by default
                    rather than hiding everything behind a click. The
                    search snippet replaces this while a query is active. */}
                {!search && entry.content !== undefined && (
                  <span className="text-muted-foreground mt-1 line-clamp-2 block pl-6 text-xs">
                    {entry.content.replace(/\s+/g, " ").trim().slice(0, 240)}
                  </span>
                )}
                {snippet && (
                  <span className="text-muted-foreground mt-1 line-clamp-2 block pl-6 text-xs">
                    {snippet.truncatedStart && "…"}
                    {snippet.before}
                    <mark className={MARK_CLASS}>{snippet.match}</mark>
                    {snippet.after}
                    {snippet.truncatedEnd && "…"}
                    {snippet.moreMatches > 0 && (
                      <span className="text-muted-foreground/70">
                        {" "}
                        +{snippet.moreMatches} more{" "}
                        {snippet.moreMatches === 1 ? "match" : "matches"}
                      </span>
                    )}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {usage && entries.length > 0 && (
          <p className="text-muted-foreground mt-3 text-center text-[10px]">
            {formatFileSize(usage.used)} of {formatFileSize(usage.budget)} used
          </p>
        )}
      </SubPage>

      {detailEntry && (
        <HistoryEntryPage
          entry={detailEntry}
          search={search}
          onClose={() => setDetailEntry(null)}
        />
      )}

      {confirmClear && (
        <ConfirmPage
          title="Clear history"
          confirmLabel="Clear history"
          onConfirm={async () => {
            await clearHistory();
            setEntries([]);
            setUsage((u) => (u ? { ...u, used: 0 } : u));
          }}
          onCancel={() => setConfirmClear(false)}
        >
          <p className="font-medium">
            Delete all {entries.length} history{" "}
            {entries.length === 1 ? "entry" : "entries"}
          </p>
          <p className="mt-2">
            This permanently deletes your encrypted operation history from this
            device. It can't be recovered.
          </p>
        </ConfirmPage>
      )}
    </>
  );
}
