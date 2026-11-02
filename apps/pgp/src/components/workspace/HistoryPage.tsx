import { Fragment, useEffect, useRef, useState } from "react";
import {
  BadgeCheckIcon,
  CheckIcon,
  ChevronRightIcon,
  ClipboardIcon,
  LockIcon,
  LockOpenIcon,
  PenLineIcon,
  Trash2Icon,
} from "lucide-react";

import { Block, BlockStack, Button } from "@amibeingpwned/ui";

import { ConfirmPage } from "~/components/shared/ConfirmPage";
import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { SubPage } from "~/components/shared/SubPage";
import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import {
  buildSnippet,
  entryMatchesQuery,
  splitHighlight,
} from "~/lib/history-search";
import { t, tn, type MessageKey } from "~/lib/i18n";
import { formatDateTime, formatRelative } from "~/lib/i18n/format";
import {
  clearHistory,
  hasUnlimitedStorage,
  historyByteSize,
  loadHistory,
  resolveBudget,
  type HistoryEntry,
  type HistoryOp,
} from "~/lib/storage/history";
import { formatFileSize } from "~/lib/utils/formatting";

const OP_ICON: Record<HistoryOp, typeof LockIcon> = {
  encrypt: LockIcon,
  decrypt: LockOpenIcon,
  sign: PenLineIcon,
  verify: BadgeCheckIcon,
};

const OP_NAME: Record<HistoryOp, MessageKey> = {
  encrypt: "common_encrypt",
  decrypt: "common_decrypt",
  sign: "common_sign",
  verify: "common_verify",
};

function opLabel(entry: HistoryEntry): string {
  const op = t(OP_NAME[entry.op]);
  return entry.signed && entry.op === "encrypt"
    ? t("actions_history_op_signed", { op })
    : op;
}

const FIELD_CLASS =
  "surface-field placeholder:text-muted-foreground focus-visible:ring-ring h-9 w-full rounded-lg px-3 text-sm focus-visible:ring-2 focus:outline-none";

const MAX_AVATARS = 4;

function RecipientAvatars({
  recipients,
}: {
  recipients: HistoryEntry["recipients"];
}) {
  if (recipients.length === 0) return null;
  return (
    <span className="flex shrink-0 -space-x-1">
      {recipients.slice(0, MAX_AVATARS).map((r, i) => (
        <KeyAvatar
          // Index keys: the same key can appear twice; the list never reorders.
          key={i}
          fingerprint={r.fingerprint}
          size={16}
          className="ring-card ring-2"
        />
      ))}
    </span>
  );
}

function entryTitle(entry: HistoryEntry): string {
  if (entry.op === "encrypt" && entry.recipients.length > 0) {
    return t("actions_history_to", {
      names: entry.recipients
        .map((r) => r.name || r.fingerprint.slice(-8))
        .join(", "),
    });
  }
  if (entry.files && entry.files.length > 0) {
    return entry.files.length === 1
      ? entry.files[0].name
      : tn("actions_history_files", entry.files.length);
  }
  return t(OP_NAME[entry.op]);
}

const MARK_CLASS = "bg-primary/25 text-foreground rounded-sm px-0.5";

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

/** Scrolls itself into view on mount; the caller keys it on the query. */
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
      {/* Only stretched when there is content, so a metadata-only stack keeps
          its rounded bottom corners. */}
      <BlockStack
        className={entry.content !== undefined ? "min-h-0 flex-1" : undefined}
      >
        <Block className="text-muted-foreground shrink-0 space-y-1.5 p-3 text-xs">
          <p className="flex items-center gap-1.5 capitalize">
            <Icon className="h-3.5 w-3.5" />
            {opLabel(entry)}
            <span className="normal-case">
              {" · "}
              {t("actions_history_when", {
                date: formatDateTime(entry.ts),
                relative: formatRelative(entry.ts),
              })}
            </span>
          </p>
          {entry.recipients.length > 0 && (
            <p className="flex items-start gap-2 break-words">
              <RecipientAvatars recipients={entry.recipients} />
              <span className="min-w-0">
                {t("actions_history_to", {
                  names: entry.recipients
                    .map((r) =>
                      r.name
                        ? t("actions_history_recipient_with_id", {
                            name: r.name,
                            id: r.fingerprint.slice(-8).toUpperCase(),
                          })
                        : r.fingerprint.slice(-8).toUpperCase(),
                    )
                    .join(", "),
                })}
              </span>
            </p>
          )}
          {entry.files && entry.files.length > 0 && (
            <ul>
              {entry.files.map((f, i) => (
                <li key={i} className="truncate">
                  {t("actions_history_file_with_size", {
                    name: f.name,
                    size: formatFileSize(f.size),
                  })}
                </li>
              ))}
            </ul>
          )}
        </Block>

        {entry.content !== undefined ? (
          <pre className="bg-card min-h-0 flex-1 overflow-auto rounded-[3px] p-3 text-xs whitespace-pre-wrap">
            {search ? (
              <HighlightedContent text={entry.content} query={search} />
            ) : (
              entry.content
            )}
            {entry.truncated ? `\n${t("actions_history_truncated")}` : ""}
          </pre>
        ) : (
          <Block className="text-muted-foreground p-3 text-xs">
            {t("actions_history_metadata_only")}
          </Block>
        )}
      </BlockStack>

      {entry.content !== undefined && (
        <Button variant="outline" size="sm" onClick={() => void handleCopy()}>
          <span className="flex items-center gap-2">
            {copied ? (
              <CheckIcon className="text-good h-4 w-4" />
            ) : (
              <ClipboardIcon className="h-4 w-4" />
            )}
            {copied ? t("common_copied") : t("common_copy")}
          </span>
        </Button>
      )}
    </SubPage>
  );
}

/**
 * Decrypted entries live ONLY in this component's state, inside the
 * masterUnlocked-gated tree in App.tsx: a master lock unmounts it and the
 * plaintext leaves with it. Nothing module-level holds decrypted history.
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
  const searchRef = useRef<HTMLInputElement>(null);

  // A frame later, so it beats the focus trap's return-focus. Chains Escape:
  // preview, then query, then history.
  const closeDetail = () => {
    setDetailEntry(null);
    setTimeout(() => searchRef.current?.focus(), 0);
  };

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
        title={t("actions_history")}
        onClose={onClose}
        bodyClassName="flex h-full flex-col p-3"
        headerActions={
          entries.length > 0 ? (
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              title={t("actions_history_clear")}
              aria-label={t("actions_history_clear")}
              className="text-muted-foreground hover:text-bad rounded p-1 transition-colors"
            >
              <Trash2Icon className="h-4 w-4" />
            </button>
          ) : undefined
        }
      >
        {entries.length > 0 && (
          <input
            type="text"
            placeholder={t("actions_history_search_placeholder")}
            aria-label={t("actions_history_search_label")}
            autoFocus
            ref={searchRef}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              // Stop it so the slide-over doesn't also close; a second Escape does.
              if (e.key === "Escape" && search !== "") {
                e.preventDefault();
                e.stopPropagation();
                setSearch("");
              }
            }}
            className={`${FIELD_CLASS} mb-3 shrink-0`}
          />
        )}

        {loaded && entries.length === 0 && (
          <div className="bg-card rounded-xl p-4 text-center">
            <p className="text-muted-foreground text-sm">
              {enabled
                ? t("actions_history_empty")
                : t("actions_history_off_reason")}
            </p>
          </div>
        )}

        {search && entries.length > 0 && filtered.length === 0 && (
          <p className="text-muted-foreground mt-2 text-center text-xs">
            {t("actions_history_no_matches", { query: search })}
          </p>
        )}

        <div className="min-h-0 flex-1 overflow-y-auto">
          <BlockStack>
            {filtered.map((entry) => {
              const Icon = OP_ICON[entry.op];
              const snippet =
                search && entry.content !== undefined
                  ? buildSnippet(entry.content, search)
                  : undefined;
              const metadataOnly =
                entry.content === undefined &&
                (!entry.files || entry.files.length === 0);
              return (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => setDetailEntry(entry)}
                  aria-label={t("actions_history_open_entry", {
                    title: entryTitle(entry),
                  })}
                  className="bg-card hover:bg-accent focus-visible:ring-ring/60 flex w-full items-start gap-3 rounded-[3px] px-3 py-2.5 text-left transition-colors outline-none focus-visible:ring-2 focus-visible:ring-inset"
                >
                  <span className="bg-secondary text-muted-foreground flex size-7 shrink-0 items-center justify-center rounded-[7px] shadow-[inset_0_1px_0_rgb(255_255_255/0.07)]">
                    <Icon className="size-3.5" />
                  </span>
                  <span className="block min-w-0 flex-1">
                    <span className="flex w-full items-center gap-2">
                      <span className="min-w-0 flex-1 truncate text-sm font-medium">
                        {metadataOnly ? (
                          <span className="text-muted-foreground font-normal italic">
                            {t("actions_history_no_content")}
                          </span>
                        ) : (
                          <Highlighted
                            text={entryTitle(entry)}
                            query={search}
                          />
                        )}
                      </span>
                      <RecipientAvatars recipients={entry.recipients} />
                      <span className="text-muted-foreground shrink-0 text-xs whitespace-nowrap">
                        {formatRelative(entry.ts)}
                      </span>
                      <ChevronRightIcon className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
                    </span>
                    <span className="text-muted-foreground block text-xs whitespace-nowrap capitalize">
                      {opLabel(entry)}
                    </span>
                    {!search && entry.content !== undefined && (
                      <span className="text-muted-foreground mt-1 line-clamp-2 block text-xs">
                        {entry.content
                          .replace(/\s+/g, " ")
                          .trim()
                          .slice(0, 240)}
                      </span>
                    )}
                    {snippet && (
                      <span className="text-muted-foreground mt-1 line-clamp-2 block text-xs">
                        {snippet.truncatedStart && "…"}
                        {snippet.before}
                        <mark className={MARK_CLASS}>{snippet.match}</mark>
                        {snippet.after}
                        {snippet.truncatedEnd && "…"}
                        {snippet.moreMatches > 0 && (
                          <span className="text-muted-foreground/70">
                            {" "}
                            {tn(
                              "actions_history_more_matches",
                              snippet.moreMatches,
                            )}
                          </span>
                        )}
                      </span>
                    )}
                  </span>
                </button>
              );
            })}
          </BlockStack>
        </div>

        {usage && entries.length > 0 && (
          <p className="text-muted-foreground mt-2 shrink-0 pt-1 text-center text-[10px]">
            {t("actions_history_usage", {
              used: formatFileSize(usage.used),
              budget: formatFileSize(usage.budget),
            })}
          </p>
        )}
      </SubPage>

      {detailEntry && (
        <HistoryEntryPage
          entry={detailEntry}
          search={search}
          onClose={closeDetail}
        />
      )}

      {confirmClear && (
        <ConfirmPage
          title={t("actions_history_clear")}
          confirmLabel={t("actions_history_clear")}
          onConfirm={async () => {
            await clearHistory();
            setEntries([]);
            setUsage((u) => (u ? { ...u, used: 0 } : u));
          }}
          onCancel={() => setConfirmClear(false)}
        >
          <p className="font-medium">
            {tn("actions_history_delete_all", entries.length)}
          </p>
          <p className="mt-2">{t("actions_history_delete_warning")}</p>
        </ConfirmPage>
      )}
    </>
  );
}
