import { useEffect, useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  BadgeCheckIcon,
  CheckIcon,
  ClipboardIcon,
  HistoryIcon,
  LockIcon,
  LockOpenIcon,
  PenLineIcon,
  Trash2Icon,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { HistoryEntry, HistoryOp } from "../../lib/storage/history";
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

function matchesSearch(entry: HistoryEntry, q: string): boolean {
  return (
    entry.op.includes(q) ||
    entry.recipients.some(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.fingerprint.toLowerCase().includes(q),
    ) ||
    (entry.content?.toLowerCase().includes(q) ?? false) ||
    (entry.files?.some((f) => f.name.toLowerCase().includes(q)) ?? false)
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
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [usage, setUsage] = useState<{ used: number; budget: number } | null>(
    null,
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);

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
    ? entries.filter((e) => matchesSearch(e, search.toLowerCase()))
    : entries;

  const handleCopy = async (entry: HistoryEntry) => {
    if (!entry.content) return;
    try {
      await navigator.clipboard.writeText(entry.content);
      setCopiedId(entry.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // clipboard may reject if the panel isn't focused
    }
  };

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
        {entries.length > 5 && (
          <input
            type="text"
            placeholder="Search history..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
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
            const expanded = expandedId === entry.id;
            return (
              <div
                key={entry.id}
                className="border-border rounded-lg border p-2.5"
              >
                <button
                  type="button"
                  className="flex w-full items-center gap-2 text-left"
                  onClick={() => setExpandedId(expanded ? null : entry.id)}
                  aria-expanded={expanded}
                >
                  <Icon className="text-muted-foreground h-4 w-4 shrink-0" />
                  <span className="min-w-0 flex-1 truncate text-sm">
                    {entryTitle(entry)}
                  </span>
                  <span className="text-muted-foreground shrink-0 text-xs capitalize">
                    {entry.op}
                    {entry.signed && entry.op === "encrypt" ? " + sign" : ""}
                  </span>
                  <span className="text-muted-foreground shrink-0 text-xs">
                    {formatDistanceToNow(entry.ts, { addSuffix: true })}
                  </span>
                </button>
                {expanded && (
                  <div className="mt-2 space-y-2">
                    {entry.files && entry.files.length > 0 && (
                      <ul className="text-muted-foreground text-xs">
                        {entry.files.map((f) => (
                          <li key={f.name} className="truncate">
                            {f.name} ({formatFileSize(f.size)})
                          </li>
                        ))}
                      </ul>
                    )}
                    {entry.content !== undefined && (
                      <>
                        <pre className="bg-muted/30 max-h-48 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">
                          {entry.content}
                          {entry.truncated ? "\n[truncated]" : ""}
                        </pre>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => void handleCopy(entry)}
                        >
                          <span className="flex items-center gap-2">
                            {copiedId === entry.id ? (
                              <CheckIcon className="h-4 w-4 text-green-400" />
                            ) : (
                              <ClipboardIcon className="h-4 w-4" />
                            )}
                            {copiedId === entry.id ? "Copied" : "Copy"}
                          </span>
                        </Button>
                      </>
                    )}
                    {entry.content === undefined &&
                      (!entry.files || entry.files.length === 0) && (
                        <p className="text-muted-foreground text-xs">
                          Metadata only - content is not stored for this
                          operation.
                        </p>
                      )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {usage && entries.length > 0 && (
          <p className="text-muted-foreground mt-3 text-center text-[10px]">
            {formatFileSize(usage.used)} of {formatFileSize(usage.budget)} used
          </p>
        )}
      </SubPage>

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
            This permanently deletes your encrypted operation history from
            this device. It can't be recovered.
          </p>
        </ConfirmPage>
      )}
    </>
  );
}
