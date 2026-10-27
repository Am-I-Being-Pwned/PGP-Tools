import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Segmented } from "@amibeingpwned/ui/segmented";

import type { IdentityHolder } from "../../lib/identity/binding";
import type { ReviewDecision } from "../../lib/import/review";
import type { IncomingKey } from "../../lib/import/types";
import { t, tn } from "../../lib/i18n";
import { emailsOf } from "../../lib/identity/binding";
import { defaultDecision, needsDecision } from "../../lib/import/review";
import { parseUserId } from "../../lib/utils/key-naming";
import { KeyAvatar } from "../shared/KeyAvatar";
import { MarkedText } from "../shared/MarkedText";

/** The 16-hex key id, the form the rest of the panel shows. */
function shortId(keyId: string): string {
  return keyId.slice(-16).toUpperCase();
}

function statusLabel(key: IncomingKey): string {
  if (key.status === "duplicate") return t("import_review_status_duplicate");
  if (key.status === "rejected") return t("import_review_status_rejected");
  if (key.info?.revoked) return t("import_review_status_revoked");
  return key.status === "update"
    ? t("import_review_status_update")
    : t("import_review_status_new");
}

/** Who already holds the identity, as one readable line. */
function holderLine(holder: IdentityHolder): { name: string; keyid: string } {
  return {
    name: parseUserId(holder.userIds[0]).name,
    keyid: shortId(holder.keyId),
  };
}

function ConflictNote({ keyData }: { keyData: IncomingKey }) {
  const conflict = keyData.conflict;
  if (!conflict) return null;
  const holder = holderLine(conflict.holders[0]);
  // The address the key shares with the holder, not just its first one.
  const theirs = new Set(
    conflict.holders.flatMap((h) => h.userIds.flatMap(emailsOf)),
  );
  const email =
    keyData.userIds.flatMap(emailsOf).find((e) => theirs.has(e)) ?? "";
  const revoked = conflict.holders.every((h) => h.revoked);
  return (
    <p className="text-bad flex gap-1.5 text-xs">
      <TriangleAlertIcon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>
        {conflict.kind === "name"
          ? t("import_review_conflict_name", holder)
          : revoked
            ? t("import_review_conflict_address_revoked", { email, ...holder })
            : t("import_review_conflict_address", { email, ...holder })}
      </span>
    </p>
  );
}

/** Whether Replace means anything: a NEW key whose address a stored
 *  contact holds (not the user's own key, not another key in this
 *  import -- there is nothing to replace those with). */
function canReplace(key: IncomingKey): boolean {
  return (
    key.status === "new" &&
    key.conflict?.kind === "address" &&
    key.conflict.holders.some((h) => !h.own && !h.incoming)
  );
}

/**
 * Every key an import found, before anything is saved: who each claims
 * to be, its key id, and what saving it would do. A key claiming an
 * identity someone else holds starts on Skip and says why; the user
 * picks Keep both or (for an address) Replace. "Import all" is the
 * deliberate, labelled way to take everything as it stands.
 */
export function ImportReview({
  keys,
  onImport,
  busy,
  error,
  allowImportAll,
}: {
  keys: IncomingKey[];
  onImport: (decisions: Map<string, ReviewDecision>) => void;
  busy: boolean;
  error: string | null;
  /** Offer the one-click "take everything" (bundles, backups). */
  allowImportAll: boolean;
}) {
  const [decisions, setDecisions] = useState(
    () =>
      new Map(
        keys.filter(needsDecision).map((k) => [k.keyId, defaultDecision(k)]),
      ),
  );
  const decide = (keyId: string, d: ReviewDecision) =>
    setDecisions((prev) => new Map(prev).set(keyId, d));

  const chosen = [...decisions.values()].filter((d) => d !== "skip").length;
  const conflicts = keys.filter((k) => k.conflict && needsDecision(k)).length;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
        <p className="text-muted-foreground text-xs">
          {tn("import_review_intro", keys.length)}
        </p>
        <BlockStack>
          {keys.map((key, index) => {
            const { name, email } = parseUserId(key.userIds[0]);
            const decision = decisions.get(key.keyId);
            return (
              <Block
                // Two copies of one key can sit in one file.
                key={`${key.keyId}:${index}`}
                className="space-y-2 px-3.5 py-3"
                data-review-key={key.keyId}
              >
                <div className="flex items-center gap-3">
                  <KeyAvatar fingerprint={key.keyId} size={32} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">
                      <MarkedText text={name} />
                    </p>
                    {email && (
                      <p className="text-muted-foreground truncate text-xs">
                        <MarkedText text={email} />
                      </p>
                    )}
                    <p className="text-muted-foreground font-mono text-[11px]">
                      {shortId(key.keyId)}
                    </p>
                  </div>
                  <span className="bg-secondary text-muted-foreground shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium">
                    {statusLabel(key)}
                  </span>
                </div>
                <ConflictNote keyData={key} />
                {key.status === "new" && key.replaces && (
                  // A re-fetch for the same lookup that came back with a
                  // different key: saving it supersedes the old one.
                  <p className="text-warn text-xs">
                    {t("import_status_replaces", { name: key.replaces })}
                  </p>
                )}
                {decision !== undefined && (
                  <Segmented
                    size="sm"
                    fill
                    ariaLabel={t("import_review_choice_aria", { name })}
                    value={decision}
                    onValueChange={(d) => decide(key.keyId, d)}
                    options={[
                      { value: "skip", label: t("import_review_choice_skip") },
                      {
                        value: "import",
                        // Saving a same-lookup re-fetch supersedes the old
                        // record (see `upsertContacts`), so it never
                        // offers to keep both.
                        label: key.replaces
                          ? t("import_review_choice_replace")
                          : key.conflict && key.status === "new"
                            ? t("import_review_choice_keep_both")
                            : t("import_review_choice_import"),
                      },
                      ...(canReplace(key) && !key.replaces
                        ? [
                            {
                              value: "replace" as const,
                              label: t("import_review_choice_replace"),
                            },
                          ]
                        : []),
                    ]}
                  />
                )}
              </Block>
            );
          })}
        </BlockStack>
      </div>
      <div className="space-y-2 border-t border-white/[0.06] p-3">
        {error && <p className="text-bad text-xs">{error}</p>}
        <Button
          className="w-full"
          disabled={busy || chosen === 0}
          onClick={() => onImport(decisions)}
        >
          {busy
            ? t("import_importing")
            : chosen === 0
              ? t("import_review_import_none")
              : tn("import_review_import_n", chosen)}
        </Button>
        {allowImportAll && decisions.size > 1 && (
          <>
            <Button
              variant="outline"
              className="w-full"
              disabled={busy}
              onClick={() =>
                onImport(
                  new Map([...decisions.keys()].map((id) => [id, "import"])),
                )
              }
            >
              {conflicts > 0
                ? t("import_review_import_all_risky")
                : t("import_review_import_all")}
            </Button>
            {conflicts > 0 && (
              <p className="text-muted-foreground text-[11px]">
                {tn("import_review_import_all_note", conflicts)}
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
