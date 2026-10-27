import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Segmented } from "@amibeingpwned/ui/segmented";

import type {
  IdentityConflict,
  IdentityHolder,
} from "../../lib/identity/binding";
import type { ReviewDecision } from "../../lib/import/review";
import type { IncomingKey } from "../../lib/import/types";
import { t, tn } from "../../lib/i18n";
import {
  addressSkeletons,
  displayKeyId,
  emailsOf,
} from "../../lib/identity/binding";
import { defaultDecision, needsDecision } from "../../lib/import/review";
import { parseUserId } from "../../lib/utils/key-naming";
import { KeyAvatar } from "../shared/KeyAvatar";
import { MarkedText } from "../shared/MarkedText";

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
    // An SSH key with no comment has no name of its own; it is shown
    // the way the rest of the panel shows one.
    name:
      holder.userIds.length === 0 && holder.keyId.startsWith("SHA256:")
        ? t("import_ssh_headline")
        : parseUserId(holder.userIds[0]).name,
    keyid: displayKeyId(holder.keyId),
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
        {conflict.kind === "key" ? (
          keyConflictText(keyData)
        ) : conflict.kind === "name" ? (
          t("import_review_conflict_name", holder)
        ) : conflict.lookalike ? (
          // Marked, so the letter that makes it a different address is
          // pointed at rather than left to be spotted.
          <MarkedText text={lookalikeAddressText(keyData, conflict, holder)} />
        ) : revoked ? (
          t("import_review_conflict_address_revoked", {
            email,
            ...holder,
          })
        ) : (
          t("import_review_conflict_address", { email, ...holder })
        )}
      </span>
    </p>
  );
}

/** An address that only READS like the holder's: both are named, since
 *  neither alone shows the difference. */
function lookalikeAddressText(
  keyData: IncomingKey,
  conflict: IdentityConflict,
  holder: { name: string; keyid: string },
): string {
  const theirs = conflict.holders[0].userIds.flatMap(emailsOf);
  const ours = keyData.userIds.flatMap(emailsOf);
  const pair = ours
    .map((e) => {
      const looks = new Set(addressSkeletons(e));
      return {
        email: e,
        theirs: theirs.find((a) =>
          addressSkeletons(a).some((k) => looks.has(k)),
        ),
      };
    })
    .find((p) => p.theirs !== undefined);
  return t("import_review_conflict_address_lookalike", {
    email: pair?.email ?? ours.at(0) ?? "",
    theirs: pair?.theirs ?? theirs.at(0) ?? "",
    ...holder,
  });
}

/**
 * An SSH import carrying a key the user already holds, in the words of
 * what saving it would do: give that contact keys it did not have, or
 * put their key (or the user's own) beside keys that are not theirs.
 * Either way it is how a paste took a contact over, so it is said, and
 * the row starts on Skip.
 */
function keyConflictText(keyData: IncomingKey): string {
  const holders = keyData.conflict?.holders ?? [];
  const own = holders.find((h) => h.own);
  if (own) {
    return t("import_review_conflict_key_own", {
      keyid: displayKeyId(own.keyId),
    });
  }
  const holder = holderLine(holders[0]);
  // An update lands on the contact it shares its id with.
  return keyData.status === "update" &&
    holders.some((h) => h.keyId === keyData.keyId)
    ? t("import_review_conflict_key_update", holder)
    : t("import_review_conflict_key_contact", holder);
}

/** Whether Replace means anything: a NEW key whose address a stored
 *  contact holds (not the user's own key, not another key in this
 *  import -- there is nothing to replace those with). Never for an
 *  address that only looks the same: a new key for someone's address is
 *  how a rotation looks, a new key for a lookalike of it never is. */
function canReplace(key: IncomingKey): boolean {
  return (
    key.status === "new" &&
    key.conflict?.kind === "address" &&
    !key.conflict.lookalike &&
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
                      {displayKeyId(key.keyId)}
                    </p>
                  </div>
                  <span className="bg-secondary text-muted-foreground shrink-0 rounded px-1.5 py-px text-[10.5px] font-medium">
                    {statusLabel(key)}
                  </span>
                </div>
                {key.status === "update" && key.changes.length > 0 && (
                  // What the update changes -- for an SSH group, how many
                  // keys it adds to the person, which is the thing to
                  // check before saying yes.
                  <ul className="text-muted-foreground space-y-0.5 text-xs">
                    {key.changes.map((change) => (
                      <li key={change}>{change}</li>
                    ))}
                  </ul>
                )}
                <ConflictNote keyData={key} />
                {key.allKeysOff && (
                  <p className="text-bad flex gap-1.5 text-xs">
                    <TriangleAlertIcon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>{t("import_review_all_keys_off")}</span>
                  </p>
                )}
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
                          : key.conflict &&
                              key.conflict.kind !== "key" &&
                              key.status === "new"
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
