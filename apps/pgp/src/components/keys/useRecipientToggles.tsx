import { useState } from "react";

import { presentError } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import {
  contactRecipients,
  isRecipientDisabled,
  withRecipientDisabled,
  type ContactRecipient,
} from "~/lib/storage/contacts";
import { toast } from "~/lib/toast";
import type { ComponentKeyRow } from "./key-facts";
import type { KeyDetailsTarget } from "./KeyDetailsPage";

/** A contact's per-key include/exclude toggles for the details page. */
export function useRecipientToggles(
  target: KeyDetailsTarget,
  /** The store write stays with the page: audit-invariants pins every
   *  contact-store writer by file. */
  persist: (keyId: string, disable: boolean) => Promise<void>,
) {
  const isOwn = target.kind === "own";
  // A contact's key list, held locally so a toggle shows immediately and
  // this page keeps rendering the list it just wrote. Seeded through the
  // accessor, so a legacy single-key record yields its one synthesised
  // entry exactly like every other call site.
  const [recipients, setRecipients] = useState<ContactRecipient[]>(() =>
    target.kind === "contact" ? contactRecipients(target.contact) : [],
  );
  const [savingKeyId, setSavingKeyId] = useState<string | null>(null);
  // More than one key means this contact is a PERSON with several
  // machines, not a certificate: every key gets a row (see
  // `sshGroupKeyFacts`) and every row gets an include/exclude control.
  // So does a single key the user turned off (a refresh can leave a
  // contact so): without its row control it could never be turned back
  // on.
  const multiRecipient =
    !isOwn && (recipients.length > 1 || recipients.some(isRecipientDisabled));
  const activeCount = recipients.filter((r) => !isRecipientDisabled(r)).length;

  /** Turn one of this contact's keys on or off, and persist it.
   *
   *  Persisted through `setContactRecipientDisabled` rather than a
   *  `saveContact` of `{ ...target.contact, ... }`, and that is the
   *  whole point: `target.contact` is a snapshot captured when this page
   *  mounted, so saving a spread of it would republish every other field
   *  as it was then -- reverting, say, the expiry backfill that ran in
   *  the meantime. The store re-reads the record inside its own lock and
   *  touches `recipients` alone.
   *
   *  `withRecipientDisabled` drops the flag entirely when re-enabling,
   *  so nothing ever stores `disabled: false`. Optimistic, with a
   *  rollback: the list on screen must never claim a key is excluded
   *  when the store still has it enabled. */
  const handleToggleRecipient = async (keyId: string, disable: boolean) => {
    if (target.kind !== "contact") return;
    // The last enabled key can never be turned off -- see the disabled
    // control below. Re-checked here because a control is not a
    // guarantee.
    if (disable && activeCount <= 1) return;
    const previous = recipients;
    const next = withRecipientDisabled(previous, keyId, disable);
    setRecipients(next);
    setSavingKeyId(keyId);
    try {
      await persist(keyId, disable);
    } catch (e) {
      setRecipients(previous);
      toast.error(presentError(e, t("keys_save_failed")).message);
    } finally {
      setSavingKeyId(null);
    }
  };

  /** The include/exclude control for one key row. Passed to
   *  `KeyPreviewBody` only from here -- the import preview doesn't pass
   *  it and renders the same rows without controls. */
  const renderRecipientAction = (row: ComponentKeyRow) => {
    const recipient = recipients.find((r) => r.keyId === row.fingerprint);
    if (!recipient) return null;
    const off = isRecipientDisabled(recipient);
    // Refusing to disable the last enabled key is the UI half of the
    // never-encrypt-to-nobody invariant (`activeRecipients` is the
    // other). Dimmed WITH A REASON rather than hidden: a control that
    // vanishes looks like it never existed, so the user is left guessing
    // why this row is different (see `lib/actions/types.ts`).
    const lastActive = !off && activeCount <= 1;
    const busy = savingKeyId === recipient.keyId;
    return (
      <span className="flex items-center gap-1.5">
        {off && (
          <span
            title={t("keys_recipient_off_title")}
            className="bg-warn/12 text-warn rounded px-1.5 py-px text-[10.5px] font-medium"
          >
            {t("keys_recipient_not_used")}
          </span>
        )}
        <button
          type="button"
          disabled={busy || lastActive}
          title={
            lastActive
              ? t("keys_recipient_last_active_title")
              : off
                ? t("keys_recipient_enable_title")
                : t("keys_recipient_disable_title")
          }
          onClick={() => void handleToggleRecipient(recipient.keyId, !off)}
          className="bg-secondary text-muted-foreground hover:text-foreground hover:bg-accent rounded px-1.5 py-px text-[10.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          {off ? t("keys_recipient_use") : t("keys_recipient_dont_use")}
        </button>
      </span>
    );
  };

  return { recipients, multiRecipient, renderRecipientAction };
}
