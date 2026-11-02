import type { ReactNode } from "react";
import { useState } from "react";
import {
  CheckCircleIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  ListChecksIcon,
  LockIcon,
  PencilIcon,
  ShieldQuestionIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@amibeingpwned/ui/dropdown-menu";

import type { IdentityConflict } from "../../lib/identity/binding";
import type { PublicContactKey } from "../../lib/storage/contacts";
import { t, tn } from "../../lib/i18n";
import { formatDate, formatDateShort } from "../../lib/i18n/format";
import { clashPillLabel, clashSentence } from "../../lib/identity/clash-copy";
import {
  activeRecipients,
  contactRecipients,
  contactSource,
} from "../../lib/storage/contact-recipients";
import { isSshRecord } from "../../lib/storage/key-kind";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import { displayUserId, parseUserId } from "../../lib/utils/key-naming";
import { KeyAvatar } from "../shared/KeyAvatar";
import { MarkedText } from "../shared/MarkedText";
import {
  CardMenu,
  CardRow,
  DetailsChevron,
  LongIdColumn,
  Pill,
} from "./CardRow";
import { HEX_FINGERPRINT, longIdLines } from "./fingerprint-lines";

interface ContactCardProps {
  contact: PublicContactKey;
  /** Another contact claims this one's address or name. */
  clash?: IdentityConflict;
  onRemove?: () => void;
  onEncryptTo?: () => void;
  onCopyPublicKey?: () => void;
  onDownloadPublicKey?: () => void;
  /** Open the rename page for this contact (local display name only). */
  onRename?: () => void;
  /** Ask the keyserver whether the owner has revoked this key. */
  onCheckRevocation?: () => void;
  /** When set, shows a bottom-right arrow opening the key-details page. */
  onShowDetails?: () => void;
  advancedMode?: boolean;
  readOnly?: boolean;
  verifiedLabel?: string;
  /** Colour of the verified badge/border. "warning" (orange) is used when a
   *  message is signed but the signature could not be verified. */
  verifiedTone?: "success" | "warning";
  /** Optional muted explanation shown under the key line. */
  note?: string;
  /** A control under the note (the unknown signer's keyserver lookup). */
  noteAction?: ReactNode;
  /** A control after the verified label (the signer's key details). */
  labelAction?: ReactNode;
  /** Bulk-selection: when true, a tap toggles selection instead of navigating
   *  and the card's own controls are dimmed/click-through. */
  selectionMode?: boolean;
  selected?: boolean;
  /** `extend` is true when Shift was held: select everything between the
   *  last-touched card and this one, rather than toggling just this one. */
  onToggleSelect?: (extend: boolean) => void;
  /** Enter selection mode with this contact selected (long-press / menu). */
  onStartSelect?: () => void;
  /** Just arrived from an import: scroll to it and pulse it once. */
  justImported?: boolean;
}

export function ContactCard({
  contact,
  clash,
  onRemove,
  onEncryptTo,
  onCopyPublicKey,
  onDownloadPublicKey,
  onRename,
  onCheckRevocation,
  onShowDetails,
  advancedMode,
  readOnly,
  verifiedLabel,
  verifiedTone = "success",
  note,
  noteAction,
  labelAction,
  selectionMode = false,
  selected = false,
  onToggleSelect,
  onStartSelect,
  justImported,
}: ContactCardProps) {
  const isWarning = verifiedTone === "warning";
  // A verified signer reads as a status band: the whole block tinted,
  // green for a good signature, amber for one that could not be checked.
  const toneBand = isWarning ? "bg-[#252012]" : "bg-[#15231b]";
  const toneText = isWarning ? "text-warn" : "text-good";
  const ToneIcon = isWarning ? TriangleAlertIcon : CheckCircleIcon;
  // Captured once at mount; cards are short-lived so drift is moot.
  const [now] = useState(() => Date.now());
  // Through the accessors, never `contact.kind` / `.recipients`: legacy
  // records lack them and are single-key PGP.
  const isSsh = isSshRecord(contact);
  const recipients = contactRecipients(contact);
  // Displayed: every key. Encrypted to: the active subset -- the pill
  // says "2 of 3 keys" when they differ.
  const activeKeys = activeRecipients(contact).length;
  const source = contactSource(contact);
  // The alias wins, via the one accessor the picker and search share.
  const userId = displayUserId(contact) ?? t("keys_unknown_name");
  const { name: rawName, email, comment } = parseUserId(userId);
  const name = comment ? `${rawName} (${comment})` : rawName;

  // The fingerprint's last 16 hex digits at the right of the row. An SSH
  // hash has no meaningful tail, so it shows in full on the key line.
  const longId =
    !isSsh && HEX_FINGERPRINT.test(contact.keyId)
      ? longIdLines(contact.keyId)
      : null;
  // The key line: always on a read-only (signer) card and in advanced
  // mode; a list row otherwise folds the algorithm into its detail line.
  const showKeyLine = !!readOnly || !!advancedMode || !longId;
  const algorithm = contact.algorithm ? formatAlgorithm(contact.algorithm) : "";
  const expired = !!contact.expiresAt && contact.expiresAt < now;
  const hasPills =
    !!contact.verified ||
    !!clash ||
    expired ||
    !!contact.revoked ||
    !!contact.securityWarning ||
    isSsh ||
    recipients.length > 1 ||
    activeKeys < recipients.length;
  // Algorithm, expiry and provenance, as one small muted line.
  const details: string[] = [];
  if (algorithm && !showKeyLine) details.push(algorithm);
  if (contact.expiresAt && !expired) {
    details.push(
      t("keys_contact_expires", { date: formatDate(contact.expiresAt) }),
    );
  }
  if (source) {
    // Provenance (also the upsert identity), NOT a trust claim: see
    // T-GITHUB-KEY-SUBSTITUTION and T-KEYSERVER-KEY-SUBSTITUTION.
    details.push(
      source.type === "github"
        ? t("keys_source_github", { user: source.user })
        : t("keys_source_keyserver", { user: source.user }),
    );
  }
  const warnIcon = <TriangleAlertIcon className="h-2.5 w-2.5" />;

  return (
    <CardRow
      selectionMode={selectionMode}
      selected={selected}
      onToggleSelect={onToggleSelect}
      onStartSelect={onStartSelect}
      onShowDetails={onShowDetails}
      justImported={justImported}
      // Read-only it stands alone (the signer card) with the card radius.
      className={cn(readOnly && "rounded-xl pr-3.5", verifiedLabel && toneBand)}
    >
      <div className="flex items-center gap-2.5">
        <KeyAvatar fingerprint={contact.keyId} size={32} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {/* The name alone on line 1: no pill can squeeze it out. */}
            <p className="min-w-0 truncate text-sm font-medium">
              <MarkedText text={name} />
            </p>
            {verifiedLabel && (
              <span
                className={`ml-auto flex shrink-0 items-center gap-1 text-xs ${toneText}`}
              >
                <ToneIcon className="h-3.5 w-3.5" />
                {verifiedLabel}
              </span>
            )}
            {labelAction && (
              <div className="-my-1.5 -mr-1.5">{labelAction}</div>
            )}
          </div>
          {email && (
            <p className="text-muted-foreground truncate text-xs">
              <MarkedText text={email} />
            </p>
          )}
          {showKeyLine && (
            <p className="text-muted-foreground font-mono text-[11px] break-all">
              {/* A base64 SSH hash's tail identifies nothing: in full. */}
              {isSsh ? contact.keyId : contact.keyId.slice(-16)}
              {algorithm ? ` - ${algorithm}` : ""}
            </p>
          )}
          {/* Pills first, warnings leading (an expired or weak key must
              never be what gets cut off), then the truncating details. */}
          {(hasPills || details.length > 0) && (
            <div className="mt-0.5 flex min-w-0 items-center gap-1">
              {expired && contact.expiresAt && (
                <Pill
                  tone="bad"
                  icon={warnIcon}
                  title={t("keys_contact_expired_title", {
                    date: formatDate(contact.expiresAt),
                  })}
                >
                  {t("keys_contact_expired", {
                    date: formatDateShort(contact.expiresAt),
                  })}
                </Pill>
              )}
              {contact.revoked && (
                // Kept so the revocation sticks; never encrypted to.
                <Pill
                  tone="bad"
                  icon={warnIcon}
                  title={t("keys_contact_revoked_title")}
                >
                  {t("keys_contact_revoked")}
                </Pill>
              )}
              {clash && (
                <Pill tone="warn" icon={warnIcon} title={clashSentence(clash)}>
                  {clashPillLabel(clash)}
                </Pill>
              )}
              {contact.verified && (
                <Pill
                  tone="good"
                  icon={<CheckIcon className="h-2.5 w-2.5" />}
                  title={t("keys_verified_chip_title")}
                >
                  {t("keys_verified_chip")}
                </Pill>
              )}
              {contact.securityWarning &&
                // A name clash already says "Lookalike name": one pill.
                !(contact.lookalike && clash?.kind === "name") && (
                  <Pill
                    tone="warn"
                    icon={warnIcon}
                    title={contact.securityWarning}
                  >
                    {contact.lookalike
                      ? t("keys_lookalike_name")
                      : t("keys_weak_sha1")}
                  </Pill>
                )}
              {isSsh && <Pill title={t("keys_ssh_chip_title")}>SSH</Pill>}
              {(recipients.length > 1 || activeKeys < recipients.length) && (
                // The key id shown is only the first key's: say there are
                // more, or a 3-stanza file is a surprise at decrypt time.
                <Pill
                  title={
                    activeKeys < recipients.length
                      ? t("keys_contact_keys_partial_title", {
                          active: activeKeys,
                          total: recipients.length,
                        })
                      : t("keys_contact_keys_all_title")
                  }
                >
                  {activeKeys < recipients.length
                    ? t("keys_contact_keys_partial", {
                        active: activeKeys,
                        total: recipients.length,
                      })
                    : tn("keys_contact_keys_count", recipients.length)}
                </Pill>
              )}
              {details.length > 0 && (
                <span className="text-muted-foreground min-w-0 truncate text-[11px]">
                  {details.join(" · ")}
                </span>
              )}
            </div>
          )}
          {note && (
            <p className="text-muted-foreground mt-0.5 text-xs whitespace-pre-line">
              {note}
            </p>
          )}
          {noteAction && <div className="mt-2">{noteAction}</div>}
          {/* 4-char blocks suit a hex fingerprint only; the key line
              already shows an SSH hash in full. */}
          {advancedMode && !isSsh && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {formatFingerprint(contact.keyId)}
            </p>
          )}
        </div>

        {longId && !showKeyLine && <LongIdColumn lines={longId} />}

        {!readOnly && (
          <CardMenu
            ariaLabel={t("keys_contact_options_aria")}
            selectionMode={selectionMode}
          >
            {onEncryptTo && (
              <DropdownMenuItem onClick={onEncryptTo}>
                <LockIcon />
                {t("keys_encrypt_to")}
              </DropdownMenuItem>
            )}
            {onCopyPublicKey && (
              <DropdownMenuItem onClick={onCopyPublicKey}>
                <CopyIcon />
                {t("keys_copy_public_key")}
              </DropdownMenuItem>
            )}
            {onDownloadPublicKey && (
              <DropdownMenuItem onClick={onDownloadPublicKey}>
                <DownloadIcon />
                {t("keys_download_public_key")}
              </DropdownMenuItem>
            )}
            {onCheckRevocation && (
              <DropdownMenuItem onClick={onCheckRevocation}>
                <ShieldQuestionIcon />
                {t("keys_check_revocation")}
              </DropdownMenuItem>
            )}
            {onRename && (
              <DropdownMenuItem onClick={onRename}>
                <PencilIcon />
                {t("keys_rename")}
              </DropdownMenuItem>
            )}
            {onStartSelect && (
              <DropdownMenuItem onClick={onStartSelect}>
                <ListChecksIcon />
                {t("keys_select")}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onRemove}
            >
              <Trash2Icon className="text-destructive" />
              {t("keys_remove_contact")}
            </DropdownMenuItem>
          </CardMenu>
        )}

        {onShowDetails && (
          <DetailsChevron
            onClick={onShowDetails}
            selectionMode={selectionMode}
          />
        )}
      </div>
    </CardRow>
  );
}
