import type { MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { useState } from "react";
import {
  CheckCircleIcon,
  CheckIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  EllipsisVerticalIcon,
  ListChecksIcon,
  LockIcon,
  PencilIcon,
  ShieldQuestionIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@amibeingpwned/ui/tooltip";

import type { IdentityConflict } from "../../lib/identity/binding";
import type { PublicContactKey } from "../../lib/storage/contacts";
import { t, tn } from "../../lib/i18n";
import { formatDate, formatDateShort } from "../../lib/i18n/format";
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
import { HEX_FINGERPRINT, longIdLines } from "./fingerprint-lines";
import { useJustImported } from "./useJustImported";
import { useLongPress } from "./useLongPress";

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

/** Who else holds the identity, for the clash pill's tooltip. */
function clashArgs(clash: IdentityConflict) {
  const holder = clash.holders[0];
  return {
    name: parseUserId(holder.userIds[0] ?? "").name,
    keyid: holder.keyId.slice(-16).toUpperCase(),
  };
}

/** The design language's status pill; the tone classes are added per use. */
const PILL =
  "shrink-0 items-center rounded px-1.5 py-px text-[10.5px] font-medium whitespace-nowrap";

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
  const [importedRef, importedClass] = useJustImported(justImported);
  const isWarning = verifiedTone === "warning";
  // A verified signer reads as a status band: the whole block tinted,
  // green for a good signature, amber for one that could not be checked.
  const toneBand = isWarning ? "bg-[#252012]" : "bg-[#15231b]";
  const toneText = isWarning ? "text-warn" : "text-good";
  const ToneIcon = isWarning ? TriangleAlertIcon : CheckCircleIcon;
  // Captured once at mount; cards are short-lived so drift is moot.
  const [now] = useState(() => Date.now());
  // Read off the record rather than taken as a prop: which engine a
  // contact belongs to is a fact ABOUT the contact, so both call sites
  // (the keys list, the verified-signer card) stay untouched and can't
  // forget to pass it. Legacy contacts carry no `kind` and are PGP --
  // hence `isSshRecord`, never `contact.kind === ...`.
  const isSsh = isSshRecord(contact);
  // Both read through the accessors for the same reason `kind` is: an
  // absent `recipients`/`source` is the legacy (and single-key,
  // hand-supplied) shape, not a missing value -- so no prop is added and
  // neither call site has to know a contact can hold several keys.
  const recipients = contactRecipients(contact);
  // What is DISPLAYED is every key; what gets encrypted to is the active
  // subset. When the user has turned some off, saying "3 keys" would be
  // a lie about the file they are about to produce -- so the badge says
  // "2 of 3 keys" instead.
  const activeKeys = activeRecipients(contact).length;
  const source = contactSource(contact);
  // Through the shared accessor, never `userIds[0]`: a contact's name is
  // its local alias when it has one, and the fallback lives in exactly
  // one place so the card, the picker and the search box cannot disagree
  // about what this person is called.
  const userId = displayUserId(contact) ?? t("keys_unknown_name");
  const { name: rawName, email, comment } = parseUserId(userId);
  const name = comment ? `${rawName} (${comment})` : rawName;

  const longPress = useLongPress(
    () => onStartSelect?.(),
    !selectionMode && !!onStartSelect,
  );

  const handleClick = (e: ReactMouseEvent) => {
    if (longPress.consumeClick()) return;
    if (selectionMode) {
      onToggleSelect?.(e.shiftKey);
      return;
    }
    onShowDetails?.();
  };

  const clickable = selectionMode || !!onShowDetails;
  // While selecting, the card itself is the target: its own controls are dimmed
  // and click-through (`dimmed`), and drop their hover highlight -- `hover:` /
  // `group-hover:` fire from hovering the CARD, so pointer-events-none alone
  // wouldn't stop the highlight.
  const dimmed = "pointer-events-none opacity-40";

  // The long key id at the right of the row: the fingerprint's last 16
  // hex digits, as two stacked lines. An SSH hash has no meaningful tail,
  // so it shows on its own line in full instead (see below).
  const longId =
    !isSsh && HEX_FINGERPRINT.test(contact.keyId)
      ? longIdLines(contact.keyId)
      : null;
  // The long key line -- the 16-digit key id and the algorithm. Always on
  // a read-only card (the signer card: "the signer's key ID is surfaced
  // so the user can locate the key") and in advanced mode; a list row
  // otherwise folds the algorithm into its small detail line.
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
    recipients.length > 1;
  // Algorithm, expiry and provenance, as one small muted line.
  const details: string[] = [];
  if (algorithm && !showKeyLine) details.push(algorithm);
  if (contact.expiresAt && !expired) {
    details.push(
      t("keys_contact_expires", { date: formatDate(contact.expiresAt) }),
    );
  }
  if (source) {
    /* Where this contact came from, which is also its upsert identity:
       looking the same user (or address) up again updates THIS record
       rather than adding a second one.

       A PROVENANCE LABEL, NOT A TRUST CLAIM. It says who told us this
       key is theirs; it does not say anyone checked. See
       T-GITHUB-KEY-SUBSTITUTION and T-KEYSERVER-KEY-SUBSTITUTION. */
    details.push(
      source.type === "github"
        ? t("keys_source_github", { user: source.user })
        : t("keys_source_keyserver", { user: source.user }),
    );
  }

  return (
    <div
      ref={importedRef}
      onClick={handleClick}
      {...longPress.handlers}
      className={cn(
        // One compact row. In the keys list it is a block of a stack
        // (KeysView rounds the stack's outer corners); read-only, it stands
        // alone (the verified-signer card) and carries the card radius
        // itself.
        // select-none: the whole card is a click target, and a shift-click
        // to extend a selection would otherwise drag a text range across it
        // instead. The fingerprint is still copyable from the card's menu.
        "group relative py-2.5 pr-2 pl-3.5 select-none",
        readOnly ? "rounded-xl pr-3.5" : "rounded-[3px]",
        verifiedLabel ? toneBand : "bg-card",
        importedClass,
        // The import pulse is an outward ring: lift the card over its
        // neighbours so the 2px gap doesn't hide half of it.
        importedClass && "z-10",
        // An inset ring (box-shadow, no layout impact) so selecting neither
        // shifts the row nor spills into the gap between blocks.
        selected && "ring-primary/70 ring-2 ring-inset",
        clickable && "hover:bg-accent/50 cursor-pointer transition-colors",
      )}
    >
      <div className="flex items-center gap-2.5">
        <KeyAvatar fingerprint={contact.keyId} size={32} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {/* Line 1 is the name and nothing else, so no pill can
                ever squeeze it out of the row. */}
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
              {/* An OpenSSH fingerprint is a base64 hash: its last 16
                characters identify nothing, so it shows in full. */}
              {isSsh ? contact.keyId : contact.keyId.slice(-16)}
              {algorithm ? ` - ${algorithm}` : ""}
            </p>
          )}
          {/* The meta line: pills first, warnings leading (an expired or
              weak key must never be the part that gets cut off), then
              algorithm, expiry and provenance as truncating text. */}
          {(hasPills || details.length > 0) && (
            <div className="mt-0.5 flex min-w-0 items-center gap-1">
              {expired && contact.expiresAt && (
                <span
                  title={t("keys_contact_expired_title", {
                    date: formatDate(contact.expiresAt),
                  })}
                  className={cn(
                    PILL,
                    "bg-destructive/12 text-bad inline-flex gap-1",
                  )}
                >
                  <TriangleAlertIcon className="h-2.5 w-2.5" />
                  {t("keys_contact_expired", {
                    date: formatDateShort(contact.expiresAt),
                  })}
                </span>
              )}
              {contact.revoked && (
                /* Kept so the revocation sticks; never encrypted to. */
                <span
                  title={t("keys_contact_revoked_title")}
                  className={cn(
                    PILL,
                    "bg-destructive/12 text-bad inline-flex gap-1",
                  )}
                >
                  <TriangleAlertIcon className="h-2.5 w-2.5" />
                  {t("keys_contact_revoked")}
                </span>
              )}
              {clash && (
                <span
                  title={
                    clash.kind === "address"
                      ? t("keys_contact_same_address_title", clashArgs(clash))
                      : t("keys_contact_same_name_title", clashArgs(clash))
                  }
                  className={cn(PILL, "bg-warn/12 text-warn inline-flex gap-1")}
                >
                  <TriangleAlertIcon className="h-2.5 w-2.5" />
                  {clash.kind === "address"
                    ? t("keys_contact_same_address")
                    : t("keys_contact_same_name")}
                </span>
              )}
              {contact.verified && (
                <span
                  title={t("keys_verified_chip_title")}
                  className={cn(PILL, "bg-good/12 text-good inline-flex gap-1")}
                >
                  <CheckIcon className="h-2.5 w-2.5" />
                  {t("keys_verified_chip")}
                </span>
              )}
              {contact.securityWarning && (
                <span
                  title={contact.securityWarning}
                  className={cn(PILL, "bg-warn/12 text-warn inline-flex gap-1")}
                >
                  <TriangleAlertIcon className="h-2.5 w-2.5" />
                  {contact.lookalike
                    ? t("keys_lookalike_name")
                    : t("keys_weak_sha1")}
                </span>
              )}
              {isSsh && (
                <span
                  title={t("keys_ssh_chip_title")}
                  className={cn(PILL, "bg-secondary text-muted-foreground")}
                >
                  SSH
                </span>
              )}
              {recipients.length > 1 && (
                /* One person, several machines. Said on the card because
                 the key id it shows is only the first key's: a 3-stanza
                 file is otherwise a surprise at decrypt time. */
                <span
                  title={
                    activeKeys < recipients.length
                      ? t("keys_contact_keys_partial_title", {
                          active: activeKeys,
                          total: recipients.length,
                        })
                      : t("keys_contact_keys_all_title")
                  }
                  className={cn(PILL, "bg-secondary text-muted-foreground")}
                >
                  {activeKeys < recipients.length
                    ? t("keys_contact_keys_partial", {
                        active: activeKeys,
                        total: recipients.length,
                      })
                    : tn("keys_contact_keys_count", recipients.length)}
                </span>
              )}
              {details.length > 0 && (
                <span className="text-muted-foreground min-w-0 truncate text-[11px]">
                  {details.join(" \u00b7 ")}
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
          {/* Advanced mode regroups a hex fingerprint into 4-character
            blocks; doing that to a base64 hash would only chop it into
            meaningless quarters, and the line above already shows it in
            full. */}
          {advancedMode && !isSsh && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {formatFingerprint(contact.keyId)}
            </p>
          )}
        </div>

        {longId && !showKeyLine && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-muted-foreground shrink-0 font-mono text-[11px] leading-tight whitespace-nowrap">
                <span className="block">{longId[0]}</span>
                <span className="block">{longId[1]}</span>
              </span>
            </TooltipTrigger>
            <TooltipContent>{t("keys_contact_long_id_title")}</TooltipContent>
          </Tooltip>
        )}

        {!readOnly && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                onClick={(e) => e.stopPropagation()}
                onPointerDown={(e) => e.stopPropagation()}
                className={cn(
                  "text-muted-foreground rounded p-1 transition-colors",
                  selectionMode ? dimmed : "hover:text-foreground",
                )}
                aria-label={t("keys_contact_options_aria")}
              >
                <EllipsisVerticalIcon className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            {/* Radix portals this into <body>, but React synthetic
                events still bubble through the COMPONENT tree -- without
                this stop, a menu-item click also fires the card's
                onShowDetails and stacks the details page underneath. */}
            <DropdownMenuContent
              align="end"
              onClick={(e) => e.stopPropagation()}
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
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {/* The row itself opens details too; this is the same action as a
            visible, keyboard-reachable target. */}
        {onShowDetails && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onShowDetails();
            }}
            aria-label={t("keys_key_details")}
            className={cn(
              "text-muted-foreground -ml-1 shrink-0 rounded p-0.5 transition-colors",
              selectionMode ? dimmed : "group-hover:text-foreground",
            )}
          >
            <ChevronRightIcon className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
