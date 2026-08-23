import { useState } from "react";
import { format } from "date-fns";
import {
  ArrowRightIcon,
  CheckCircleIcon,
  CopyIcon,
  DownloadIcon,
  EllipsisVerticalIcon,
  ListChecksIcon,
  LockIcon,
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

import type { PublicContactKey } from "../../lib/storage/contacts";
import {
  activeRecipients,
  contactRecipients,
  contactSource,
} from "../../lib/storage/contacts";
import { isSshRecord } from "../../lib/storage/key-kind";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import { parseUserId } from "../../lib/utils/key-naming";
import { useJustImported } from "./useJustImported";
import { useLongPress } from "./useLongPress";

interface ContactCardProps {
  contact: PublicContactKey;
  onRemove?: () => void;
  onEncryptTo?: () => void;
  onCopyPublicKey?: () => void;
  onDownloadPublicKey?: () => void;
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
  /** Bulk-selection: when true, a tap toggles selection instead of navigating
   *  and the card's own controls are dimmed/click-through. */
  selectionMode?: boolean;
  selected?: boolean;
  onToggleSelect?: () => void;
  /** Enter selection mode with this contact selected (long-press / menu). */
  onStartSelect?: () => void;
  /** Just arrived from an import: scroll to it and pulse it once. */
  justImported?: boolean;
}

export function ContactCard({
  contact,
  onRemove,
  onEncryptTo,
  onCopyPublicKey,
  onDownloadPublicKey,
  onShowDetails,
  advancedMode,
  readOnly,
  verifiedLabel,
  verifiedTone = "success",
  note,
  selectionMode = false,
  selected = false,
  onToggleSelect,
  onStartSelect,
  justImported,
}: ContactCardProps) {
  const [importedRef, importedClass] = useJustImported(justImported);
  const isWarning = verifiedTone === "warning";
  const toneBorder = isWarning ? "border-orange-500/50" : "border-green-500/50";
  const toneText = isWarning ? "text-orange-400" : "text-green-400";
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
  const userId = contact.userIds[0] ?? "Unknown";
  const { name: rawName, email, comment } = parseUserId(userId);
  const name = comment ? `${rawName} (${comment})` : rawName;

  const longPress = useLongPress(
    () => onStartSelect?.(),
    !selectionMode && !!onStartSelect,
  );

  const handleClick = () => {
    if (longPress.consumeClick()) return;
    if (selectionMode) {
      onToggleSelect?.();
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

  return (
    <div
      ref={importedRef}
      onClick={handleClick}
      {...longPress.handlers}
      className={cn(
        "group relative rounded-md p-3",
        importedClass,
        // Keep the border width constant (1px) and add thickness with a ring
        // (box-shadow, no layout impact) so selecting doesn't shift the card.
        selected
          ? "border border-green-500/80 ring-2 ring-green-500/40"
          : verifiedLabel
            ? `border ${toneBorder}`
            : "border-border border",
        clickable && "hover:bg-muted/40 cursor-pointer transition-colors",
      )}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="flex min-w-0 items-center gap-1.5 truncate text-sm font-medium">
              <span className="truncate">{name}</span>
              {isSsh && (
                <span
                  title="An SSH key, used with age. It can't be combined with PGP recipients in one message."
                  className="bg-secondary text-muted-foreground shrink-0 rounded border px-1 text-[10px] leading-4 font-normal"
                >
                  SSH
                </span>
              )}
              {recipients.length > 1 && (
                /* One person, several machines. Said on the card because
                   the fingerprint line below shows only the first: a
                   3-stanza file is otherwise a surprise at decrypt time. */
                <span
                  title={
                    activeKeys < recipients.length
                      ? `Messages are encrypted to ${activeKeys} of this contact's ${recipients.length} keys; the rest are turned off in their key details.`
                      : "Messages are encrypted to all of this contact's keys; any one of them can decrypt."
                  }
                  className="bg-secondary text-muted-foreground shrink-0 rounded border px-1 text-[10px] leading-4 font-normal"
                >
                  {activeKeys < recipients.length
                    ? `${activeKeys} of ${recipients.length} keys`
                    : `${recipients.length} keys`}
                </span>
              )}
            </p>
            {verifiedLabel && (
              <span
                className={`flex shrink-0 items-center gap-1 text-xs ${toneText}`}
              >
                <ToneIcon className="h-3.5 w-3.5" />
                {verifiedLabel}
              </span>
            )}
          </div>
          {email && (
            <p className="text-muted-foreground truncate text-xs">{email}</p>
          )}
          <p className="text-muted-foreground mt-0.5 font-mono text-xs break-all">
            {/* An OpenSSH fingerprint is a base64 hash: its last 16
                characters identify nothing, so it shows in full. */}
            {isSsh ? contact.keyId : contact.keyId.slice(-16)}
            {contact.algorithm
              ? ` - ${formatAlgorithm(contact.algorithm)}`
              : ""}
          </p>
          {source?.type === "github" && (
            /* Where this contact came from, which is also its upsert
               identity: looking the same user up again updates THIS
               record rather than adding a second one. */
            <p className="text-muted-foreground mt-0.5 text-xs">
              From github.com/{source.user}
            </p>
          )}
          {note && <p className="text-muted-foreground mt-1 text-xs">{note}</p>}
          {/* Advanced mode regroups a hex fingerprint into 4-character
              blocks; doing that to a base64 hash would only chop it into
              meaningless quarters, and the line above already shows it in
              full. */}
          {advancedMode && !isSsh && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {formatFingerprint(contact.keyId)}
            </p>
          )}
          {contact.expiresAt &&
            (contact.expiresAt < now ? (
              <div className="mt-1">
                <span
                  title={`This key expired on ${format(new Date(contact.expiresAt), "PPP")} and can no longer be encrypted to. Ask the owner for their current key.`}
                  className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-400"
                >
                  <TriangleAlertIcon className="h-3 w-3" />
                  Expired {format(new Date(contact.expiresAt), "PP")}
                </span>
              </div>
            ) : (
              <p className="text-muted-foreground mt-0.5 text-xs">
                Expires {format(new Date(contact.expiresAt), "PPP")}
              </p>
            ))}
          {contact.securityWarning && (
            <div className="mt-1">
              <span
                title={contact.securityWarning}
                className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400"
              >
                <TriangleAlertIcon className="h-3 w-3" />
                Weak (SHA-1)
              </span>
            </div>
          )}
        </div>

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
                aria-label="Contact options"
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
                  Encrypt to
                </DropdownMenuItem>
              )}
              {onCopyPublicKey && (
                <DropdownMenuItem onClick={onCopyPublicKey}>
                  <CopyIcon />
                  Copy public key
                </DropdownMenuItem>
              )}
              {onDownloadPublicKey && (
                <DropdownMenuItem onClick={onDownloadPublicKey}>
                  <DownloadIcon />
                  Download public key
                </DropdownMenuItem>
              )}
              {onStartSelect && (
                <DropdownMenuItem onClick={onStartSelect}>
                  <ListChecksIcon />
                  Select
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={onRemove}
              >
                <Trash2Icon className="text-destructive" />
                Remove contact
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {onShowDetails && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onShowDetails();
          }}
          aria-label="Key details"
          className={cn(
            "text-muted-foreground absolute right-3 bottom-2 rounded p-1 transition-colors",
            selectionMode ? dimmed : "group-hover:text-foreground",
          )}
        >
          <ArrowRightIcon className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}
