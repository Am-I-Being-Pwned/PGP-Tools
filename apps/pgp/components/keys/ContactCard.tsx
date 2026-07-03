import { useState } from "react";
import { format } from "date-fns";
import {
  CheckCircleIcon,
  EllipsisVerticalIcon,
  TriangleAlertIcon,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import { parseUserId } from "../../lib/utils/key-naming";

interface ContactCardProps {
  contact: PublicContactKey;
  onRemove?: () => void;
  onEncryptTo?: () => void;
  onCopyPublicKey?: () => void;
  advancedMode?: boolean;
  readOnly?: boolean;
  verifiedLabel?: string;
  /** Colour of the verified badge/border. "warning" (orange) is used when a
   *  message is signed but the signature could not be verified. */
  verifiedTone?: "success" | "warning";
  /** Optional muted explanation shown under the key line. */
  note?: string;
}

export function ContactCard({
  contact,
  onRemove,
  onEncryptTo,
  onCopyPublicKey,
  advancedMode,
  readOnly,
  verifiedLabel,
  verifiedTone = "success",
  note,
}: ContactCardProps) {
  const isWarning = verifiedTone === "warning";
  const toneBorder = isWarning ? "border-orange-500/50" : "border-green-500/50";
  const toneText = isWarning ? "text-orange-400" : "text-green-400";
  const ToneIcon = isWarning ? TriangleAlertIcon : CheckCircleIcon;
  const [confirming, setConfirming] = useState(false);
  const [showWarning, setShowWarning] = useState(false);
  const userId = contact.userIds[0] ?? "Unknown";
  const { name: rawName, email, comment } = parseUserId(userId);
  const name = comment ? `${rawName} (${comment})` : rawName;

  if (confirming) {
    return (
      <div className="border-destructive/30 bg-destructive/5 rounded-md border p-3">
        <p className="text-xs">
          Remove <span className="font-medium">{name}</span>?
        </p>
        <div className="mt-2 flex gap-1">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setConfirming(false)}
          >
            Cancel
          </Button>
          <Button size="sm" variant="destructive" onClick={onRemove}>
            Remove
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`rounded-md border p-3 ${verifiedLabel ? toneBorder : "border-border"}`}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-sm font-medium">{name}</p>
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
          <p className="text-muted-foreground mt-0.5 font-mono text-xs">
            {contact.keyId.slice(-16)}
            {contact.algorithm
              ? ` - ${formatAlgorithm(contact.algorithm)}`
              : ""}
          </p>
          {note && <p className="text-muted-foreground mt-1 text-xs">{note}</p>}
          {advancedMode && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {formatFingerprint(contact.keyId)}
            </p>
          )}
          {contact.expiresAt && (
            <p className="text-muted-foreground mt-0.5 text-xs">
              Expires {format(new Date(contact.expiresAt), "PPP")}
            </p>
          )}
          {contact.securityWarning && (
            <div className="mt-1">
              <button
                type="button"
                onClick={() => setShowWarning((v) => !v)}
                aria-expanded={showWarning}
                className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-700 transition-colors hover:bg-amber-500/20 dark:text-amber-400"
              >
                <TriangleAlertIcon className="h-3 w-3" />
                Weak (SHA-1)
              </button>
              {showWarning && (
                <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
                  {contact.securityWarning}
                </p>
              )}
            </div>
          )}
        </div>

        {!readOnly && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
                aria-label="Contact options"
              >
                <EllipsisVerticalIcon className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {onEncryptTo && (
                <DropdownMenuItem onClick={onEncryptTo}>
                  Encrypt to
                </DropdownMenuItem>
              )}
              {onCopyPublicKey && (
                <DropdownMenuItem onClick={onCopyPublicKey}>
                  Copy public key
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => setConfirming(true)}
              >
                Remove contact
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </div>
  );
}
