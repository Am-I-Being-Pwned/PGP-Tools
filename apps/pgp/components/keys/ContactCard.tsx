import { useState } from "react";
import { format } from "date-fns";
import { CheckCircleIcon, EllipsisVerticalIcon } from "lucide-react";

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
}

export function ContactCard({
  contact,
  onRemove,
  onEncryptTo,
  onCopyPublicKey,
  advancedMode,
  readOnly,
  verifiedLabel,
}: ContactCardProps) {
  const [confirming, setConfirming] = useState(false);
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
      className={`rounded-md border p-3 ${verifiedLabel ? "border-green-500/50" : "border-border"}`}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between">
            <p className="truncate text-sm font-medium">{name}</p>
            {verifiedLabel && (
              <span className="flex shrink-0 items-center gap-1 text-xs text-green-400">
                <CheckCircleIcon className="h-3.5 w-3.5" />
                {verifiedLabel}
              </span>
            )}
          </div>
          {email && (
            <p className="text-muted-foreground truncate text-xs">{email}</p>
          )}
          <p className="text-muted-foreground mt-0.5 font-mono text-xs">
            {contact.keyId.slice(-16)} - {formatAlgorithm(contact.algorithm)}
          </p>
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
