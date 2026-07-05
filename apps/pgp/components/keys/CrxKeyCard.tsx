import { useRef, useState } from "react";
import {
  CopyIcon,
  EllipsisVerticalIcon,
  KeyIcon,
  LockIcon,
  PencilIcon,
  Trash2Icon,
} from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import { publicKeyDerToPem } from "../../lib/crx/types";
import { formatAlgorithm } from "../../lib/utils/formatting";
import { CrxExportPrivateDialog } from "./CrxExportPrivateDialog";

interface CrxKeyCardProps {
  keyBlob: CrxSigningKeyBlob;
  onDelete: () => void;
  /** Open the rename page. Omitted when renaming isn't available. */
  onRename?: () => void;
}

/**
 * List card for a CRX (Chrome extension) signing key. Deliberately mirrors
 * {@link KeyCard}'s shell -- same container, lock glyph, title/subtitle, and
 * overflow menu -- so CRX keys read as first-class keys in the same list
 * rather than a bolted-on row. The action set differs (a CRX key is raw RSA:
 * no messaging, no per-session unlock -- it's sealed at rest and unlocked
 * only for the signing act), so the menu offers just "Copy public key" and
 * "Delete".
 */
export function CrxKeyCard({ keyBlob, onDelete, onRename }: CrxKeyCardProps) {
  const [showCopyPrivate, setShowCopyPrivate] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const feedbackTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const displayName = keyBlob.label ?? keyBlob.extensionId;
  const shortId = keyBlob.extensionId.slice(0, 16);
  const isPasskey = keyBlob.protection.method === "passkey";

  const showFeedback = (msg: string) => {
    setFeedback(msg);
    clearTimeout(feedbackTimer.current);
    feedbackTimer.current = setTimeout(() => setFeedback(null), 2000);
  };

  return (
    <div className="border-border rounded-md border p-3">
      <div className="flex items-center gap-2">
        <span
          className="text-muted-foreground shrink-0 text-sm"
          title="Sealed at rest"
        >
          <LockIcon className="h-4 w-4" />
        </span>

        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">
            {displayName}
            <span className="text-muted-foreground ml-1.5 text-[11px]">
              CRX
            </span>
          </p>
          <p className="text-muted-foreground truncate font-mono text-xs">
            {shortId} · {formatAlgorithm(keyBlob.algorithm)}
          </p>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
              aria-label="Key options"
            >
              <EllipsisVerticalIcon className="h-4 w-4" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {onRename && (
              <DropdownMenuItem onClick={onRename}>
                <PencilIcon />
                Rename
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              onClick={() => {
                void navigator.clipboard.writeText(
                  publicKeyDerToPem(keyBlob.publicKeyDerB64),
                );
                showFeedback("Public key copied");
              }}
            >
              <CopyIcon />
              Copy public key
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => setShowCopyPrivate(true)}
            >
              <KeyIcon className="text-destructive" />
              Copy private key
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onDelete}
            >
              <Trash2Icon className="text-destructive" />
              Delete key
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <p className="text-muted-foreground mt-0.5 ml-6 text-xs">
        {isPasskey ? "Passkey" : "Password"}
      </p>

      {feedback && (
        <p className="mt-1 ml-6 text-xs text-green-400">{feedback}</p>
      )}

      <CrxExportPrivateDialog
        open={showCopyPrivate}
        onClose={() => setShowCopyPrivate(false)}
        keyBlob={keyBlob}
      />
    </div>
  );
}
