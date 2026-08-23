import { useEffect, useRef, useState } from "react";
import {
  ArrowRightIcon,
  CopyIcon,
  DownloadIcon,
  EllipsisVerticalIcon,
  KeyIcon,
  ListChecksIcon,
  LockIcon,
  LockOpenIcon,
  PencilIcon,
  Trash2Icon,
  TriangleAlertIcon,
} from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Button } from "@amibeingpwned/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";

import type { PrivateKeyExporter } from "./ExportPrivateKeyPage";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { ExportPrivateKeyPage } from "./ExportPrivateKeyPage";
import { useJustImported } from "./useJustImported";
import { useLongPress } from "./useLongPress";

/** Lock/unlock lifecycle for a key that lives in the per-session vault (PGP).
 *  Absent on a descriptor ⇒ the key is sealed at rest (CRX): no unlock UI. */
export interface KeyCardSession {
  isUnlocked: boolean;
  unlockWithPassword: (password: string) => Promise<boolean>;
  unlockWithPasskey: () => Promise<boolean | "cancelled">;
  lock: () => void;
}

/**
 * A unified, crypto-agnostic view of a manageable private key. Both PGP private
 * keys and CRX signing keys map into this shape so one card renders both; the
 * behavioural differences (session unlock vs sealed-at-rest, action set) are
 * expressed as optional capabilities rather than separate components.
 */
export interface KeyCardModel {
  kind: "pgp" | "crx";
  /** Stable identity: keyId (PGP) or extensionId (CRX). */
  id: string;
  displayName: string;
  /** Underlying identity (userId / extensionId) for the rename hint. */
  realName: string;
  shortId: string;
  algorithm: string;
  /** Advanced-mode fingerprint line (PGP only). */
  fingerprint?: string;
  /** Small tag after the name, e.g. "CRX". */
  badge?: string;
  /** True when this is the user's configured default key (PGP only):
   *  shows a subtle "Default" pill after the name. */
  isDefault?: boolean;
  protectionMethod: "password" | "passkey";
  securityWarning?: string;
  /** Present ⇒ show unlock/lock lifecycle (PGP). Absent ⇒ sealed at rest (CRX). */
  session?: KeyCardSession;
  /** Present ⇒ enable "Copy private key" (opens the unified export page). */
  exporter: PrivateKeyExporter | null;
  onCopyPublicKey: () => void;
  onDownloadPublicKey: () => void;
  onDelete: () => void;
  onRename?: () => void;
  /** Present ⇒ card is clickable into a details page (PGP). */
  onShowDetails?: () => void;
}

interface KeyCardProps {
  model: KeyCardModel;
  advancedMode?: boolean;
  selectionMode: boolean;
  selected: boolean;
  /** Toggle this card's membership while already in selection mode. */
  onToggleSelect: () => void;
  /** Enter selection mode with this card selected (long-press / menu). */
  onStartSelect: () => void;
  /** Just arrived from an import: scroll to it and pulse it once. */
  justImported?: boolean;
}

export function KeyCard({
  model,
  advancedMode,
  selectionMode,
  selected,
  onToggleSelect,
  onStartSelect,
  justImported,
}: KeyCardProps) {
  const [importedRef, importedClass] = useJustImported(justImported);
  const [showPasswordUnlock, setShowPasswordUnlock] = useState(false);
  const [showExportPrivate, setShowExportPrivate] = useState(false);
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const feedbackTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const longPress = useLongPress(onStartSelect, !selectionMode);

  useEffect(() => {
    return () => clearTimeout(feedbackTimer.current);
  }, []);

  const { session, exporter } = model;
  const isUnlocked = session?.isUnlocked ?? false;
  const isPasskey = model.protectionMethod === "passkey";
  // CRX exports unlock inside the dialog; PGP requires the session unlocked.
  const canExportPrivate = exporter !== null && (!session || isUnlocked);

  const showFeedback = (msg: string) => {
    setFeedback(msg);
    clearTimeout(feedbackTimer.current);
    feedbackTimer.current = setTimeout(() => setFeedback(null), 2000);
  };

  const handlePasswordUnlock = async () => {
    if (!session) return;
    setError(null);
    setUnlocking(true);
    const success = await session.unlockWithPassword(password);
    if (success) {
      setShowPasswordUnlock(false);
      setPassword("");
    } else {
      setError("Wrong password");
    }
    setUnlocking(false);
  };

  const handlePasskeyUnlock = async () => {
    if (!session) return;
    setError(null);
    const result = await session.unlockWithPasskey();
    if (result === "cancelled") return;
    if (!result) setError("Passkey authentication failed");
  };

  const handleCardClick = () => {
    if (longPress.consumeClick()) return; // swallow the click ending a long-press
    if (selectionMode) {
      onToggleSelect();
      return;
    }
    model.onShowDetails?.();
  };

  const clickable = selectionMode || !!model.onShowDetails;
  // While selecting, the card itself is the target: its own controls are dimmed
  // and click-through (`dimmed`), and drop their hover highlight -- `hover:` /
  // `group-hover:` fire from hovering the CARD, so pointer-events-none alone
  // wouldn't stop the highlight.
  const dimmed = "pointer-events-none opacity-40";

  return (
    <div
      ref={importedRef}
      onClick={handleCardClick}
      {...longPress.handlers}
      className={cn(
        // Same floor as ContactCard: the two render into one list, so a
        // sealed-at-rest key (no unlock row, no details arrow) must not
        // read as a shorter species of card than the contacts above it.
        "group relative min-h-19 rounded-md p-3 transition-colors",
        importedClass,
        // Keep the border width constant (1px) and add thickness with a ring
        // (box-shadow, no layout impact) so selecting doesn't shift the card.
        selected
          ? "border border-green-500/80 ring-2 ring-green-500/40"
          : "border-border border",
        clickable && "hover:bg-muted/40 cursor-pointer",
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={`shrink-0 text-sm ${isUnlocked ? "text-green-400" : "text-muted-foreground"}`}
          title={
            session ? (isUnlocked ? "Unlocked" : "Locked") : "Sealed at rest"
          }
        >
          {isUnlocked ? (
            <LockOpenIcon className="h-4 w-4" />
          ) : (
            <LockIcon className="h-4 w-4" />
          )}
        </span>

        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">
            {model.displayName}
            {model.badge && (
              <span className="text-muted-foreground ml-1.5 text-[11px]">
                {model.badge}
              </span>
            )}
            {model.isDefault && (
              <span
                title="Used by default for signing, decrypting, and encrypt-to-self"
                className="border-border text-muted-foreground ml-1.5 rounded-full border px-1.5 py-px text-[10px] font-medium whitespace-nowrap"
              >
                Default
              </span>
            )}
          </p>
          <p className="text-muted-foreground truncate font-mono text-xs">
            {model.shortId} · {model.algorithm}
          </p>
          {advancedMode && model.fingerprint && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {model.fingerprint}
            </p>
          )}
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              onClick={(e) => e.stopPropagation()}
              onPointerDown={(e) => e.stopPropagation()}
              className={cn(
                "text-muted-foreground rounded p-1 transition-colors",
                selectionMode ? dimmed : "hover:text-foreground",
              )}
              aria-label="Key options"
            >
              <EllipsisVerticalIcon className="h-4 w-4" />
            </button>
          </DropdownMenuTrigger>
          {/* Radix portals this into <body>, but React synthetic events still
                bubble through the COMPONENT tree -- without this stop, a
                menu-item click also fires the card's onClick. */}
          <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
            {model.onRename && (
              <DropdownMenuItem onClick={model.onRename}>
                <PencilIcon />
                Rename
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              onClick={() => {
                model.onCopyPublicKey();
                showFeedback("Public key copied");
              }}
            >
              <CopyIcon />
              Copy public key
            </DropdownMenuItem>
            <DropdownMenuItem onClick={model.onDownloadPublicKey}>
              <DownloadIcon />
              Download public key
            </DropdownMenuItem>
            {canExportPrivate && (
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => setShowExportPrivate(true)}
              >
                <KeyIcon className="text-destructive" />
                Copy private key
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onStartSelect}>
              <ListChecksIcon />
              Select
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={model.onDelete}
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

      {model.securityWarning && (
        <div className="mt-1 ml-6">
          <span
            title={model.securityWarning}
            className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400"
          >
            <TriangleAlertIcon className="h-3 w-3" />
            Weak (SHA-1)
          </span>
        </div>
      )}

      {feedback && (
        <p className="mt-1 ml-6 text-xs text-green-400">{feedback}</p>
      )}

      {/* Inline password unlock -- session keys only, and not while selecting. */}
      {session &&
        showPasswordUnlock &&
        !isUnlocked &&
        !isPasskey &&
        !selectionMode && (
          <div className="mt-2 space-y-2" onClick={(e) => e.stopPropagation()}>
            <input
              type="password"
              autoComplete="current-password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handlePasswordUnlock();
              }}
              className={INPUT_CLASS}
            />
            {error && <p className="text-destructive text-xs">{error}</p>}
            <div className="flex justify-between gap-1">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setShowPasswordUnlock(false);
                  setPassword("");
                  setError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => void handlePasswordUnlock()}
                disabled={unlocking}
              >
                {unlocking ? "..." : "Unlock"}
              </Button>
            </div>
          </div>
        )}

      {session && error && isPasskey && !isUnlocked && (
        <p className="text-destructive mt-2 text-xs">{error}</p>
      )}

      {exporter && showExportPrivate && (
        // The page portals visually (fixed inset-0) but lives in the card's
        // DOM subtree, so stop clicks/presses from bubbling into the card's
        // own click + long-press handlers.
        <div
          onClick={(e) => e.stopPropagation()}
          onPointerDown={(e) => e.stopPropagation()}
        >
          <ExportPrivateKeyPage
            onClose={() => setShowExportPrivate(false)}
            exporter={exporter}
          />
        </div>
      )}

      {/* Bottom action row: unlock/lock lifecycle + details arrow. Dimmed while
          selecting, and absent entirely for sealed-at-rest keys with no
          details page (CRX). */}
      {!showPasswordUnlock && (!!session || !!model.onShowDetails) && (
        <div
          className={cn(
            "mt-2 flex items-center justify-end gap-1",
            selectionMode && dimmed,
          )}
        >
          {session &&
            (isUnlocked ? (
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  session.lock();
                }}
              >
                Lock
              </Button>
            ) : isPasskey ? (
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  void handlePasskeyUnlock();
                }}
              >
                Unlock
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  setShowPasswordUnlock(true);
                }}
              >
                Unlock
              </Button>
            ))}
          {model.onShowDetails && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                model.onShowDetails?.();
              }}
              aria-label="Key details"
              className={cn(
                "text-muted-foreground rounded p-1.5 transition-colors",
                !selectionMode && "group-hover:text-foreground",
              )}
            >
              <ArrowRightIcon className="h-4 w-4" />
            </button>
          )}
        </div>
      )}
    </div>
  );
}
