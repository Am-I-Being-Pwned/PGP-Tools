import { useState } from "react";
import {
  CopyIcon,
  DownloadIcon,
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
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@amibeingpwned/ui/dropdown-menu";

import type { PrivateKeyExporter } from "./ExportPrivateKeyPage";
import { useAsyncAction } from "../../hooks/useAsyncAction";
import { useFlashMessage } from "../../hooks/useFlashMessage";
import { t } from "../../lib/i18n";
import { KeyAvatar } from "../shared/KeyAvatar";
import {
  CardMenu,
  CardRow,
  DetailsChevron,
  DIMMED,
  LongIdColumn,
  Pill,
} from "./CardRow";
import { ExportPrivateKeyPage } from "./ExportPrivateKeyPage";
import { HEX_FINGERPRINT, longIdLines } from "./fingerprint-lines";
import { UnlockPasswordField } from "./KeyUnlockRow";

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
  /** `extend`: Shift was held -- select the run from the last-touched card. */
  onToggleSelect: (extend: boolean) => void;
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
  const [showPasswordUnlock, setShowPasswordUnlock] = useState(false);
  const [showExportPrivate, setShowExportPrivate] = useState(false);
  const [password, setPassword] = useState("");
  const unlock = useAsyncAction(t("keys_wrong_password"));
  const [feedback, flash] = useFlashMessage();

  const { session, exporter } = model;
  const isUnlocked = session?.isUnlocked ?? false;
  const isPasskey = model.protectionMethod === "passkey";
  // CRX exports unlock inside the page; PGP needs the session unlocked.
  const canExportPrivate = exporter !== null && (!session || isUnlocked);

  const handlePasswordUnlock = () =>
    unlock.run(async () => {
      if (!session) return;
      if (await session.unlockWithPassword(password)) {
        setShowPasswordUnlock(false);
        setPassword("");
      } else {
        unlock.setError(t("keys_wrong_password"));
      }
    });

  const handlePasskeyUnlock = () =>
    unlock.run(async () => {
      if (!session) return;
      const result = await session.unlockWithPasskey();
      if (result === false) unlock.setError(t("keys_passkey_failed"));
    }, t("keys_passkey_failed"));

  const cancelPasswordUnlock = () => {
    setShowPasswordUnlock(false);
    setPassword("");
    unlock.reset();
  };

  // A hex fingerprint's tail is a real id; an SSH hash's or a CRX
  // extension id's is not, so those keep the full id in the meta line.
  const longId = HEX_FINGERPRINT.test(model.id) ? longIdLines(model.id) : null;
  const error = unlock.error?.message;

  return (
    <CardRow
      selectionMode={selectionMode}
      selected={selected}
      onToggleSelect={onToggleSelect}
      onStartSelect={onStartSelect}
      onShowDetails={model.onShowDetails}
      justImported={justImported}
    >
      <div className="flex items-center gap-2.5">
        <KeyAvatar fingerprint={model.id} size={32} />

        <div className="min-w-0 flex-1">
          {/* The name alone on line 1: no pill can squeeze it out. */}
          <p className="truncate text-sm font-medium">{model.displayName}</p>
          {/* Pills first, warnings leading, so they are never what gets
              cut off; then the algorithm (or the full id, see longId). */}
          <div className="mt-0.5 flex min-w-0 items-center gap-1">
            {model.securityWarning && (
              <Pill
                tone="warn"
                title={model.securityWarning}
                icon={<TriangleAlertIcon className="h-2.5 w-2.5" />}
              >
                {t("keys_weak_sha1")}
              </Pill>
            )}
            {model.badge && <Pill>{model.badge}</Pill>}
            {model.isDefault && (
              <Pill title={t("keys_default_title")}>
                {t("keys_default_badge")}
              </Pill>
            )}
            {/* Protection, with the session state in its lock; green is
                a key live in this session. */}
            <Pill
              tone={isUnlocked ? "good" : "neutral"}
              title={
                session
                  ? isUnlocked
                    ? t("keys_status_unlocked")
                    : t("keys_status_locked")
                  : t("keys_status_sealed")
              }
              icon={
                isUnlocked ? (
                  <LockOpenIcon className="h-2.5 w-2.5" />
                ) : (
                  <LockIcon className="h-2.5 w-2.5" />
                )
              }
            >
              {isPasskey
                ? t("keys_protection_passkey")
                : t("keys_protection_password")}
            </Pill>
            {advancedMode || !longId ? (
              <span className="text-muted-foreground min-w-0 truncate font-mono text-[11px]">
                {model.shortId} · {model.algorithm}
              </span>
            ) : (
              <span className="text-muted-foreground min-w-0 truncate text-xs">
                {model.algorithm}
              </span>
            )}
          </div>
          {advancedMode && model.fingerprint && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {model.fingerprint}
            </p>
          )}
        </div>

        {longId && !advancedMode && <LongIdColumn lines={longId} />}

        {/* Hidden while the password field is open (it has its own
            controls); absent for sealed-at-rest keys. */}
        {session && !showPasswordUnlock && (
          <span className={cn("shrink-0", selectionMode && DIMMED)}>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2.5 text-xs"
              onClick={(e) => {
                e.stopPropagation();
                if (isUnlocked) session.lock();
                else if (isPasskey) void handlePasskeyUnlock();
                else setShowPasswordUnlock(true);
              }}
            >
              {isUnlocked ? t("common_lock") : t("common_unlock")}
            </Button>
          </span>
        )}

        <CardMenu
          ariaLabel={t("keys_key_options_aria")}
          selectionMode={selectionMode}
        >
          {model.onRename && (
            <DropdownMenuItem onClick={model.onRename}>
              <PencilIcon />
              {t("keys_rename")}
            </DropdownMenuItem>
          )}
          <DropdownMenuItem
            onClick={() => {
              model.onCopyPublicKey();
              flash(t("keys_public_key_copied"));
            }}
          >
            <CopyIcon />
            {t("keys_copy_public_key")}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={model.onDownloadPublicKey}>
            <DownloadIcon />
            {t("keys_download_public_key")}
          </DropdownMenuItem>
          {canExportPrivate && (
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => setShowExportPrivate(true)}
            >
              <KeyIcon className="text-destructive" />
              {t("keys_copy_private_key")}
            </DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={onStartSelect}>
            <ListChecksIcon />
            {t("keys_select")}
          </DropdownMenuItem>
          <DropdownMenuItem
            className="text-destructive focus:text-destructive"
            onClick={model.onDelete}
          >
            <Trash2Icon className="text-destructive" />
            {t("keys_delete_key")}
          </DropdownMenuItem>
        </CardMenu>

        {model.onShowDetails && !showPasswordUnlock && (
          <DetailsChevron
            onClick={model.onShowDetails}
            selectionMode={selectionMode}
          />
        )}
      </div>

      {feedback && (
        <p className="text-good mt-1 ml-[42px] text-xs">{feedback}</p>
      )}

      {session &&
        showPasswordUnlock &&
        !isUnlocked &&
        !isPasskey &&
        !selectionMode && (
          <div
            className="mt-2 ml-[42px] space-y-2"
            onClick={(e) => e.stopPropagation()}
          >
            <UnlockPasswordField
              password={password}
              onPasswordChange={setPassword}
              busy={unlock.busy}
              onUnlock={() => void handlePasswordUnlock()}
              placeholder={t("keys_enter_password_placeholder")}
            />
            {error && <p className="text-destructive text-xs">{error}</p>}
            <Button size="sm" variant="outline" onClick={cancelPasswordUnlock}>
              {t("common_cancel")}
            </Button>
          </div>
        )}

      {session && error && isPasskey && !isUnlocked && (
        <p className="text-destructive mt-2 ml-[42px] text-xs">{error}</p>
      )}

      {exporter && showExportPrivate && (
        // The page is fixed inset-0 but lives in the card's subtree: keep
        // its clicks and presses out of the card's handlers.
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
    </CardRow>
  );
}
