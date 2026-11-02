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

import {
  Button,
  cn,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@amibeingpwned/ui";

import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { useAsyncAction } from "~/hooks/useAsyncAction";
import { useFlashMessage } from "~/hooks/useFlashMessage";
import { t } from "~/lib/i18n";
import {
  CardMenu,
  CardRow,
  DetailsChevron,
  DIMMED,
  LongIdColumn,
  Pill,
} from "./CardRow";
import {
  ExportPrivateKeyPage,
  type PrivateKeyExporter,
} from "./ExportPrivateKeyPage";
import { HEX_FINGERPRINT, longIdLines } from "./fingerprint-lines";
import { UnlockPasswordField } from "./KeyUnlockRow";

/** Absent ⇒ sealed at rest (CRX): no unlock UI. */
export interface KeyCardSession {
  isUnlocked: boolean;
  unlockWithPassword: (password: string) => Promise<boolean>;
  unlockWithPasskey: () => Promise<boolean | "cancelled">;
  lock: () => void;
}

/** One card for PGP private keys and CRX signing keys; differences are
 *  optional capabilities. */
export interface KeyCardModel {
  kind: "pgp" | "crx";
  id: string;
  displayName: string;
  realName: string;
  shortId: string;
  algorithm: string;
  fingerprint?: string;
  badge?: string;
  isDefault?: boolean;
  protectionMethod: "password" | "passkey";
  securityWarning?: string;
  session?: KeyCardSession;
  exporter: PrivateKeyExporter | null;
  onCopyPublicKey: () => void;
  onDownloadPublicKey: () => void;
  onDelete: () => void;
  onRename?: () => void;
  onShowDetails?: () => void;
}

interface KeyCardProps {
  model: KeyCardModel;
  advancedMode?: boolean;
  selectionMode: boolean;
  selected: boolean;
  onToggleSelect: (extend: boolean) => void;
  onStartSelect: () => void;
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

  // Only a hex fingerprint's tail is a real id.
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
          <p className="truncate text-sm font-medium">{model.displayName}</p>
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
        // The page lives in the card's subtree: keep its events out of the card.
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
