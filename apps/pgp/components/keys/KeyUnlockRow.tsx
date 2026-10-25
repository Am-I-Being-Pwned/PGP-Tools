import { CheckIcon, LockIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { t } from "../../lib/i18n";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { KeyAvatar } from "../shared/KeyAvatar";

interface KeyUnlockRowProps {
  name: string;
  /** The key's fingerprint (or a CRX key's extension id), for its face.
   *  Absent ⇒ no avatar. */
  fingerprint?: string;
  /** Small trailing tag after the name (e.g. "CRX", "SSH"). */
  badge?: string;
  unlocked: boolean;
  isPasskey: boolean;
  busy: boolean;
  password: string;
  error?: string;
  onPasswordChange: (v: string) => void;
  onUnlockPassword: () => void;
  onUnlockPasskey: () => void;
}

/**
 * One key in an "unlock these first" list: status icon, name, and the
 * inline unlock control its protection method calls for (a button for a
 * passkey, a password field otherwise). Shared by every flow that needs
 * several keys live before it can proceed -- bulk export, and re-sealing
 * keys under the vault passkey -- so they all look and behave the same.
 *
 * A flat block: callers stack the rows in a `BlockStack`.
 */
export function KeyUnlockRow({
  name,
  fingerprint,
  badge,
  unlocked,
  isPasskey,
  busy,
  password,
  error,
  onPasswordChange,
  onUnlockPassword,
  onUnlockPasskey,
}: KeyUnlockRowProps) {
  return (
    <div className="bg-card rounded-[3px] px-3 py-2.5">
      <div className="flex items-center gap-2.5">
        {fingerprint && <KeyAvatar fingerprint={fingerprint} size={32} />}
        <span className={unlocked ? "text-good" : "text-muted-foreground"}>
          {unlocked ? (
            <CheckIcon className="h-4 w-4" />
          ) : (
            <LockIcon className="h-4 w-4" />
          )}
        </span>
        <span className="min-w-0 flex-1 truncate text-sm">
          {name}
          {badge && (
            <span className="bg-secondary text-muted-foreground ml-1.5 rounded px-1.5 py-px text-[10.5px] font-medium">
              {badge}
            </span>
          )}
        </span>
        {!unlocked && isPasskey && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={onUnlockPasskey}
          >
            {busy ? "..." : t("common_unlock")}
          </Button>
        )}
      </div>

      {!unlocked && !isPasskey && (
        <div className="mt-2 flex items-stretch gap-2">
          <input
            type="password"
            autoComplete="current-password"
            placeholder={t("keygen_key_password_placeholder")}
            value={password}
            onChange={(e) => onPasswordChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key !== "Enter") return;
              // preventDefault is LOAD-BEARING. The unlock chain is all
              // microtasks, and the Argon2id derive inside it runs
              // synchronously on the main thread -- so it completes, and
              // this row re-renders as unlocked (removing this input),
              // BEFORE the browser delivers the matching keypress. Focus
              // then lands on the slide-over's first tabbable, the header
              // Back button, and the keypress activates it: Enter-to-
              // unlock closed the whole page. Found by
              // e2e/unlock-on-open.spec.ts; the export page had it too.
              e.preventDefault();
              onUnlockPassword();
            }}
            className={`${INPUT_CLASS} h-9 flex-1 py-0`}
          />
          <Button
            size="sm"
            className="h-9 shrink-0"
            disabled={busy || !password}
            onClick={onUnlockPassword}
          >
            {busy ? "..." : t("common_unlock")}
          </Button>
        </div>
      )}

      {error && <p className="text-destructive mt-1 text-xs">{error}</p>}
    </div>
  );
}
