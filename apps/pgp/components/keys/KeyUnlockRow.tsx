import { CheckIcon, LockIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";

import { t } from "../../lib/i18n";
import { KeyAvatar } from "../shared/KeyAvatar";

interface KeyUnlockRowProps {
  name: string;
  fingerprint?: string;
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

export function UnlockPasswordField({
  password,
  onPasswordChange,
  busy,
  onUnlock,
  placeholder = t("keygen_key_password_placeholder"),
  className,
}: {
  password: string;
  onPasswordChange: (v: string) => void;
  busy: boolean;
  onUnlock: () => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex items-stretch gap-2", className)}>
      <Input
        type="password"
        autoComplete="current-password"
        placeholder={placeholder}
        value={password}
        onChange={(e) => onPasswordChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          // LOAD-BEARING. The derive runs synchronously, so the row unmounts this
          // input before the keypress lands and Enter would close the page
          // (e2e/unlock-on-open.spec.ts).
          e.preventDefault();
          onUnlock();
        }}
        className="h-9 flex-1 py-0"
      />
      <Button
        size="sm"
        className="h-9 shrink-0"
        disabled={busy || !password}
        onClick={onUnlock}
      >
        {busy ? "..." : t("common_unlock")}
      </Button>
    </div>
  );
}

/** One key in an "unlock these first" list, shared by every such flow. */
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
        <UnlockPasswordField
          className="mt-2"
          password={password}
          onPasswordChange={onPasswordChange}
          busy={busy}
          onUnlock={onUnlockPassword}
        />
      )}

      {error && <p className="text-destructive mt-1 text-xs">{error}</p>}
    </div>
  );
}
