import { useState } from "react";
import { EyeIcon, EyeOffIcon } from "lucide-react";

import { SubPage } from "~/components/shared/SubPage";
import { t, tn } from "~/lib/i18n";
import { INPUT_CLASS } from "~/lib/utils/styles";
import { MIN_MESSAGE_PASSWORD_LENGTH } from "./workspace-state";

interface MessagePasswordPageProps {
  /** Never called with fewer than {@link MIN_MESSAGE_PASSWORD_LENGTH}. */
  onSet: (password: string) => void;
  onCancel: () => void;
}

/**
 * The symmetric-encryption password. One field plus a reveal toggle, not a
 * confirm field: a typo is silent and permanent (the message opens for
 * nobody), and reveal also catches the same mistake typed twice.
 */
export function MessagePasswordPage({
  onSet,
  onCancel,
}: MessagePasswordPageProps) {
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);

  const tooShort =
    password.length > 0 && password.length < MIN_MESSAGE_PASSWORD_LENGTH;
  const ready = password.length >= MIN_MESSAGE_PASSWORD_LENGTH;

  return (
    <SubPage
      title={t("workspace_message_password_title")}
      onClose={onCancel}
      actions={[
        {
          text: t("workspace_set_password"),
          disabled: !ready,
          onClick: () => onSet(password),
          closeOnSuccess: true,
        },
        { type: "outline", text: t("common_cancel") },
      ]}
    >
      {(api) => (
        <div className="space-y-3">
          <div>
            <label
              htmlFor="message-password"
              className="text-muted-foreground mb-1 block text-xs"
            >
              {t("workspace_message_password_label")}
            </label>
            <div className="flex items-stretch gap-2">
              <input
                id="message-password"
                // `new-password`: keep password managers from offering the
                // user's saved logins here.
                type={revealed ? "text" : "password"}
                autoComplete="new-password"
                spellCheck={false}
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => {
                  // runAction no-ops while disabled (too short).
                  if (e.key === "Enter") api.runAction(0);
                }}
                className={`${INPUT_CLASS} h-9 flex-1 py-0`}
              />
              <button
                type="button"
                onClick={() => setRevealed((v) => !v)}
                aria-pressed={revealed}
                aria-label={
                  revealed
                    ? t("workspace_hide_password")
                    : t("workspace_show_password")
                }
                title={
                  revealed
                    ? t("workspace_hide_password")
                    : t("workspace_show_password")
                }
                className="bg-secondary text-muted-foreground hover:text-foreground hover:bg-accent focus:ring-ring inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg shadow-[inset_0_1px_0_rgb(255_255_255/0.07)] focus:ring-2 focus:outline-none"
              >
                {revealed ? (
                  <EyeOffIcon className="h-4 w-4" />
                ) : (
                  <EyeIcon className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          <p
            className={
              tooShort ? "text-bad text-xs" : "text-muted-foreground text-xs"
            }
            role={tooShort ? "alert" : undefined}
          >
            {tooShort
              ? tn("workspace_password_too_short", MIN_MESSAGE_PASSWORD_LENGTH)
              : tn(
                  "workspace_password_min_length",
                  MIN_MESSAGE_PASSWORD_LENGTH,
                )}
          </p>

          <p className="text-muted-foreground text-xs">
            {t("workspace_message_password_help")}
          </p>
        </div>
      )}
    </SubPage>
  );
}
