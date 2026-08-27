import { useState } from "react";
import { EyeIcon, EyeOffIcon } from "lucide-react";

import { INPUT_CLASS } from "../../lib/utils/styles";
import { SubPage } from "../shared/SubPage";
import { MIN_MESSAGE_PASSWORD_LENGTH } from "./useWorkspaceState";

interface MessagePasswordPageProps {
  /** Applied on save. Never called with a password shorter than
   *  {@link MIN_MESSAGE_PASSWORD_LENGTH}. */
  onSet: (password: string) => void;
  onCancel: () => void;
}

/**
 * Where the symmetric-encryption password is typed.
 *
 * A DIALOG RATHER THAN AN INLINE ROW, and that is the whole reason this
 * file exists: revealing two fields under the badge row pushed the
 * message box, the recipient picker and the action bar down the panel
 * every time the badge was pressed. `SubPage` is this app's one modal
 * surface (see its doc comment), so the password gets the same treatment
 * as every other thing that used to be a dialog.
 *
 * ONE FIELD, NOT TWO. A typo here is silent and permanent -- the message
 * encrypts cleanly and opens for nobody, including the sender -- so
 * something has to guard it. A confirm field is the usual answer; a
 * reveal toggle is the cheaper one, and unlike a confirm field it also
 * catches the case where the user typed the same wrong thing twice
 * (a stuck modifier, the wrong keyboard layout).
 *
 * KEYBOARD-ONLY THROUGHOUT. Tab reaches the field, the reveal toggle and
 * both footer buttons in that order -- the reveal is a real `<button>`,
 * not an icon with a click handler, so it is tab-reachable and
 * space/enter-activatable for free. Enter in the field runs the primary
 * action; Escape closes (both inherited from `SubPage`/`useSlideOver`).
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
      title="Password for this message"
      onClose={onCancel}
      actions={[
        {
          text: "Set password",
          disabled: !ready,
          onClick: () => onSet(password),
          closeOnSuccess: true,
        },
        { type: "outline", text: "Cancel" },
      ]}
    >
      {(api) => (
        <div className="space-y-3">
          <div>
            <label
              htmlFor="message-password"
              className="text-muted-foreground mb-1 block text-xs"
            >
              Message password
            </label>
            <div className="flex items-stretch gap-2">
              <input
                id="message-password"
                // Toggling `type` is what the reveal does. `new-password`
                // keeps a password manager from offering the user's own
                // saved credentials for a field that is not a login.
                type={revealed ? "text" : "password"}
                autoComplete="new-password"
                spellCheck={false}
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => {
                  // runAction no-ops while busy or disabled, so Enter on
                  // a too-short password does nothing rather than
                  // submitting one.
                  if (e.key === "Enter") api.runAction(0);
                }}
                className={`${INPUT_CLASS} h-9 flex-1 py-0`}
              />
              <button
                type="button"
                onClick={() => setRevealed((v) => !v)}
                aria-pressed={revealed}
                aria-label={revealed ? "Hide password" : "Show password"}
                title={revealed ? "Hide password" : "Show password"}
                className="border-border text-muted-foreground hover:text-foreground hover:bg-accent/50 focus:ring-ring inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border focus:ring-2 focus:outline-none"
              >
                {revealed ? (
                  <EyeOffIcon className="h-4 w-4" />
                ) : (
                  <EyeIcon className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          {/* States the requirement rather than only complaining once it
              is missed: an empty field is one waiting to be filled, not
              an error. */}
          <p
            className={
              tooShort
                ? "text-destructive text-xs"
                : "text-muted-foreground text-xs"
            }
            role={tooShort ? "alert" : undefined}
          >
            {tooShort
              ? `Use at least ${MIN_MESSAGE_PASSWORD_LENGTH} characters.`
              : `At least ${MIN_MESSAGE_PASSWORD_LENGTH} characters.`}
          </p>

          <p className="text-muted-foreground text-xs">
            Anyone with this password can read the message, so send it another
            way - not alongside the message itself. It is added to the message
            on top of any recipients you have picked; either can open it.
          </p>
        </div>
      )}
    </SubPage>
  );
}
