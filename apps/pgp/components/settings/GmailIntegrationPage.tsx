import { useState } from "react";
import { CheckIcon, InfoIcon, ShieldCheckIcon } from "lucide-react";

import { Switch } from "@amibeingpwned/ui/switch";

import { t } from "../../lib/i18n";
import { SubPage } from "../shared/SubPage";

/**
 * The Gmail add-on's on/off switch, and the page that says what turning
 * it on actually means -- in both directions. The switch is the browser
 * permission (see `useGmailAccess`): it is the one place mail.google.com
 * access is ever asked for, and Chrome's own prompt follows the click.
 *
 * The copy is split into what it does and what it never does on purpose:
 * "read and change all your data on mail.google.com" is the sentence
 * Chrome will show, and the second list is the honest answer to it.
 */
export function GmailIntegrationPage({
  onClose,
  enabled,
  onEnable,
  onDisable,
}: {
  onClose: () => void;
  enabled: boolean | null;
  onEnable: () => Promise<boolean>;
  onDisable: () => Promise<void>;
}) {
  const [denied, setDenied] = useState(false);

  return (
    <SubPage title={t("gmail_settings_title")} onClose={onClose}>
      <div className="space-y-5">
        <p className="text-muted-foreground text-sm">
          {t("gmail_settings_pitch")}
        </p>

        <label className="border-border flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">{t("gmail_settings_toggle_title")}</span>
            <p className="text-muted-foreground text-xs">
              {t("gmail_settings_toggle_desc")}
            </p>
          </div>
          <Switch
            checked={enabled === true}
            disabled={enabled === null}
            onCheckedChange={(v) => {
              setDenied(false);
              // Synchronous from the click: the prompt needs the gesture.
              if (v) {
                void onEnable().then((granted) => setDenied(!granted));
              } else {
                void onDisable().catch(() => undefined);
              }
            }}
          />
        </label>
        {denied && (
          <p className="text-muted-foreground -mt-3 text-xs" role="status">
            {t("gmail_settings_denied")}
          </p>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            {t("gmail_settings_does_title")}
          </h3>
          <ul className="space-y-1.5">
            {(
              [
                "gmail_settings_does_read",
                "gmail_settings_does_compose",
                "gmail_settings_does_recipients",
                "gmail_settings_does_attachments",
              ] as const
            ).map((key) => (
              <li key={key} className="flex gap-2 text-xs">
                <CheckIcon className="text-primary mt-px h-3.5 w-3.5 shrink-0" />
                <span>{t(key)}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            {t("gmail_settings_never_title")}
          </h3>
          <ul className="space-y-1.5">
            {(
              [
                "gmail_settings_never_plaintext",
                "gmail_settings_never_account",
                "gmail_settings_never_keys",
              ] as const
            ).map((key) => (
              <li key={key} className="flex gap-2 text-xs">
                <ShieldCheckIcon className="text-primary mt-px h-3.5 w-3.5 shrink-0" />
                <span>{t(key)}</span>
              </li>
            ))}
          </ul>
        </section>

        <div className="border-border bg-muted/40 space-y-2 rounded-md border p-3">
          <p className="flex gap-2 text-xs">
            <InfoIcon className="text-muted-foreground mt-px h-3.5 w-3.5 shrink-0" />
            <span>{t("gmail_settings_draft_note")}</span>
          </p>
          <p className="flex gap-2 text-xs">
            <InfoIcon className="text-muted-foreground mt-px h-3.5 w-3.5 shrink-0" />
            <span>{t("gmail_settings_limits")}</span>
          </p>
        </div>
      </div>
    </SubPage>
  );
}
