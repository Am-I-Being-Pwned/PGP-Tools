import { useSyncExternalStore } from "react";
import { TriangleAlertIcon, XIcon } from "lucide-react";

import { STORAGE_INTEGRITY, STORAGE_SETTINGS } from "../../lib/constants";
import { t } from "../../lib/i18n";
import {
  acknowledgeIntegrityIssues,
  integrityIssues,
  subscribeIntegrity,
} from "../../lib/storage/integrity";

/**
 * "Stored data was rolled back or is missing" -- one amber band under the
 * tab bar, shown while the vault is open, until dismissed.
 *
 * Deliberately a warning and not a stop: the stores still load (the
 * owner's call -- refusing would turn every false positive into a
 * locked-out user), and the two things a rollback could quietly undo are
 * held regardless: a revoked contact stays revoked, and missing settings
 * read as the strictest preset. The copy says what can cause it besides
 * an attacker, because one thing can: two synced devices changing the
 * same store at once (see `lib/storage/integrity.ts`).
 *
 * A store saved with NO generation after this device recorded one
 * (`no-generation`) gets its own, softer line instead of the main one:
 * that is what a 2.0.x build on another device of a sync vault leaves
 * behind, as well as what a rollback to a pre-generation copy looks
 * like, and the copy says both. On a sync vault the "missing" case gets
 * an extra line too, since such a build deletes a store it empties.
 *
 * Dismissing forgets this panel's reports; a store that is still behind
 * reports again the next time the panel opens. A lost ledger (deleted,
 * or unreadable) and an older settings copy are the exceptions: they
 * repeat on every unlock until dismissed here, and hold the settings at
 * the strictest preset until then, so dismissing one calls
 * `onAcknowledged` for the panel to re-read them.
 */
export function IntegrityBanner({
  onAcknowledged,
  syncVault = false,
}: {
  onAcknowledged?: () => void;
  /** The vault lives in synced storage (wording only). */
  syncVault?: boolean;
}) {
  const issues = useSyncExternalStore(subscribeIntegrity, integrityIssues);
  if (issues.length === 0) return null;
  const settingsMissing = issues.some(
    (i) => i.store === STORAGE_SETTINGS && i.kind === "missing",
  );
  const settingsUnreadable = issues.some(
    (i) => i.store === STORAGE_SETTINGS && i.kind === "unreadable",
  );
  const settingsHeld = issues.some(
    (i) =>
      i.store === STORAGE_SETTINGS &&
      (i.kind === "rolled-back" || i.kind === "no-generation"),
  );
  const ledgerLost = issues.some((i) => i.store === STORAGE_INTEGRITY);
  const noGeneration = issues.some((i) => i.kind === "no-generation");
  const hard = issues.some((i) => i.kind !== "no-generation");
  const storeMissing = issues.some(
    (i) => i.kind === "missing" && i.store !== STORAGE_INTEGRITY,
  );

  return (
    <div
      role="alert"
      className="bg-warn/12 text-warn mx-2 mt-2 flex items-start gap-2 rounded-xl p-3 text-xs"
    >
      <TriangleAlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1 space-y-1 leading-relaxed">
        {hard && <p>{t("app_integrity_warning")}</p>}
        {hard && syncVault && storeMissing && (
          <p>{t("app_integrity_missing_sync")}</p>
        )}
        {noGeneration && <p>{t("app_integrity_no_generation")}</p>}
        {settingsHeld && <p>{t("app_integrity_settings_held")}</p>}
        {settingsMissing && <p>{t("app_integrity_settings_strict")}</p>}
        {settingsUnreadable && <p>{t("app_integrity_settings_unreadable")}</p>}
        {ledgerLost && <p>{t("app_integrity_ledger_lost")}</p>}
      </div>
      <button
        type="button"
        onClick={() => {
          void acknowledgeIntegrityIssues().then((cleared) => {
            if (cleared) onAcknowledged?.();
          });
        }}
        title={t("app_integrity_dismiss")}
        aria-label={t("app_integrity_dismiss")}
        className="hover:bg-warn/12 -m-1 flex size-6 shrink-0 items-center justify-center rounded-md"
      >
        <XIcon className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
