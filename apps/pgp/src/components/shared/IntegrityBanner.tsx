import { useSyncExternalStore } from "react";
import { TriangleAlertIcon, XIcon } from "lucide-react";

import { STORAGE_INTEGRITY, STORAGE_SETTINGS } from "~/lib/constants";
import { t } from "~/lib/i18n";
import {
  acknowledgeIntegrityIssues,
  integrityIssues,
  subscribeIntegrity,
} from "~/lib/storage/integrity";

/**
 * Rollback/missing-store warning. A warning, not a stop: refusing to load
 * would lock users out on every false positive, and the two things a
 * rollback could undo are held anyway (revocations stick, missing settings
 * read as strictest). Two synced devices can trigger it too
 * (`lib/storage/integrity.ts`). A lost ledger or older settings copy
 * repeats every unlock until dismissed here, hence `onAcknowledged`.
 */
export function IntegrityBanner({
  onAcknowledged,
  syncVault = false,
}: {
  onAcknowledged?: () => void;
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
