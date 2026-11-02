import { useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui";

import { useAsyncAction } from "~/hooks/useAsyncAction";
import { t } from "~/lib/i18n";
import type { StorageLocation } from "~/lib/storage/preferences";
import { ConfirmPage } from "./ConfirmPage";

/**
 * No vault where the bootstrap says, yet onboarding must NOT show
 * (`vault-state.ts`):
 *  - `elsewhere`: the plaintext sync pointer was changed; offer to point
 *    it back.
 *  - `ambiguous`: vaults in both areas, no local record. Picking silently
 *    would let a planted sync record hide a local vault, so the user picks.
 *  - `orphaned`: stores but no master protection. Only erase, behind its
 *    own confirmation, so onboarding can never do it.
 * Nothing is copied or deleted except by that erase.
 */
interface VaultProblemScreenProps {
  problem:
    | { kind: "elsewhere"; location: StorageLocation }
    | { kind: "ambiguous" }
    | { kind: "orphaned" };
  onUseLocation: (loc: StorageLocation) => Promise<void>;
  onErase: () => Promise<void>;
}

export function VaultProblemScreen({
  problem,
  onUseLocation,
  onErase,
}: VaultProblemScreenProps) {
  const [confirming, setConfirming] = useState(false);
  // One guard for both actions: an erase must not start under a re-point.
  const action = useAsyncAction(t("shared_something_went_wrong"));
  const { busy, error } = action;
  const erasingRef = useRef(false);

  if (confirming) {
    return (
      <ConfirmPage
        title={t("app_vault_erase_title")}
        confirmLabel={t("app_vault_erase_confirm")}
        // Not through `action`: ConfirmPage shows its own rejection.
        onConfirm={async () => {
          if (erasingRef.current || action.inFlight) return;
          erasingRef.current = true;
          try {
            await onErase();
          } finally {
            erasingRef.current = false;
          }
        }}
        onCancel={() => setConfirming(false)}
      >
        <p>{t("app_vault_erase_body")}</p>
      </ConfirmPage>
    );
  }

  const use = (loc: StorageLocation) => {
    if (erasingRef.current) return;
    void action.run(() => onUseLocation(loc));
  };

  const errorLine = error ? (
    <p role="alert" className="text-bad max-w-xs text-xs">
      {error.message}
    </p>
  ) : null;

  if (problem.kind === "ambiguous") {
    return (
      <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 overflow-y-auto p-6 text-center">
        <p className="text-warn text-sm font-medium">
          {t("app_vault_ambiguous_title")}
        </p>
        <p className="text-muted-foreground max-w-xs text-xs leading-relaxed">
          {t("app_vault_ambiguous_body")}
        </p>
        <Button variant="outline" disabled={busy} onClick={() => use("local")}>
          {t("app_vault_ambiguous_use_local")}
        </Button>
        <Button variant="outline" disabled={busy} onClick={() => use("sync")}>
          {t("app_vault_ambiguous_use_sync")}
        </Button>
        {errorLine}
      </div>
    );
  }

  const elsewhere = problem.kind === "elsewhere";
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 overflow-y-auto p-6 text-center">
      <p className="text-warn text-sm font-medium">
        {elsewhere
          ? t("app_vault_elsewhere_title")
          : t("app_vault_orphaned_title")}
      </p>
      <p className="text-muted-foreground max-w-xs text-xs leading-relaxed">
        {elsewhere
          ? problem.location === "local"
            ? t("app_vault_elsewhere_body_local")
            : t("app_vault_elsewhere_body_sync")
          : t("app_vault_orphaned_body")}
      </p>
      {elsewhere ? (
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => use(problem.location)}
        >
          {t("app_vault_elsewhere_use")}
        </Button>
      ) : (
        <Button variant="destructive" onClick={() => setConfirming(true)}>
          {t("app_vault_erase_title")}
        </Button>
      )}
      {errorLine}
    </div>
  );
}
