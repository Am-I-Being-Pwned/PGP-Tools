import { useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { StorageLocation } from "../../lib/storage/preferences";
import { presentError } from "../../lib/errors/present";
import { t } from "../../lib/i18n";
import { ConfirmPage } from "./ConfirmPage";

/**
 * The two states in which the panel must NOT show onboarding, although
 * there is no vault where the bootstrap says to look (`vault-state.ts`):
 *
 *  - `elsewhere`: the vault is in the other storage area. The location
 *    pointer is plaintext in sync and was changed under it -- by another
 *    device, or by someone signed in to the Google account. Offer to point
 *    it back; nothing is copied or deleted.
 *  - `ambiguous`: a master protection in BOTH areas, and this device has
 *    no record of which is its own (first run after an upgrade, say).
 *    Picking one silently is how a planted record in sync used to hide a
 *    local vault, so the user chooses; nothing is copied or deleted, and
 *    the lock screen offers the other one if the choice will not open.
 *  - `orphaned`: sealed stores, but no master protection anywhere. Nothing
 *    can open them any more, and a new vault cannot be started over them
 *    (its stores would collide with blobs it cannot read), so the only way
 *    forward is to erase -- behind its own confirmation, so onboarding can
 *    never do it by itself.
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A ref, not the state: two clicks in one frame both see `busy` false.
  const runningRef = useRef(false);

  if (confirming) {
    return (
      <ConfirmPage
        title={t("app_vault_erase_title")}
        confirmLabel={t("app_vault_erase_confirm")}
        // ConfirmPage shows a rejection and disables its buttons while
        // this runs; the ref also stops a second erase from starting.
        onConfirm={async () => {
          if (runningRef.current) return;
          runningRef.current = true;
          try {
            await onErase();
          } finally {
            runningRef.current = false;
          }
        }}
        onCancel={() => setConfirming(false)}
      >
        <p>{t("app_vault_erase_body")}</p>
      </ConfirmPage>
    );
  }

  const use = (loc: StorageLocation) => {
    if (runningRef.current) return;
    runningRef.current = true;
    setBusy(true);
    setError(null);
    onUseLocation(loc)
      .catch((e: unknown) => {
        setError(presentError(e, t("shared_something_went_wrong")).message);
      })
      .finally(() => {
        runningRef.current = false;
        setBusy(false);
      });
  };

  const errorLine = error ? (
    <p role="alert" className="text-bad max-w-xs text-xs">
      {error}
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
