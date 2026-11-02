import { useCallback, useEffect, useRef, type ReactNode } from "react";

import { Button } from "@amibeingpwned/ui";

import { useContacts } from "~/hooks/useContacts";
import { useKeyring } from "~/hooks/useKeyring";
import type { VaultServices } from "~/hooks/useVault";
import { normalizeCrxPadding } from "~/lib/crx/storage";
import { t } from "~/lib/i18n";
import {
  masterPasskeyOf,
  partitionByMasterSeal,
} from "~/lib/protection/vault-unlock";
import { normalizeContactsPadding } from "~/lib/storage/contacts";
import { getKeyring, normalizeKeyringPadding } from "~/lib/storage/keyring";
import { getMasterProtection } from "~/lib/storage/master-protection";
import {
  getPreferences,
  migrateLegacyPreferences,
} from "~/lib/storage/preferences";
import { preferencesStore } from "~/lib/storage/preferences-store";
import { refreshVaultLists } from "~/lib/storage/vault-lists";
import {
  adoptVaultLocation,
  eraseVault,
  resolveVaultState,
} from "~/lib/storage/vault-state";
import type { VaultEvent, VaultLifecycle } from "~/lib/vault-phase";
import { AppFooter } from "./AppFooter";
import { MasterUnlockScreen, type MasterPrfLoan } from "./MasterUnlockScreen";
import { OnboardingFlow } from "./OnboardingFlow";
import { VaultProblemScreen } from "./VaultProblemScreen";

interface VaultGateProps {
  vault: VaultLifecycle;
  dispatchVault: (event: VaultEvent) => VaultLifecycle;
  services: VaultServices;
  lock: () => Promise<void>;
  resetAutoLock: () => void;
  children: ReactNode;
}

/** Everything before the vault is open; renders `children` only once open and read. */
export function VaultGate({
  vault,
  dispatchVault,
  services,
  lock,
  resetAutoLock,
  children,
}: VaultGateProps) {
  const { phase, alternate } = vault;
  const { session } = services;
  const keyring = useKeyring();
  const contacts = useContacts();
  const open = phase.kind === "open";

  const load = useCallback(async () => {
    // Read while locked: settings are defaults until the unlock re-reads them.
    await preferencesStore.reload();
    dispatchVault({ type: "resolved", vault: await resolveVaultState() });
  }, [dispatchVault]);

  useEffect(() => {
    void load();
  }, [load]);

  // Best-effort upgrade of pre-padding blobs.
  useEffect(() => {
    if (!open) return;
    void preferencesStore.reload();
    const ignore = () => undefined;
    void normalizeKeyringPadding().catch(ignore);
    void normalizeContactsPadding().catch(ignore);
    void normalizeCrxPadding().catch(ignore);
  }, [open]);

  // First open only: later tab switches must not steal focus.
  const focusedRef = useRef(false);
  useEffect(() => {
    if (focusedRef.current || !open) return;
    focusedRef.current = true;
    const timer = setTimeout(
      () => document.getElementById("pgp-input")?.focus(),
      0,
    );
    return () => clearTimeout(timer);
  }, [open]);

  const onUnlocked = async (prf?: MasterPrfLoan) => {
    if (phase.kind !== "locked") return;
    // Must precede the contacts backfill, whose generation stamp blocks it.
    await migrateLegacyPreferences().catch(() => undefined);
    const { generation } = dispatchVault({ type: "unlocking" });
    resetAutoLock();
    const listsRead = refreshVaultLists();
    // Preference read from storage (state holds the locked-time default),
    // inside the batch so a concurrent lock cancels it. `prf` is on loan.
    const master = masterPasskeyOf(phase.protection);
    if (prf && master) {
      try {
        await session.unlockAllWithMasterPrf(async () => {
          const p = await getPreferences();
          // Never-cache wins even over an inconsistent stored pair.
          if (!p.unlockKeysOnOpen || p.neverCacheKeys) return [];
          const keys = await getKeyring().catch(() => []);
          return partitionByMasterSeal(keys, master).eligible;
        }, prf.prfOutput);
      } catch {
        // Best-effort: keys just stay locked.
      }
    }
    await listsRead;
    dispatchVault({ type: "settled", generation });
  };

  // A main tree mounted early would be torn down by the lock screen.
  if (phase.kind === "loading") return null;

  if (phase.kind === "problem") {
    return (
      <Screen className="flex flex-col">
        <VaultProblemScreen
          problem={phase.problem}
          onUseLocation={async (loc) => {
            await adoptVaultLocation(loc);
            await load();
          }}
          onErase={async () => {
            await eraseVault();
            await load();
          }}
        />
      </Screen>
    );
  }

  if (phase.kind === "onboarding") {
    return (
      <Screen>
        <OnboardingFlow
          onComplete={async () => {
            dispatchVault({
              type: "onboarded",
              protection: await getMasterProtection(),
            });
            void preferencesStore.reload();
            void refreshVaultLists();
          }}
          addKey={services.addKey}
          cacheKey={services.cacheKeys}
          onKeyCached={services.onKeyCached}
        />
      </Screen>
    );
  }

  if (phase.kind === "locked") {
    return (
      <Screen>
        <MasterUnlockScreen
          masterProtection={phase.protection}
          autoLocked={phase.autoLocked}
          alternate={alternate ?? undefined}
          onUseAlternate={async () => {
            if (!alternate) return;
            await adoptVaultLocation(alternate);
            await load();
          }}
          onUnlocked={onUnlocked}
        />
      </Screen>
    );
  }

  // Failed AEAD tag (passkey master has no canary). The normal UI would
  // falsely say "your keys are gone"; wrong PRF and corrupt blob look alike.
  const readError = keyring.error ?? contacts.error;
  if (phase.protection && readError) {
    return (
      <Screen className="flex flex-col items-center justify-center gap-3 p-6 text-center">
        <p className="text-destructive text-sm font-medium">
          {t("app_vault_unreadable_title")}
        </p>
        <p className="text-muted-foreground max-w-xs text-xs leading-relaxed">
          {phase.protection.method === "passkey"
            ? t("app_vault_unreadable_body_passkey")
            : t("app_vault_unreadable_body")}
        </p>
        <Button variant="outline" onClick={() => void lock()}>
          {t("app_vault_lock_retry")}
        </Button>
      </Screen>
    );
  }

  return children;
}

function Screen({
  className = "",
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex h-screen flex-col">
      <main className={`min-h-0 flex-1 overflow-y-auto ${className}`}>
        {children}
      </main>
      <AppFooter />
    </div>
  );
}
