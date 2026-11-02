import type { ReactNode } from "react";
import { useCallback, useEffect, useRef } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { VaultServices } from "../../hooks/useVault";
import type { VaultEvent, VaultLifecycle } from "../../lib/vault-phase";
import type { MasterPrfLoan } from "./MasterUnlockScreen";
import { useContacts } from "../../hooks/useContacts";
import { useKeyring } from "../../hooks/useKeyring";
import { normalizeCrxPadding } from "../../lib/crx/storage";
import { t } from "../../lib/i18n";
import {
  masterPasskeyOf,
  partitionByMasterSeal,
} from "../../lib/protection/vault-unlock";
import { normalizeContactsPadding } from "../../lib/storage/contacts";
import { getKeyring, normalizeKeyringPadding } from "../../lib/storage/keyring";
import { getMasterProtection } from "../../lib/storage/master-protection";
import {
  getPreferences,
  migrateLegacyPreferences,
} from "../../lib/storage/preferences";
import { preferencesStore } from "../../lib/storage/preferences-store";
import { refreshVaultLists } from "../../lib/storage/vault-lists";
import {
  adoptVaultLocation,
  eraseVault,
  resolveVaultState,
} from "../../lib/storage/vault-state";
import { AppFooter } from "./AppFooter";
import { MasterUnlockScreen } from "./MasterUnlockScreen";
import { OnboardingFlow } from "./OnboardingFlow";
import { VaultProblemScreen } from "./VaultProblemScreen";

interface VaultGateProps {
  vault: VaultLifecycle;
  dispatchVault: (event: VaultEvent) => VaultLifecycle;
  services: VaultServices;
  lock: () => Promise<void>;
  resetAutoLock: () => void;
  /** The open vault's UI. */
  children: ReactNode;
}

/**
 * Everything before the vault is open: reading what is stored, the
 * problem / onboarding / lock screens, the unlock sequence, and the
 * unreadable-vault stop. Renders `children` only once the vault is open
 * and its stores read.
 */
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

  /** Decide, from what is actually stored, whether there is a vault. */
  const load = useCallback(async () => {
    // The bootstrap reads while locked; settings read as defaults until
    // the unlock re-reads them.
    await preferencesStore.reload();
    dispatchVault({ type: "resolved", vault: await resolveVaultState() });
  }, [dispatchVault]);

  useEffect(() => {
    void load();
  }, [load]);

  // Once open: settings become readable, and pre-padding blobs are
  // upgraded now rather than on their next write (best-effort).
  useEffect(() => {
    if (!open) return;
    void preferencesStore.reload();
    const ignore = () => undefined;
    void normalizeKeyringPadding().catch(ignore);
    void normalizeContactsPadding().catch(ignore);
    void normalizeCrxPadding().catch(ignore);
  }, [open]);

  // Focus the message box on the first open only (later tab switches must
  // not steal focus), deferred a tick for the workspace to mount.
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
    // Legacy-settings migration first: its gate refuses once a local
    // store carries a generation, which the contacts backfill stamps.
    await migrateLegacyPreferences().catch(() => undefined);
    const { generation } = dispatchVault({ type: "unlocking" });
    resetAutoLock();
    const listsRead = refreshVaultLists();
    // "Unlock keys with the vault", off the same ceremony. The preference
    // is read from storage (state still holds the locked-time default),
    // inside the batch so a lock landing meanwhile cancels it. `prf` is on
    // loan until this resolves.
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
        // Best-effort: the vault is open; keys just stay locked.
      }
    }
    await listsRead;
    dispatchVault({ type: "settled", generation });
  };

  // Nothing renders until what is stored is known: a main tree mounted
  // early would be torn down by the lock screen, state and all.
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

  // The session cannot open the stores (failed AEAD tag). Showing the
  // normal UI would say "your keys are gone", which is false. Reachable
  // via the passkey master, which has no canary; the copy deliberately
  // does not guess why, since a wrong PRF and a corrupt blob look alike.
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
