import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { WorkspaceIntake } from "../../components/workspace/useWorkspace";
import type { DropPayload } from "../../lib/drop-routing";
import type { WorkspaceAction } from "../../lib/messages";
import { CommandPalette } from "../../components/CommandPalette";
import { KeysView } from "../../components/keys/KeysView";
import { AppFooter } from "../../components/shared/AppFooter";
import { GlobalDropZone } from "../../components/shared/GlobalDropZone";
import { ImportOverlay } from "../../components/shared/ImportOverlay";
import { IntegrityBanner } from "../../components/shared/IntegrityBanner";
import { SettingsView } from "../../components/shared/SettingsView";
import { HistoryButton, TabBar } from "../../components/shared/TabBar";
import { VaultGate } from "../../components/shared/VaultGate";
import { HistoryPage } from "../../components/workspace/HistoryPage";
import { WorkspaceView } from "../../components/workspace/WorkspaceView";
import {
  useActionContext,
  useWorkspaceBridgeStore,
  WorkspaceBridgeContext,
} from "../../hooks/useActionContext";
import { useAutoLock } from "../../hooks/useAutoLock";
import { useContacts } from "../../hooks/useContacts";
import { useKeyring } from "../../hooks/useKeyring";
import { useMasterLock } from "../../hooks/useMasterLock";
import { NavContext, useNavState } from "../../hooks/useNav";
import { usePendingOperation } from "../../hooks/usePendingOperation";
import { usePreferences } from "../../hooks/usePreferences";
import { useReaderTabs } from "../../hooks/useReaderTabs";
import { VaultContext } from "../../hooks/useVault";
import { useVaultLifecycle } from "../../hooks/useVaultLifecycle";
import { useVaultServices } from "../../hooks/useVaultServices";
import { panelDropRules } from "../../lib/drop-routing";
import { preferencesStore } from "../../lib/storage/preferences-store";
import { protectionOf } from "../../lib/vault-phase";

const WORKSPACE_ACTIONS = new Set<string>([
  "encrypt",
  "decrypt",
  "sign",
  "verify",
]);

/** Bumped per drop so dropping the same files again re-applies them. */
let intakeNonce = 0;

export default function App() {
  const nav = useNavState();
  const prefs = usePreferences();
  const [vault, dispatchVault] = useVaultLifecycle();
  const { phase } = vault;
  const vaultOpen = phase.kind === "open";
  const services = useVaultServices(protectionOf(phase));
  const keyring = useKeyring();
  const contacts = useContacts();

  // Pending context-menu ops and Reply's reader tabs only while the vault
  // is open: consuming earlier would park the user's plaintext in React
  // state for the whole locked window (see usePendingOperation).
  const { pending, clearPending, checked } = usePendingOperation(vaultOpen);
  const { open: openReader, lockNow: lockReaders } = useReaderTabs(vaultOpen);

  const { lock, draftCiphertext, discardDraft, registerDraftSource } =
    useMasterLock({
      session: services.session,
      dispatchVault,
      clearPending,
      lockReaders,
    });
  const resetAutoLock = useAutoLock({
    session: services.session,
    vaultOpen,
    lock,
    autoLockEnabled: prefs.autoLockEnabled,
    autoLockMinutes: prefs.autoLockMinutes,
    lockOnTabAway: prefs.lockOnTabAway,
  });
  const lockNow = useCallback(() => lock(), [lock]);

  // A drop routed to the workspace.
  const [intake, setIntake] = useState<WorkspaceIntake | null>(null);
  const clearIntake = useCallback(() => setIntake(null), []);

  const { openImport, showTab } = nav;
  useEffect(() => {
    if (!pending) return;
    if (
      pending.action === "import-public" ||
      pending.action === "import-private"
    ) {
      openImport({ prefill: pending.text });
      clearPending();
      return;
    }
    // A text-less keyboard mode command must not discard a locked draft.
    if (pending.text) discardDraft();
    showTab("workspace");
  }, [pending, clearPending, openImport, showTab, discardDraft]);

  const toWorkspace = useCallback(
    ({ files, text }: DropPayload) => {
      setIntake({ files, text, nonce: ++intakeNonce });
      discardDraft();
      showTab("workspace");
    },
    [discardDraft, showTab],
  );
  const dropRules = useMemo(
    () =>
      panelDropRules({
        importKey: (armored) => openImport({ prefill: armored }),
        workspace: toWorkspace,
      }),
    [openImport, toWorkspace],
  );

  // The workspace publishes to this store and only the palette listens,
  // so a workspace change never re-renders the App.
  const workspaceBridge = useWorkspaceBridgeStore();
  // The palette registers its open() so the footer's mod+K hint can pop it.
  const openPaletteRef = useRef<(() => void) | null>(null);
  const bindPaletteOpen = useCallback((fn: () => void) => {
    openPaletteRef.current = fn;
  }, []);

  return (
    <VaultContext value={services}>
      <NavContext value={nav}>
        <VaultGate
          vault={vault}
          dispatchVault={dispatchVault}
          services={services}
          lock={lockNow}
          resetAutoLock={resetAutoLock}
        >
          <WorkspaceBridgeContext value={workspaceBridge}>
            <GlobalDropZone rules={dropRules}>
              <div className="flex h-screen flex-col">
                <TabBar
                  activeTab={nav.tab}
                  onTabChange={showTab}
                  trailing={
                    // Never-cache means no history, so no viewer either.
                    nav.tab === "workspace" && !prefs.neverCacheKeys ? (
                      <HistoryButton onClick={nav.openHistory} />
                    ) : undefined
                  }
                />
                {/* A sealed store came back older than this device last
                    saw it, or went missing (lib/storage/integrity.ts). */}
                <IntegrityBanner
                  syncVault={prefs.storageLocation === "sync"}
                  // Settings sat at the strictest preset until acknowledged.
                  onAcknowledged={() => void preferencesStore.reload()}
                />
                <Palette
                  tab={nav.tab}
                  counts={{
                    ownKeys: keyring.keys.length,
                    contacts: contacts.contacts.length,
                  }}
                  neverCacheKeys={prefs.neverCacheKeys}
                  nav={nav}
                  lockNow={lockNow}
                  bindOpen={bindPaletteOpen}
                />
                <ImportOverlay />
                {nav.historyOpen && (
                  <HistoryPage
                    enabled={prefs.historyEnabled}
                    onClose={nav.closeHistory}
                  />
                )}

                <main
                  className="flex min-h-0 flex-1 flex-col overflow-y-auto p-4"
                  role="tabpanel"
                  id={`tabpanel-${nav.tab}`}
                  aria-labelledby={`tab-${nav.tab}`}
                >
                  <div
                    className={nav.tab === "workspace" ? "h-full" : "hidden"}
                  >
                    <WorkspaceView
                      vaultSettling={
                        (vaultOpen && phase.opening) ||
                        keyring.loading ||
                        contacts.loading
                      }
                      awaitingPendingOp={!checked}
                      onOpenReply={openReader}
                      pendingAction={
                        pending && WORKSPACE_ACTIONS.has(pending.action)
                          ? {
                              action: pending.action as WorkspaceAction,
                              text: pending.text,
                            }
                          : null
                      }
                      onClearPending={clearPending}
                      restoreDraft={draftCiphertext}
                      onDraftRestored={discardDraft}
                      onRegisterDraftSource={registerDraftSource}
                      intake={intake}
                      onIntakeConsumed={clearIntake}
                    />
                  </div>
                  {nav.tab === "keys" && <KeysView />}
                  {nav.tab === "settings" && <SettingsView />}
                </main>

                <AppFooter onOpenPalette={() => openPaletteRef.current?.()} />
              </div>
            </GlobalDropZone>
          </WorkspaceBridgeContext>
        </VaultGate>
      </NavContext>
    </VaultContext>
  );
}

/** The palette over the live action context. Subscribes to the workspace
 *  bridge itself, so workspace changes re-render this, not the App. */
function Palette({
  bindOpen,
  ...args
}: Parameters<typeof useActionContext>[0] & {
  bindOpen: (open: () => void) => void;
}) {
  return <CommandPalette ctx={useActionContext(args)} bindOpen={bindOpen} />;
}
