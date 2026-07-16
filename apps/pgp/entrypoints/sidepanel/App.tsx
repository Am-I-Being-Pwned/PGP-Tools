import { useCallback, useEffect, useRef, useState } from "react";
import { SettingsIcon } from "lucide-react";

import type { WorkspaceIntake } from "../../components/workspace/useWorkspaceState";
import type { WorkspaceOpsBridge } from "../../hooks/useActionContext";
import type { DropRule } from "../../lib/drop-routing";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { MasterProtection } from "../../lib/storage/master-protection";
import type {
  AutoLockTimeout,
  PgpPreferences,
  StorageLocation,
} from "../../lib/storage/preferences";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import { CommandPalette } from "../../components/CommandPalette";
import { KeysView } from "../../components/keys/KeysView";
import { AppFooter } from "../../components/shared/AppFooter";
import { GlobalDropZone } from "../../components/shared/GlobalDropZone";
import { MasterUnlockScreen } from "../../components/shared/MasterUnlockScreen";
import { OnboardingFlow } from "../../components/shared/OnboardingFlow";
import { SettingsView } from "../../components/shared/SettingsView";
import { HistoryPage } from "../../components/workspace/HistoryPage";
import { WorkspaceView } from "../../components/workspace/WorkspaceView";
import { useActionContext } from "../../hooks/useActionContext";
import { useContacts } from "../../hooks/useContacts";
import { useCrxKeys } from "../../hooks/useCrxKeys";
import { useKeyring } from "../../hooks/useKeyring";
import { useKeySession } from "../../hooks/useKeySession";
import { usePendingOperation } from "../../hooks/usePendingOperation";
import {
  SESSION_PENDING_OP,
  STORAGE_PREFERENCES,
  STORAGE_SETTINGS,
} from "../../lib/constants";
import { normalizeCrxPadding } from "../../lib/crx/storage";
import { looksLikeKey, readAllFilesText } from "../../lib/drop-routing";
import * as wasmApi from "../../lib/pgp/wasm";
import { normalizeContactsPadding } from "../../lib/storage/contacts";
import { normalizeKeyringPadding } from "../../lib/storage/keyring";
import { getMasterProtection } from "../../lib/storage/master-protection";
import { getPreferences, savePreferences } from "../../lib/storage/preferences";
import { toast } from "../../lib/toast";
import {
  draftHasContent,
  encryptWorkspaceDraft,
} from "../../lib/workspace-draft";

type Tab = "workspace" | "keys" | "settings";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("workspace");
  const [advancedMode, setAdvancedMode] = useState(false);
  const [storageLocation, setStorageLocation] =
    useState<StorageLocation>("local");
  const [autoLockEnabled, setAutoLockEnabled] = useState(true);
  const [autoLockMinutes, setAutoLockMinutes] = useState<AutoLockTimeout>(15);
  const [neverCacheKeys, setNeverCacheKeys] = useState(false);
  const [autoDownloadFiles, setAutoDownloadFiles] = useState(false);
  const [autoDownloadText, setAutoDownloadText] = useState(false);
  const [lockOnTabAway, setLockOnTabAway] = useState(false);
  const [crxSigningEnabled, setCrxSigningEnabled] = useState(false);
  // The user's preferred own key (null = implicit first-key default).
  // Owned here so Keys (badge/action) and the workspace (self-key and
  // sign/decrypt preselection) stay in sync without a prefs re-read.
  const [defaultKeyId, setDefaultKeyId] = useState<string | null>(null);
  const [onboardingComplete, setOnboardingComplete] = useState<boolean | null>(
    null,
  );
  const [importPrefill, setImportPrefill] = useState<string | null>(null);
  const [encryptToKeyId, setEncryptToKeyId] = useState<string | null>(null);
  // A file/text drop routed to the workspace by the global dropzone. The
  // nonce bumps on every drop so re-dropping the same files re-applies.
  const [workspaceIntake, setWorkspaceIntake] =
    useState<WorkspaceIntake | null>(null);
  const workspaceIntakeNonce = useRef(0);
  // True once a pending context-menu op has been routed to a tab.
  // The preferences-loading effect (mount-only) consults this ref to
  // avoid overriding our routed tab with the stale saved value when
  // getPreferences resolves after our pending route.
  const pendingRoutedRef = useRef(false);

  // Master protection state
  const [masterProtection, setMasterProtection] =
    useState<MasterProtection | null>(null);
  // Separate from `masterProtection` (which is null in TWO cases: not
  // loaded yet, and no protection set up). Without this flag the main
  // tree mounts during the brief load window, then unmounts when the
  // lock screen kicks in, blowing away any local component state
  // that was building up in parallel (e.g. KeysView's open-dialog
  // state set by the context-menu prefill flow).
  const [masterProtectionLoaded, setMasterProtectionLoaded] = useState(false);
  const [masterUnlocked, setMasterUnlocked] = useState(false);
  const masterLockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const keyring = useKeyring();
  const session = useKeySession({
    autoLockEnabled,
    autoLockMinutes,
    neverCacheKeys,
  });
  const contacts = useContacts();
  const crxKeys = useCrxKeys();
  const { pending, clearPending } = usePendingOperation();

  // True when the most recent master-lock was system-initiated (idle
  // timer, visibility hidden, OS idle). Used to suppress the
  // MasterUnlockScreen's auto-passkey-prompt -- a re-lock should not
  // pop a system passkey dialog without an explicit user action.
  const [masterAutoLocked, setMasterAutoLocked] = useState(false);

  // Workspace-draft persistence across lock cycles. WorkspaceView pushes
  // its current state into `latestDraftRef` on every change; on master
  // lock we encrypt that snapshot under the in-WASM draft key and stash
  // the ciphertext here so the workspace can rehydrate after re-unlock.
  // The plaintext draft never survives the lock event in the JS heap.
  const latestDraftRef = useRef<WorkspaceDraft | null>(null);
  const [draftCiphertext, setDraftCiphertext] = useState<Uint8Array | null>(
    null,
  );

  // Stable callbacks so WorkspaceView's effect deps don't churn.
  const handleDraftChange = useCallback((draft: WorkspaceDraft | null) => {
    latestDraftRef.current = draft;
  }, []);
  const handleDraftRestored = useCallback(() => {
    setDraftCiphertext(null);
  }, []);

  const doMasterLock = useCallback(
    async (auto = false) => {
      // Encrypt + stash the workspace draft before flipping
      // masterUnlocked (which unmounts the workspace). On error, lock
      // anyway -- a lost draft is preferable to a failed lock.
      const draft = latestDraftRef.current;
      if (draft && draftHasContent(draft)) {
        try {
          await wasmApi.initDraftSessionIfUnset();
          const ct = await encryptWorkspaceDraft(draft);
          setDraftCiphertext(ct);
        } catch {
          /* lock anyway */
        }
      }
      latestDraftRef.current = null;

      // Wipe any unconsumed context-menu pending op. Without this a
      // selection that landed during an unlocked session could sit
      // in storage.session and surface on the next unlock.
      void chrome.storage.session.remove(SESSION_PENDING_OP);

      // Password-master path leaves the contacts session key in WASM
      // (passkey path already drops it after each decrypt).
      void wasmApi.dropContactsSession();
      setMasterAutoLocked(auto);
      setMasterUnlocked(false);
      session.lockAll();
    },
    [session],
  );

  const resetMasterLockTimer = useCallback(() => {
    if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    if (!autoLockEnabled) return;
    masterLockTimerRef.current = setTimeout(
      () => void doMasterLock(true),
      autoLockMinutes * 60 * 1000,
    );
  }, [autoLockEnabled, autoLockMinutes, doMasterLock]);

  useEffect(() => {
    if (!masterUnlocked) return;
    resetMasterLockTimer();
    return () => {
      if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    };
  }, [masterUnlocked, resetMasterLockTimer]);

  // Auto-lock effects read fresh state via these refs so they don't
  // re-register listeners on every App render (`useKeySession()`
  // returns a new object identity per render). Updated after every
  // render so event-driven callbacks see the latest values without
  // re-binding the listeners.
  const sessionRef = useRef(session);
  const masterUnlockedRef = useRef(masterUnlocked);
  const doMasterLockRef = useRef(doMasterLock);
  const resetMasterLockTimerRef = useRef(resetMasterLockTimer);
  const lockOnTabAwayRef = useRef(lockOnTabAway);
  useEffect(() => {
    sessionRef.current = session;
    masterUnlockedRef.current = masterUnlocked;
    doMasterLockRef.current = doMasterLock;
    resetMasterLockTimerRef.current = resetMasterLockTimer;
    lockOnTabAwayRef.current = lockOnTabAway;
  });

  // Reset lock timers on user activity so the extension doesn't lock
  // while the user is actively typing or interacting.
  const lastActivityRef = useRef(0);
  useEffect(() => {
    const handleActivity = () => {
      const now = Date.now();
      if (now - lastActivityRef.current < 30_000) return;
      lastActivityRef.current = now;
      if (masterUnlockedRef.current) resetMasterLockTimerRef.current();
      const s = sessionRef.current;
      if (s.unlockedKeyIds.size > 0) s.resetLockTimer();
    };
    document.addEventListener("keydown", handleActivity);
    document.addEventListener("pointerdown", handleActivity);
    return () => {
      document.removeEventListener("keydown", handleActivity);
      document.removeEventListener("pointerdown", handleActivity);
    };
  }, []);

  // Tab-away lock via `chrome.windows.onFocusChanged`. Fires on real
  // window/app focus changes only -- not on system overlays like the
  // WebAuthn dialog -- so it avoids the visibilitychange flicker that
  // was re-locking the user mid-unlock. Locks when focus leaves
  // Chrome entirely OR moves to a different Chrome window.
  const ownWindowIdRef = useRef<number | null>(null);
  useEffect(() => {
    let cancelled = false;
    void chrome.windows.getCurrent().then((win) => {
      if (cancelled) return;
      ownWindowIdRef.current = win.id ?? null;
    });

    const onFocus = (windowId: number) => {
      if (!lockOnTabAwayRef.current) return;
      if (ownWindowIdRef.current === null) return;
      if (windowId === ownWindowIdRef.current) return;
      const s = sessionRef.current;
      if (s.unlockedKeyIds.size > 0) s.lockAll();
      if (masterUnlockedRef.current) void doMasterLockRef.current(true);
    };
    chrome.windows.onFocusChanged.addListener(onFocus);
    return () => {
      cancelled = true;
      chrome.windows.onFocusChanged.removeListener(onFocus);
    };
  }, []);

  // OS lockscreen → always lock. We do not subscribe to
  // chrome.idle's `"idle"` state -- only `"locked"`.
  useEffect(() => {
    const onState = (state: "idle" | "active" | "locked") => {
      if (state !== "locked") return;
      const s = sessionRef.current;
      if (s.unlockedKeyIds.size > 0) s.lockAll();
      if (masterUnlockedRef.current) void doMasterLockRef.current(true);
    };
    chrome.idle.onStateChanged.addListener(onState);
    return () => chrome.idle.onStateChanged.removeListener(onState);
  }, []);

  // Apply the encrypted (non-bootstrap) settings to UI state. These
  // decrypt only with an active vault session, so at first mount (locked)
  // they arrive as defaults; the unlock effect below re-reads and
  // re-applies them once the session exists.
  const applyPrefs = useCallback((prefs: PgpPreferences) => {
    setAdvancedMode(prefs.advancedMode);
    setAutoLockMinutes(prefs.autoLockMinutes);
    // If a pending context-menu op has already routed us to a tab, do
    // NOT overwrite that with the saved value. Without this guard,
    // opening the side panel via the context menu races: pending-routing
    // fires fast, getPreferences resolves later and clobbers `activeTab`,
    // which unmounts the target view (KeysView) and closes the dialog.
    if (!pendingRoutedRef.current) {
      setActiveTab(prefs.activeTab);
    }
    setNeverCacheKeys(prefs.neverCacheKeys);
    setAutoLockEnabled(prefs.autoLockEnabled);
    setAutoDownloadFiles(prefs.autoDownloadFiles);
    setAutoDownloadText(prefs.autoDownloadText);
    setLockOnTabAway(prefs.lockOnTabAway);
    setCrxSigningEnabled(prefs.crxSigningEnabled);
    setDefaultKeyId(prefs.defaultKeyId);
  }, []);

  useEffect(() => {
    void (async () => {
      const prefs = await getPreferences();
      // Bootstrap fields are readable regardless of lock state.
      setStorageLocation(prefs.storageLocation);
      setOnboardingComplete(prefs.onboardingComplete);
      applyPrefs(prefs);

      const mp = await getMasterProtection();
      setMasterProtection(mp);
      setMasterProtectionLoaded(true);
    })();
    // Pending op delivery is now via chrome.storage.session
    // (see usePendingOperation). No runtime handshake needed.
  }, [applyPrefs]);

  // On unlock the settings blob becomes decryptable -- re-read and apply
  // the real values (they were defaults while locked). Also runs the
  // one-time legacy-prefs migration via getPreferences.
  useEffect(() => {
    if (!masterUnlocked) return;
    void getPreferences().then(applyPrefs);
    // Best-effort: upgrade any pre-padding blobs to canonical padding now,
    // rather than waiting for their next mutation. Each is a no-op if
    // already canonical; failures are swallowed (the data is untouched).
    const ignore = () => {
      /* best-effort: leave the blob as-is on any failure */
    };
    void normalizeKeyringPadding().catch(ignore);
    void normalizeContactsPadding().catch(ignore);
    void normalizeCrxPadding().catch(ignore);
  }, [masterUnlocked, applyPrefs]);

  useEffect(() => {
    if (!pending) return;
    if (
      pending.action === "import-public" ||
      pending.action === "import-private"
    ) {
      pendingRoutedRef.current = true;
      setImportPrefill(pending.text);
      setActiveTab("keys");
      void savePreferences({ activeTab: "keys" });
      clearPending();
      return;
    }
    pendingRoutedRef.current = true;
    // A keyboard mode command carries no text: it must not discard a
    // locked workspace draft the way a real selection does.
    if (pending.text) setDraftCiphertext(null);
    setActiveTab("workspace");
    void savePreferences({ activeTab: "workspace" });
  }, [pending, clearPending]);

  // ── Command palette / action registry wiring ─────────────────────
  // WorkspaceView pushes its palette-facing state/ops slice up here;
  // useActionContext folds it with tab + navigation callbacks into the
  // ActionCtx the registry evaluates against.
  const [workspaceBridge, setWorkspaceBridge] =
    useState<WorkspaceOpsBridge | null>(null);
  // Bumped when Settings rewrites preference-backed workspace toggles
  // (preset apply); the always-mounted WorkspaceView re-reads prefs.
  const [workspacePrefsVersion, setWorkspacePrefsVersion] = useState(0);

  // Cross-window preference sync (same storage.onChanged pattern as
  // usePendingOperation): another window saving the encrypted settings
  // blob or the plaintext bootstrap fires here; re-read and re-apply
  // via the same applyPrefs path unlock uses, and bump prefsVersion so
  // the workspace re-reads its preference-backed toggles. applyPrefs
  // never writes, so this can't feed back into another change event.
  // While locked, getPreferences returns defaults; skip and let the
  // unlock effect re-read instead.
  useEffect(() => {
    const onPrefsStorageChanged = (
      changes: Record<string, chrome.storage.StorageChange>,
      area: chrome.storage.AreaName,
    ) => {
      if (area !== "local" && area !== "sync") return;
      if (!(STORAGE_SETTINGS in changes) && !(STORAGE_PREFERENCES in changes)) {
        return;
      }
      if (!masterUnlockedRef.current) return;
      void getPreferences().then((prefs) => {
        applyPrefs(prefs);
        setWorkspacePrefsVersion((v) => v + 1);
      });
    };
    chrome.storage.onChanged.addListener(onPrefsStorageChanged);
    return () => chrome.storage.onChanged.removeListener(onPrefsStorageChanged);
  }, [applyPrefs]);

  const [historyOpen, setHistoryOpen] = useState(false);
  const [keysRoute, setKeysRoute] = useState<"generate" | "import" | null>(
    null,
  );
  // One-shot request for Settings to open its security-presets subpage
  // (the "Open security presets" palette action), keysRoute-style.
  const [presetsRoute, setPresetsRoute] = useState(false);

  const changeTab = useCallback((tab: Tab) => {
    setActiveTab(tab);
    void savePreferences({ activeTab: tab });
    toast.dismiss();
  }, []);

  const openHistory = useCallback(() => setHistoryOpen(true), []);
  const openKeysRoute = useCallback(
    (route: "generate" | "import") => {
      setKeysRoute(route);
      changeTab("keys");
    },
    [changeTab],
  );
  const openGenerate = useCallback(
    () => openKeysRoute("generate"),
    [openKeysRoute],
  );
  const openImport = useCallback(
    () => openKeysRoute("import"),
    [openKeysRoute],
  );
  const openSecurityPresets = useCallback(() => {
    setPresetsRoute(true);
    changeTab("settings");
  }, [changeTab]);
  const lockNow = useCallback(() => void doMasterLock(), [doMasterLock]);

  // The palette registers its imperative open() here so the footer's
  // mod+K hint can pop it without owning the palette's state.
  const openPaletteRef = useRef<(() => void) | null>(null);
  const bindPaletteOpen = useCallback((fn: () => void) => {
    openPaletteRef.current = fn;
  }, []);
  const openPalette = useCallback(() => openPaletteRef.current?.(), []);

  const actionCtx = useActionContext({
    tab: activeTab,
    setTab: changeTab,
    workspace: workspaceBridge,
    counts: {
      ownKeys: keyring.keys.length,
      contacts: contacts.contacts.length,
    },
    neverCacheKeys,
    openHistory,
    openGenerate,
    openImport,
    openSecurityPresets,
    lockNow,
  });

  // Persist (or clear, with null) the default-key choice.
  const handleSetDefaultKey = useCallback((keyId: string | null) => {
    setDefaultKeyId(keyId);
    void savePreferences({ defaultKeyId: keyId });
  }, []);

  // The user's first own key becomes the explicit default: with one key the
  // resolver's first-key fallback behaves identically anyway, but making it
  // explicit means adding a second key later never silently changes which
  // key "encrypt to me" targets.
  const handleAddKey = useCallback(
    async (blob: ProtectedKeyBlob) => {
      const isFirstKey = keyring.keys.length === 0;
      await keyring.add(blob);
      if (isFirstKey && defaultKeyId === null) handleSetDefaultKey(blob.keyId);
    },
    [keyring, defaultKeyId, handleSetDefaultKey],
  );

  const handleDeleteKey = useCallback(
    async (keyId: string) => {
      await keyring.remove(keyId);
      void contacts.refresh();
      // Deleting the default key clears the preference with it, so the
      // stored id never points at a key that no longer exists. (The
      // resolver also skips stale ids, as a second line of defense.)
      if (defaultKeyId === keyId) handleSetDefaultKey(null);
    },
    [keyring, contacts, defaultKeyId, handleSetDefaultKey],
  );

  const clearWorkspaceIntake = useCallback(() => setWorkspaceIntake(null), []);

  // Routing table for the global dropzone. First match wins; the final
  // rule is the catch-all. Extend by adding a rule (see lib/drop-routing).
  const dropRules: DropRule[] = [
    {
      id: "keys",
      // Armored keys announce themselves in the text sample; raw binary
      // exports (`gpg --export` without --armor) are flagged from the
      // byte sample and armored during readAllFilesText.
      match: (s) => looksLikeKey(s.sampleText) || s.hasBinaryKeyFile,
      run: async ({ files, text }) => {
        // Use the dragged text only when it is itself a key; otherwise the
        // key lives in a file (a benign text/plain riding along must not
        // shadow it). Reading files is bounded — see readAllFilesText.
        const armored = looksLikeKey(text)
          ? text
          : await readAllFilesText(files);
        if (!armored.trim()) return;
        setImportPrefill(armored);
        setActiveTab("keys");
        void savePreferences({ activeTab: "keys" });
      },
    },
    {
      id: "workspace",
      match: () => true,
      run: ({ files, text }) => {
        workspaceIntakeNonce.current += 1;
        setWorkspaceIntake({
          files,
          text,
          nonce: workspaceIntakeNonce.current,
        });
        setDraftCiphertext(null);
        setActiveTab("workspace");
        void savePreferences({ activeTab: "workspace" });
      },
    },
  ];

  if (onboardingComplete === null) return null;
  // Wait for masterProtection's initial load before rendering any
  // post-onboarding tree. Without this gate, the main UI mounts during
  // the load window, then unmounts when the lock screen takes over --
  // taking transient view state with it (e.g. an open import dialog
  // populated by the context-menu prefill flow).
  if (onboardingComplete && !masterProtectionLoaded) return null;

  if (!onboardingComplete) {
    return (
      <div className="flex h-screen flex-col">
        <main className="min-h-0 flex-1 overflow-y-auto">
          <OnboardingFlow
            onComplete={async (loc) => {
              setStorageLocation(loc);
              setOnboardingComplete(true);
              setMasterUnlocked(true);
              setMasterProtection(await getMasterProtection());
              setMasterProtectionLoaded(true);
              void keyring.refresh();
              void contacts.refresh();
              void crxKeys.refresh();
            }}
            addKey={handleAddKey}
            cacheKey={!neverCacheKeys}
            onKeyCached={(keyId, handle) => {
              void session.cacheKeyHandle(keyId, handle);
            }}
          />
        </main>
        <AppFooter />
      </div>
    );
  }

  if (masterProtection && !masterUnlocked) {
    return (
      <div className="flex h-screen flex-col">
        <main className="min-h-0 flex-1 overflow-y-auto">
          <MasterUnlockScreen
            masterProtection={masterProtection}
            autoLocked={masterAutoLocked}
            onUnlocked={() => {
              setMasterUnlocked(true);
              setMasterAutoLocked(false);
              resetMasterLockTimer();
              void keyring.refresh();
              void contacts.refresh();
              void crxKeys.refresh();
            }}
          />
        </main>
        <AppFooter />
      </div>
    );
  }

  const masterPasskeyCredentialId =
    masterProtection?.method === "passkey"
      ? masterProtection.credentialId
      : undefined;

  return (
    <GlobalDropZone rules={dropRules}>
      <div className="flex h-screen flex-col">
        <TabBar activeTab={activeTab} onTabChange={changeTab} />

        <CommandPalette ctx={actionCtx} bindOpen={bindPaletteOpen} />
        {historyOpen && (
          <HistoryPage
            enabled={workspaceBridge?.historyEnabled ?? false}
            onClose={() => setHistoryOpen(false)}
          />
        )}

        <main
          className="flex min-h-0 flex-1 flex-col overflow-y-auto p-4"
          role="tabpanel"
          id={`tabpanel-${activeTab}`}
          aria-labelledby={`tab-${activeTab}`}
        >
          <div className={activeTab === "workspace" ? "h-full" : "hidden"}>
            <WorkspaceView
              myKeys={keyring.keys}
              contacts={contacts.contacts}
              crxSigningEnabled={crxSigningEnabled}
              crxKeys={crxKeys.keys}
              getKeyHandle={session.getKeyHandle}
              onUnlockWithPassword={session.unlockWithPassword}
              onUnlockWithPasskey={session.unlockWithPasskey}
              pendingAction={
                pending &&
                (pending.action === "encrypt" ||
                  pending.action === "decrypt" ||
                  pending.action === "sign" ||
                  pending.action === "verify")
                  ? { action: pending.action, text: pending.text }
                  : null
              }
              onClearPending={clearPending}
              encryptToKeyId={encryptToKeyId}
              onClearEncryptTo={() => setEncryptToKeyId(null)}
              onNavigateToKeys={(prefill) => {
                if (prefill) setImportPrefill(prefill);
                setActiveTab("keys");
                void savePreferences({ activeTab: "keys" });
              }}
              autoDownloadFiles={autoDownloadFiles}
              autoDownloadText={autoDownloadText}
              onOperationComplete={session.lockAllIfNoCache}
              restoreDraft={draftCiphertext}
              onDraftRestored={handleDraftRestored}
              onDraftChange={handleDraftChange}
              intake={workspaceIntake}
              onIntakeConsumed={clearWorkspaceIntake}
              onPaletteOps={setWorkspaceBridge}
              prefsVersion={workspacePrefsVersion}
              defaultKeyId={defaultKeyId}
              neverCacheKeys={neverCacheKeys}
            />
          </div>
          {activeTab === "keys" && (
            <KeysView
              myKeys={keyring.keys}
              contacts={contacts.contacts}
              crxSigningEnabled={crxSigningEnabled}
              crxKeys={crxKeys.keys}
              onAddCrxKey={crxKeys.add}
              onDeleteCrxKey={crxKeys.remove}
              defaultKeyId={defaultKeyId}
              onSetDefaultKey={handleSetDefaultKey}
              onRenameKey={keyring.rename}
              onRenameCrxKey={crxKeys.rename}
              contactsLocked={false}
              isUnlocked={session.isUnlocked}
              onUnlockWithPassword={session.unlockWithPassword}
              onUnlockWithPasskey={session.unlockWithPasskey}
              onLock={session.lock}
              onDeleteKey={handleDeleteKey}
              getKeyHandle={session.getKeyHandle}
              onSaveRevocationCertificate={keyring.setRevocationCertificate}
              onAddKey={handleAddKey}
              onAddContact={contacts.add}
              onDeleteContact={contacts.remove}
              advancedMode={advancedMode}
              autoOpenImport={importPrefill}
              onAutoOpenImportConsumed={() => setImportPrefill(null)}
              autoOpenRoute={keysRoute}
              onAutoOpenRouteConsumed={() => setKeysRoute(null)}
              onEncryptTo={(keyId) => {
                setEncryptToKeyId(keyId);
                setActiveTab("workspace");
                void savePreferences({ activeTab: "workspace" });
              }}
              primaryPasskeyCredentialId={masterPasskeyCredentialId}
              cacheKeys={!neverCacheKeys}
              onKeyCached={(keyId, handle) => {
                void session.cacheKeyHandle(keyId, handle);
              }}
            />
          )}
          {activeTab === "settings" && (
            <SettingsView
              advancedMode={advancedMode}
              onAdvancedModeChange={setAdvancedMode}
              storageLocation={storageLocation}
              onStorageLocationChange={(loc) => {
                setStorageLocation(loc);
                void keyring.refresh();
                void contacts.refresh();
                void crxKeys.refresh();
              }}
              autoLockEnabled={autoLockEnabled}
              onAutoLockEnabledChange={setAutoLockEnabled}
              autoLockMinutes={autoLockMinutes}
              onAutoLockChange={setAutoLockMinutes}
              neverCacheKeys={neverCacheKeys}
              onNeverCacheKeysChange={setNeverCacheKeys}
              autoDownloadFiles={autoDownloadFiles}
              onAutoDownloadFilesChange={setAutoDownloadFiles}
              autoDownloadText={autoDownloadText}
              onAutoDownloadTextChange={setAutoDownloadText}
              lockOnTabAway={lockOnTabAway}
              onLockOnTabAwayChange={setLockOnTabAway}
              crxSigningEnabled={crxSigningEnabled}
              onWorkspacePrefsChanged={() =>
                setWorkspacePrefsVersion((v) => v + 1)
              }
              onCrxSigningEnabledChange={setCrxSigningEnabled}
              myKeys={keyring.keys}
              contacts={contacts.contacts}
              isUnlocked={session.isUnlocked}
              getKeyHandle={session.getKeyHandle}
              onUnlockWithPassword={session.unlockWithPassword}
              onUnlockWithPasskey={session.unlockWithPasskey}
              onAddKey={handleAddKey}
              onAddContact={contacts.add}
              crxKeys={crxKeys.keys}
              onAddCrxKey={crxKeys.add}
              primaryPasskeyCredentialId={masterPasskeyCredentialId}
              autoOpenPresets={presetsRoute}
              onAutoOpenPresetsConsumed={() => setPresetsRoute(false)}
            />
          )}
        </main>

        <AppFooter onOpenPalette={openPalette} />
      </div>
    </GlobalDropZone>
  );
}

// ── Tab bar with WAI-ARIA keyboard navigation ────────────────────────

const TABS: { id: Tab; label: string }[] = [
  { id: "workspace", label: "Main" },
  { id: "keys", label: "Keys" },
  { id: "settings", label: "Settings" },
];

function TabBar({
  activeTab,
  onTabChange,
}: {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
}) {
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const idx = TABS.findIndex((t) => t.id === activeTab);
      let next = idx;

      switch (e.key) {
        case "ArrowRight":
          next = (idx + 1) % TABS.length;
          break;
        case "ArrowLeft":
          next = (idx - 1 + TABS.length) % TABS.length;
          break;
        case "Home":
          next = 0;
          break;
        case "End":
          next = TABS.length - 1;
          break;
        default:
          return;
      }

      e.preventDefault();
      onTabChange(TABS[next].id);
      tabRefs.current[next]?.focus();
    },
    [activeTab, onTabChange],
  );

  return (
    <nav className="border-border border-b" aria-label="Main navigation">
      <div
        className="flex items-center"
        role="tablist"
        onKeyDown={handleKeyDown}
      >
        {TABS.map((tab, i) => {
          const isSettings = tab.id === "settings";
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              ref={(el) => {
                tabRefs.current[i] = el;
              }}
              role="tab"
              aria-selected={isActive}
              aria-controls={`tabpanel-${tab.id}`}
              aria-label={isSettings ? "Settings" : undefined}
              id={`tab-${tab.id}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => onTabChange(tab.id)}
              className={
                isSettings
                  ? `ml-auto px-3 py-2.5 transition-colors ${
                      isActive
                        ? "text-primary border-primary border-b-2"
                        : "text-muted-foreground hover:text-foreground"
                    }`
                  : `flex-1 px-3 py-2.5 text-sm font-medium transition-colors ${
                      isActive
                        ? "border-primary text-primary border-b-2"
                        : "text-muted-foreground hover:text-foreground"
                    }`
              }
            >
              {isSettings ? <SettingsIcon className="h-4 w-4" /> : tab.label}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
