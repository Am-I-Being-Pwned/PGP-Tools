import { useCallback, useEffect, useRef, useState } from "react";
import { SettingsIcon } from "lucide-react";
import { toast } from "sonner";

import type {
  AutoLockTimeout,
  StorageLocation,
} from "../../lib/storage/preferences";
import type { MasterProtection } from "../../lib/storage/master-protection";
import { KeysView } from "../../components/keys/KeysView";
import { MasterUnlockScreen } from "../../components/shared/MasterUnlockScreen";
import { OnboardingFlow } from "../../components/shared/OnboardingFlow";
import { SettingsView } from "../../components/shared/SettingsView";
import { WorkspaceView } from "../../components/workspace/WorkspaceView";
import { useContacts } from "../../hooks/useContacts";
import { useKeyring } from "../../hooks/useKeyring";
import { useKeySession } from "../../hooks/useKeySession";
import { usePendingOperation } from "../../hooks/usePendingOperation";
import { lockLog } from "../../lib/lock-logger";
import * as wasmApi from "../../lib/pgp/wasm";
import { getMasterProtection } from "../../lib/storage/master-protection";
import { getPreferences, savePreferences } from "../../lib/storage/preferences";
import {
  draftHasContent,
  encryptWorkspaceDraft,
  type WorkspaceDraft,
} from "../../lib/workspace-draft";

type Tab = "workspace" | "keys" | "settings";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("workspace");
  const [advancedMode, setAdvancedMode] = useState(false);
  const [storageLocation, setStorageLocation] =
    useState<StorageLocation>("local");
  const [autoLockMinutes, setAutoLockMinutes] = useState<AutoLockTimeout>(15);
  const [neverCacheKeys, setNeverCacheKeys] = useState(false);
  const [autoDownloadFiles, setAutoDownloadFiles] = useState(false);
  const [autoDownloadText, setAutoDownloadText] = useState(false);
  const [lockImmediatelyOnIdle, setLockImmediatelyOnIdle] = useState(false);
  const [lockImmediatelyOnTabOut, setLockImmediatelyOnTabOut] = useState(false);
  const [onboardingComplete, setOnboardingComplete] = useState<boolean | null>(
    null,
  );
  const [openGenerateOnMount, setOpenGenerateOnMount] = useState(false);
  const [encryptToKeyId, setEncryptToKeyId] = useState<string | null>(null);

  // Master protection state
  const [masterProtection, setMasterProtection] =
    useState<MasterProtection | null>(null);
  const [masterUnlocked, setMasterUnlocked] = useState(false);
  const masterLockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const keyring = useKeyring();
  const session = useKeySession({
    autoLockMinutes,
    neverCacheKeys,
  });
  const contacts = useContacts();
  const {
    pending,
    clearPending,
    importKey: importKeyMsg,
    clearImportKey,
  } = usePendingOperation();

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
      lockLog("master.lock", { auto });
      // Best-effort: encrypt + stash the workspace draft BEFORE we
      // unmount the workspace by flipping `masterUnlocked`. If the
      // encrypt errors, fall through and lock anyway -- losing draft
      // content is better than failing to lock.
      const draft = latestDraftRef.current;
      if (draft && draftHasContent(draft)) {
        try {
          await wasmApi.initDraftSessionIfUnset();
          const ct = await encryptWorkspaceDraft(draft);
          setDraftCiphertext(ct);
        } catch {
          /* fall through */
        }
      }
      latestDraftRef.current = null;

      // Drop the WASM contacts session key. For passkey users this is
      // already gone (dropped after decrypt), but for password users
      // it persists and must be explicitly cleared.
      void wasmApi.dropContactsSession();
      setMasterAutoLocked(auto);
      setMasterUnlocked(false);
      session.lockAll();
    },
    [session],
  );

  const resetMasterLockTimer = useCallback(() => {
    if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    const ms = autoLockMinutes * 60 * 1000;
    lockLog("master.timer-arm", { autoLockMinutes, ms });
    masterLockTimerRef.current = setTimeout(() => {
      lockLog("master.timer-fire", { autoLockMinutes });
      void doMasterLock(true);
    }, ms);
  }, [autoLockMinutes, doMasterLock]);

  useEffect(() => {
    if (!masterUnlocked) return;
    resetMasterLockTimer();
    return () => {
      if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    };
  }, [masterUnlocked, resetMasterLockTimer]);

  // Refs that mirror the latest unstable values. Auto-lock effects use
  // these so they can read fresh state without re-registering listeners
  // (and re-calling chrome.idle.setDetectionInterval) on every App
  // render. `useKeySession()` returns a new object every render; without
  // the ref indirection, the effects below would churn constantly.
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const masterUnlockedRef = useRef(masterUnlocked);
  masterUnlockedRef.current = masterUnlocked;
  const doMasterLockRef = useRef(doMasterLock);
  doMasterLockRef.current = doMasterLock;
  const resetMasterLockTimerRef = useRef(resetMasterLockTimer);
  resetMasterLockTimerRef.current = resetMasterLockTimer;
  const lockImmediatelyOnTabOutRef = useRef(lockImmediatelyOnTabOut);
  lockImmediatelyOnTabOutRef.current = lockImmediatelyOnTabOut;

  // Reset lock timers on user activity so the extension doesn't lock
  // while the user is actively typing or interacting.
  const lastActivityRef = useRef(0);
  useEffect(() => {
    const handleActivity = () => {
      const now = Date.now();
      if (now - lastActivityRef.current < 30_000) return;
      lastActivityRef.current = now;
      lockLog("activity.reset");
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

  // Visibility-based lock.
  //   - If `lockImmediatelyOnTabOut` is on, lock the moment the panel
  //     hides (no grace).
  //   - Otherwise apply a 60s grace: schedule a lock when hidden,
  //     cancel if the panel becomes visible again. Quick alt-tabs
  //     don't lock; a sustained "I left this for a minute" does.
  const VISIBILITY_GRACE_MS = 60_000;
  const visibilityLockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );
  useEffect(() => {
    const fireLock = () => {
      lockLog("visibility.hidden-fire");
      const s = sessionRef.current;
      if (s.unlockedKeyIds.size > 0) s.lockAll();
      if (masterUnlockedRef.current) void doMasterLockRef.current(true);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        if (visibilityLockTimerRef.current) {
          clearTimeout(visibilityLockTimerRef.current);
          visibilityLockTimerRef.current = null;
        }
        const immediate = lockImmediatelyOnTabOutRef.current;
        lockLog("visibility.hidden-arm", {
          immediate,
          ms: immediate ? 0 : VISIBILITY_GRACE_MS,
          masterUnlocked: masterUnlockedRef.current,
          unlockedKeys: sessionRef.current.unlockedKeyIds.size,
        });
        if (immediate) {
          fireLock();
        } else {
          visibilityLockTimerRef.current = setTimeout(
            fireLock,
            VISIBILITY_GRACE_MS,
          );
        }
      } else {
        if (visibilityLockTimerRef.current) {
          lockLog("visibility.cancel");
          clearTimeout(visibilityLockTimerRef.current);
          visibilityLockTimerRef.current = null;
        }
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      if (visibilityLockTimerRef.current) {
        clearTimeout(visibilityLockTimerRef.current);
      }
    };
  }, []);

  // OS-level idle / lock detection.
  //   - `"locked"` (OS lockscreen) ALWAYS triggers an immediate lock,
  //     regardless of any user setting -- the screen is gone, the
  //     user has clearly stepped away.
  //   - `"idle"` is acted on ONLY when `lockImmediatelyOnIdle` is true.
  //     When the setting is off, the in-app `autoLockMinutes` timer
  //     is the only idle-based lock; OS-idle does nothing.
  //
  // This effect re-runs only when the two relevant prefs change.
  useEffect(() => {
    if (!chrome.idle?.onStateChanged) return;
    if (lockImmediatelyOnIdle) {
      lockLog("chrome-idle.set-interval", { seconds: 60 });
      chrome.idle.setDetectionInterval(60);
    }
    lockLog("chrome-idle.install", { lockImmediatelyOnIdle });
    const onState = (state: "idle" | "active" | "locked") => {
      lockLog("chrome-idle.state", { state, lockImmediatelyOnIdle });
      if (state === "active") return;
      if (state === "idle" && !lockImmediatelyOnIdle) {
        lockLog("chrome-idle.skip-idle");
        return;
      }
      const s = sessionRef.current;
      if (s.unlockedKeyIds.size > 0) s.lockAll();
      if (masterUnlockedRef.current) void doMasterLockRef.current(true);
    };
    chrome.idle.onStateChanged.addListener(onState);

    // Periodic poll: ask Chrome what state it thinks we're in. Useful
    // for debugging "I waited 90s and the idle event didn't fire" --
    // if the poll shows "active" the OS is still seeing input from
    // somewhere; if it shows "idle" but no event fired the listener
    // didn't pick up the transition. Threshold matches the active
    // detection interval.
    const queryEverySec = lockImmediatelyOnIdle ? 30 : 60;
    const queryThresholdSec = lockImmediatelyOnIdle ? 60 : 60;
    const pollId = window.setInterval(() => {
      chrome.idle.queryState(queryThresholdSec, (state) => {
        lockLog("chrome-idle.poll", {
          state,
          queryThresholdSec,
        });
      });
    }, queryEverySec * 1000);

    return () => {
      chrome.idle.onStateChanged.removeListener(onState);
      window.clearInterval(pollId);
    };
  }, [lockImmediatelyOnIdle]);

  useEffect(() => {
    void (async () => {
      const prefs = await getPreferences();
      setAdvancedMode(prefs.advancedMode);
      setStorageLocation(prefs.storageLocation);
      setAutoLockMinutes(prefs.autoLockMinutes);
      setOnboardingComplete(prefs.onboardingComplete);
      setActiveTab(prefs.activeTab);
      setNeverCacheKeys(prefs.neverCacheKeys);
      setAutoDownloadFiles(prefs.autoDownloadFiles);
      setAutoDownloadText(prefs.autoDownloadText);
      setLockImmediatelyOnIdle(prefs.lockImmediatelyOnIdle);
      setLockImmediatelyOnTabOut(prefs.lockImmediatelyOnTabOut);
      lockLog("prefs", {
        autoLockMinutes: prefs.autoLockMinutes,
        lockImmediatelyOnIdle: prefs.lockImmediatelyOnIdle,
        lockImmediatelyOnTabOut: prefs.lockImmediatelyOnTabOut,
        neverCacheKeys: prefs.neverCacheKeys,
      });

      const mp = await getMasterProtection();
      setMasterProtection(mp);
    })();
    chrome.runtime.sendMessage({ type: "SIDEPANEL_READY" }).catch(() => {
      /* noop */
    });
  }, []);

  useEffect(() => {
    if (pending) {
      setActiveTab("workspace");
      void savePreferences({ activeTab: "workspace" });
    }
  }, [pending]);

  useEffect(() => {
    if (importKeyMsg) {
      setActiveTab("keys");
      void savePreferences({ activeTab: "keys" });
    }
  }, [importKeyMsg]);

  const handleDeleteKey = useCallback(
    async (keyId: string) => {
      await keyring.remove(keyId);
      void contacts.refresh();
    },
    [keyring, contacts],
  );

  if (onboardingComplete === null) return null;

  if (!onboardingComplete) {
    return (
      <OnboardingFlow
        onComplete={async (loc) => {
          setStorageLocation(loc);
          setOnboardingComplete(true);
          setMasterUnlocked(true);
          setMasterProtection(await getMasterProtection());
          void keyring.refresh();
          void contacts.refresh();
        }}
        addKey={keyring.add}
        cacheKey={!neverCacheKeys}
        onKeyCached={(keyId, handle) => {
          void session.cacheKeyHandle(keyId, handle);
        }}
      />
    );
  }

  if (masterProtection && !masterUnlocked) {
    return (
      <MasterUnlockScreen
        masterProtection={masterProtection}
        autoLocked={masterAutoLocked}
        onUnlocked={() => {
          setMasterUnlocked(true);
          setMasterAutoLocked(false);
          resetMasterLockTimer();
          void keyring.refresh();
          void contacts.refresh();
        }}
      />
    );
  }

  const masterPasskeyCredentialId =
    masterProtection?.method === "passkey"
      ? masterProtection.credentialId
      : undefined;

  return (
    <div className="flex h-screen flex-col">
      <TabBar
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          void savePreferences({ activeTab: tab });
          toast.dismiss();
        }}
      />

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
            getKeyHandle={session.getKeyHandle}
            onUnlockWithPassword={session.unlockWithPassword}
            onUnlockWithPasskey={session.unlockWithPasskey}
            pendingAction={
              pending ? { action: pending.action, text: pending.text } : null
            }
            onClearPending={clearPending}
            encryptToKeyId={encryptToKeyId}
            onClearEncryptTo={() => setEncryptToKeyId(null)}
            onNavigateToKeys={() => setActiveTab("keys")}
            autoDownloadFiles={autoDownloadFiles}
            autoDownloadText={autoDownloadText}
            onOperationComplete={session.lockAllIfNoCache}
            restoreDraft={draftCiphertext}
            onDraftRestored={handleDraftRestored}
            onDraftChange={handleDraftChange}
          />
        </div>
        {activeTab === "keys" && (
          <KeysView
            myKeys={keyring.keys}
            contacts={contacts.contacts}
            contactsLocked={false}
            isUnlocked={session.isUnlocked}
            onUnlockWithPassword={session.unlockWithPassword}
            onUnlockWithPasskey={session.unlockWithPasskey}
            onLock={session.lock}
            onDeleteKey={handleDeleteKey}
            getKeyHandle={session.getKeyHandle}
            onAddKey={keyring.add}
            onAddContact={contacts.add}
            onDeleteContact={contacts.remove}
            advancedMode={advancedMode}
            autoOpenGenerate={openGenerateOnMount}
            onAutoOpenConsumed={() => setOpenGenerateOnMount(false)}
            importKeyFromLink={importKeyMsg}
            onImportKeyConsumed={clearImportKey}
            onEncryptTo={(keyId) => {
              setEncryptToKeyId(keyId);
              setActiveTab("workspace");
              void savePreferences({ activeTab: "workspace" });
            }}
            unlockRequestKeyId={null}
            primaryPasskeyCredentialId={masterPasskeyCredentialId}
            onUnlockRequestConsumed={() => {
              /* noop */
            }}
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
            }}
            autoLockMinutes={autoLockMinutes}
            onAutoLockChange={setAutoLockMinutes}
            neverCacheKeys={neverCacheKeys}
            onNeverCacheKeysChange={setNeverCacheKeys}
            autoDownloadFiles={autoDownloadFiles}
            onAutoDownloadFilesChange={setAutoDownloadFiles}
            autoDownloadText={autoDownloadText}
            onAutoDownloadTextChange={setAutoDownloadText}
            lockImmediatelyOnIdle={lockImmediatelyOnIdle}
            onLockImmediatelyOnIdleChange={setLockImmediatelyOnIdle}
            lockImmediatelyOnTabOut={lockImmediatelyOnTabOut}
            onLockImmediatelyOnTabOutChange={setLockImmediatelyOnTabOut}
          />
        )}
      </main>

      <footer className="border-border border-t px-4 py-2 text-center">
        <a
          href="https://amibeingpwned.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-muted-foreground hover:text-foreground text-xs transition-colors"
        >
          by Am I Being Pwned
        </a>
      </footer>
    </div>
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
      <div className="flex items-center" role="tablist" onKeyDown={handleKeyDown}>
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
              {isSettings ? (
                <SettingsIcon className="h-4 w-4" />
              ) : (
                tab.label
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
