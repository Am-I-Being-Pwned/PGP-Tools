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
import * as wasmApi from "../../lib/pgp/wasm";
import { getMasterProtection } from "../../lib/storage/master-protection";
import { getPreferences, savePreferences } from "../../lib/storage/preferences";

type Tab = "workspace" | "keys" | "settings";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("workspace");
  const [advancedMode, setAdvancedMode] = useState(false);
  const [storageLocation, setStorageLocation] =
    useState<StorageLocation>("local");
  const [autoLockMinutes, setAutoLockMinutes] = useState<AutoLockTimeout>(15);
  const [neverCacheKeys, setNeverCacheKeys] = useState(false);
  const [autoDecryptDownloads, setAutoDecryptDownloads] = useState(false);
  const [autoDownloadFiles, setAutoDownloadFiles] = useState(false);
  const [autoDownloadText, setAutoDownloadText] = useState(false);
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
    autoDecrypt,
    clearAutoDecrypt,
  } = usePendingOperation();

  // ── Master auto-lock ───────────────────────────────────────────────

  const doMasterLock = useCallback(() => {
    // Drop the WASM contacts session key. For passkey users this is
    // already gone (dropped after decrypt), but for password users
    // it persists and must be explicitly cleared.
    void wasmApi.dropContactsSession();
    setMasterUnlocked(false);
    session.lockAll();
  }, [session]);

  const resetMasterLockTimer = useCallback(() => {
    if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    masterLockTimerRef.current = setTimeout(
      doMasterLock,
      autoLockMinutes * 60 * 1000,
    );
  }, [autoLockMinutes, doMasterLock]);

  useEffect(() => {
    if (!masterUnlocked) return;
    resetMasterLockTimer();
    return () => {
      if (masterLockTimerRef.current) clearTimeout(masterLockTimerRef.current);
    };
  }, [masterUnlocked, resetMasterLockTimer]);

  // ── Init ───────────────────────────────────────────────────────────

  useEffect(() => {
    void (async () => {
      const prefs = await getPreferences();
      setAdvancedMode(prefs.advancedMode);
      setStorageLocation(prefs.storageLocation);
      setAutoLockMinutes(prefs.autoLockMinutes);
      setOnboardingComplete(prefs.onboardingComplete);
      setActiveTab(prefs.activeTab);
      setNeverCacheKeys(prefs.neverCacheKeys);
      setAutoDecryptDownloads(prefs.autoDecryptDownloads);
      setAutoDownloadFiles(prefs.autoDownloadFiles);
      setAutoDownloadText(prefs.autoDownloadText);

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
    if (autoDecrypt) {
      setActiveTab("workspace");
      void savePreferences({ activeTab: "workspace" });
    }
  }, [autoDecrypt]);

  useEffect(() => {
    if (importKeyMsg) {
      setActiveTab("keys");
      void savePreferences({ activeTab: "keys" });
    }
  }, [importKeyMsg]);

  // ── Delete key handler ─────────────────────────────────────────────

  const handleDeleteKey = useCallback(
    async (keyId: string) => {
      await keyring.remove(keyId);
      void contacts.refresh();
    },
    [keyring, contacts],
  );

  // ── Render gates ───────────────────────────────────────────────────

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
        onUnlocked={() => {
          setMasterUnlocked(true);
          resetMasterLockTimer();
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
            autoDecrypt={autoDecrypt}
            onClearAutoDecrypt={clearAutoDecrypt}
            encryptToKeyId={encryptToKeyId}
            onClearEncryptTo={() => setEncryptToKeyId(null)}
            onNavigateToKeys={() => setActiveTab("keys")}
            autoDownloadFiles={autoDownloadFiles}
            autoDownloadText={autoDownloadText}
            onOperationComplete={session.lockAllIfNoCache}
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
            autoDecryptDownloads={autoDecryptDownloads}
            onAutoDecryptDownloadsChange={setAutoDecryptDownloads}
            autoDownloadFiles={autoDownloadFiles}
            onAutoDownloadFilesChange={setAutoDownloadFiles}
            autoDownloadText={autoDownloadText}
            onAutoDownloadTextChange={setAutoDownloadText}
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
