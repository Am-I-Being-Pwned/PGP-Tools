import type { KeyboardEvent, ReactNode } from "react";
import { useRef } from "react";
import { HistoryIcon, SettingsIcon } from "lucide-react";

import type { Tab } from "../../hooks/useNav";
import { t } from "../../lib/i18n";

// Labels resolve at render time, never at module load.
const TABS: { id: Tab; label: () => string }[] = [
  { id: "workspace", label: () => t("app_tab_main") },
  { id: "keys", label: () => t("common_keys") },
  { id: "settings", label: () => t("common_settings") },
];

const KEY_STEP: Record<string, (i: number) => number> = {
  ArrowRight: (i) => (i + 1) % TABS.length,
  ArrowLeft: (i) => (i - 1 + TABS.length) % TABS.length,
  Home: () => 0,
  End: () => TABS.length - 1,
};

/** Main/Keys as a segmented pair, Settings as an icon, all one WAI-ARIA
 *  tablist. `trailing` (History) sits between them, outside the tablist. */
export function TabBar({
  activeTab,
  onTabChange,
  trailing,
}: {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  trailing?: ReactNode;
}) {
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKeyDown = (e: KeyboardEvent) => {
    const step = KEY_STEP[e.key] as ((i: number) => number) | undefined;
    if (!step) return;
    e.preventDefault();
    const next = step(TABS.findIndex((tab) => tab.id === activeTab));
    onTabChange(TABS[next].id);
    tabRefs.current[next]?.focus();
  };

  const renderTab = (tab: (typeof TABS)[number], i: number) => {
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
        aria-label={isSettings ? t("common_settings") : undefined}
        id={`tab-${tab.id}`}
        // Out of the Tab order: a click, the palette, or arrows away.
        tabIndex={-1}
        onClick={() => onTabChange(tab.id)}
        className={
          isSettings
            ? `${trailing ? "" : "ml-auto"} order-2 flex size-[30px] items-center justify-center rounded-md transition-colors ${
                isActive
                  ? "bg-raised text-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              }`
            : `h-[26px] rounded-md px-3 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-raised text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.5)]"
                  : "text-muted-foreground hover:text-foreground"
              }`
        }
      >
        {isSettings ? <SettingsIcon className="h-4 w-4" /> : tab.label()}
      </button>
    );
  };

  return (
    <nav
      className="bg-chrome flex shrink-0 items-center gap-1 border-b border-white/[0.06] py-2 pr-2.5 pl-3"
      aria-label={t("app_nav_label")}
    >
      {/* `contents`: one tablist, laid out in the nav's row. */}
      <div className="contents" role="tablist" onKeyDown={onKeyDown}>
        <div className="bg-track flex gap-0.5 rounded-lg p-[3px]">
          {TABS.map((tab, i) =>
            tab.id === "settings" ? null : renderTab(tab, i),
          )}
        </div>
        {TABS.map((tab, i) =>
          tab.id === "settings" ? renderTab(tab, i) : null,
        )}
      </div>
      {trailing && (
        <div className="order-1 ml-auto flex items-center">{trailing}</div>
      )}
    </nav>
  );
}

export function HistoryButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={t("actions_history")}
      aria-label={t("actions_history")}
      // Out of the Tab order; keyboard users have the palette.
      tabIndex={-1}
      className="text-muted-foreground hover:bg-accent hover:text-foreground flex size-[30px] items-center justify-center rounded-md transition-colors"
    >
      <HistoryIcon className="h-4 w-4" />
    </button>
  );
}
