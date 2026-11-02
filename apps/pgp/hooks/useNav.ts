import { createContext, use, useMemo, useRef, useState } from "react";

import { toast } from "~/lib/toast";

export type Tab = "workspace" | "keys" | "settings";
export type KeysRoute = "generate" | "import";

/** Where the panel is, and the one-shot requests a view acts on when it
 *  next renders (then clears with `consume`). */
export interface NavState {
  tab: Tab;
  /** The import panel, open over whatever tab is showing. */
  importing: { prefill: string | null; lookup: string | null } | null;
  historyOpen: boolean;
  highlightKeyIds: string[] | null;
  keysRoute: KeysRoute | null;
  presets: boolean;
  encryptToKeyId: string | null;
}

type Intent = "highlightKeyIds" | "keysRoute" | "presets" | "encryptToKeyId";

const CLEARED: Pick<NavState, Intent> = {
  highlightKeyIds: null,
  keysRoute: null,
  presets: false,
  encryptToKeyId: null,
};

export interface Nav extends NavState {
  showTab: (tab: Tab) => void;
  /** Open the import panel in place: no tab change to flash past. */
  openImport: (from: { prefill?: string; lookup?: string }) => void;
  closeImport: () => void;
  openHistory: () => void;
  closeHistory: () => void;
  /** Show keys on the Keys tab, scrolled to and pulsing. */
  revealKeys: (keyIds: string[]) => void;
  /** Pulse keys without leaving the current tab. */
  highlightKeys: (keyIds: string[]) => void;
  openKeysRoute: (route: KeysRoute) => void;
  openPresets: () => void;
  encryptTo: (keyId: string) => void;
  consume: (intent: Intent) => void;
}

export function useNavState(): Nav {
  const [state, setState] = useState<NavState>({
    tab: "workspace",
    importing: null,
    historyOpen: false,
    ...CLEARED,
  });

  const tabRef = useRef(state.tab);
  const actions = useMemo(() => {
    const patch = (p: Partial<NavState>) => setState((s) => ({ ...s, ...p }));
    // Every tab change dismisses the last tab's toasts.
    const go = (tab: Tab, p: Partial<NavState> = {}) => {
      if (tabRef.current !== tab) toast.dismiss();
      tabRef.current = tab;
      patch({ ...p, tab });
    };
    return {
      showTab: (tab: Tab) => go(tab),
      openImport: ({
        prefill,
        lookup,
      }: {
        prefill?: string;
        lookup?: string;
      }) =>
        patch({
          importing: { prefill: prefill ?? null, lookup: lookup ?? null },
        }),
      closeImport: () => patch({ importing: null }),
      openHistory: () => patch({ historyOpen: true }),
      closeHistory: () => patch({ historyOpen: false }),
      revealKeys: (keyIds: string[]) => {
        if (keyIds.length > 0) go("keys", { highlightKeyIds: keyIds });
      },
      highlightKeys: (keyIds: string[]) => patch({ highlightKeyIds: keyIds }),
      openKeysRoute: (route: KeysRoute) => go("keys", { keysRoute: route }),
      openPresets: () => go("settings", { presets: true }),
      encryptTo: (keyId: string) => go("workspace", { encryptToKeyId: keyId }),
      consume: (intent: Intent) => patch({ [intent]: CLEARED[intent] }),
    };
  }, []);

  return useMemo(() => ({ ...state, ...actions }), [state, actions]);
}

export const NavContext = createContext<Nav | null>(null);

export function useNav(): Nav {
  const nav = use(NavContext);
  if (!nav) throw new Error("useNav outside the panel");
  return nav;
}
