import {
  createContext,
  use,
  useEffect,
  useEffectEvent,
  useMemo,
  useRef,
  useState,
} from "react";

import { toast } from "~/lib/toast";

export type Tab = "workspace" | "keys" | "settings";
export type KeysRoute = "generate" | "import";

/** Where the panel is, plus one-shot requests a view clears with `consume`. */
export interface NavState {
  tab: Tab;
  importing: { prefill: string | null; lookup: string | null } | null;
  historyOpen: boolean;
  highlightKeyIds: string[] | null;
  keysRoute: KeysRoute | null;
  presets: boolean;
  encryptToKeyId: string | null;
}

export type Intent =
  "highlightKeyIds" | "keysRoute" | "presets" | "encryptToKeyId";

const CLEARED: Pick<NavState, Intent> = {
  highlightKeyIds: null,
  keysRoute: null,
  presets: false,
  encryptToKeyId: null,
};

export interface Nav extends NavState {
  showTab: (tab: Tab) => void;
  openImport: (from: { prefill?: string; lookup?: string }) => void;
  closeImport: () => void;
  openHistory: () => void;
  closeHistory: () => void;
  revealKeys: (keyIds: string[]) => void;
  /** Without leaving the current tab. */
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

/** Take a one-shot intent once the receiving view is mounted: it is held
 *  in nav state until then, so a view that mounts after the request (the
 *  Keys tab) still sees it. */
export function useNavIntent<I extends Intent>(
  intent: I,
  onIntent: (value: Exclude<NavState[I], null | false>) => void,
): void {
  const nav = useNav();
  const value: NavState[I] = nav[intent];
  const { consume } = nav;
  const take = useEffectEvent(onIntent);
  useEffect(() => {
    if (!value) return;
    take(value as Exclude<NavState[I], null | false>);
    consume(intent);
  }, [value, intent, consume]);
}
