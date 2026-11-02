import { createContext, use } from "react";

import type { KeysNav } from "./keys-routes";
import type { KeySelection } from "./useKeySelection";

/** What the Keys tab's lists share: its subpage stack, the one selection
 *  and the import pulse. Provided by `KeysView`. */
export interface KeysTab {
  nav: KeysNav;
  selection: KeySelection;
  justImported: ReadonlySet<string>;
}

export const KeysContext = createContext<KeysTab | null>(null);

export function useKeysTab(): KeysTab {
  const tab = use(KeysContext);
  if (!tab) throw new Error("useKeysTab outside KeysView");
  return tab;
}
