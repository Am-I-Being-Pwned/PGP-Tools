import { useEffect, useRef, useState } from "react";

import { useNav } from "~/hooks/useNav";

/**
 * Key ids written by the most recent import (or a `highlightKeyIds`
 * intent): their cards scroll into view and pulse once. Cleared on a
 * timer -- a permanent ring would just become decoration.
 */
export function useImportHighlight(): [
  Set<string>,
  (keyIds: string[]) => void,
] {
  const appNav = useNav();
  const [justImported, setJustImported] = useState<Set<string>>(new Set());
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const highlight = (keyIds: string[]) => {
    if (keyIds.length === 0) return;
    setJustImported(new Set(keyIds));
    clearTimeout(timer.current);
    // Outlasts the 1.6s pulse plus the panel's slide-out.
    timer.current = setTimeout(() => setJustImported(new Set()), 2600);
  };

  useEffect(() => {
    if (!appNav.highlightKeyIds?.length) return;
    highlight(appNav.highlightKeyIds);
    appNav.consume("highlightKeyIds");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appNav.highlightKeyIds]);

  return [justImported, highlight];
}
