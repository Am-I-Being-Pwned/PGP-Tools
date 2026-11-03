import { useShortcut } from "~/hooks";
import { t } from "~/lib/i18n";
import { toast } from "~/lib/toast";
import type { Workspace } from "./useWorkspace";
import type { WorkspaceFlags } from "./workspace-view";

/** Clearing the message (undoably) and putting focus back where the flow starts. */
export function useClearWithUndo(ws: Workspace, v: WorkspaceFlags) {
  const { state: s, dispatch, inputElRef, inputChanged } = ws;
  const resetAll = () => dispatch({ type: "reset-all" });
  // The undo snapshot lives in a wipeable ref, never a toast closure: sonner
  // keeps action callbacks alive past a master lock.
  const restoreCleared = ws.restoreClearUndo;
  /** Next tick: Radix restores focus to a closing popover's anchor first. */
  const focusMessageBox = () =>
    setTimeout(() => inputElRef.current?.focus(), 0);
  const focusFlowStart = () => {
    setTimeout(() => {
      const input = inputElRef.current;
      if (input) return input.focus();
      document
        .querySelector<HTMLElement>("[data-workspace-card]")
        ?.querySelector<HTMLElement>(
          [
            '[role="combobox"]',
            'input:not([type="file"]):not([disabled])',
            "textarea:not([disabled])",
            "select:not([disabled])",
            "button:not([disabled]):not([tabindex='-1'])",
          ].join(","),
        )
        ?.focus();
    }, 0);
  };
  const resetAndRefocus = () => {
    resetAll();
    focusFlowStart();
  };
  const clear = (toastMessage: string | null, textOnly = false) => {
    ws.stashClearUndo();
    if (textOnly) inputChanged("");
    else resetAll();
    if (toastMessage) {
      toast.message(toastMessage, {
        id: "workspace-text-cleared",
        duration: 4000,
        action: { label: t("workspace_undo"), onClick: restoreCleared },
      });
    }
    focusFlowStart();
  };
  const clearText = () =>
    clear(
      v.done ? null : t("workspace_text_cleared_toast"),
      s.files.length > 0,
    );

  useShortcut({ mod: true, key: "z" }, restoreCleared, {
    enabled: s.clearUndo && s.input.len === 0,
  });

  return { focusMessageBox, clear, clearText, resetAndRefocus };
}
