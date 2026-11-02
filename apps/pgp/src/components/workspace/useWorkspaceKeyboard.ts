import { useEffect, useEffectEvent, useRef, type RefObject } from "react";

import { hasOpenSlideOver } from "~/components/shared/SlideOver";
import type { Mode } from "./workspace-state";

const DOUBLE_TAP_MS = 350;
const RESET_MODE_MS = 700;

/**
 * Document-level keys. Escape: Back from full output; double-tap clears
 * staged input (undoably); a third press soon after returns to Encrypt.
 * Type-to-focus: a stray printable key lands in the message box.
 */
export function useWorkspaceKeyboard(o: {
  mode: Mode;
  showFullOutput: boolean;
  hasStaged: boolean;
  /** Keystrokes are presumed passphrase: never divert them into the
   *  (draft-snapshotted) plaintext box. */
  promptOpen: boolean;
  onBack: () => void;
  onClear: () => void;
  onResetMode: () => void;
  focusMessageBox: () => void;
  inputElRef: RefObject<HTMLTextAreaElement | null>;
}) {
  const lastEscapeAt = useRef(0);
  const lastClearAt = useRef(0);

  const onEscape = useEffectEvent((e: KeyboardEvent) => {
    if (e.defaultPrevented || hasOpenSlideOver()) return;
    const target = e.target as HTMLElement | null;
    if (target?.closest("[data-radix-popper-content-wrapper]")) return;
    if (o.showFullOutput) {
      lastEscapeAt.current = 0;
      o.onBack();
      return;
    }
    const now = Date.now();
    if (!o.hasStaged) {
      lastEscapeAt.current = 0;
      if (now - lastClearAt.current < RESET_MODE_MS && o.mode !== "encrypt") {
        lastClearAt.current = 0;
        o.onResetMode();
      }
      o.focusMessageBox();
      return;
    }
    if (now - lastEscapeAt.current < DOUBLE_TAP_MS) {
      lastEscapeAt.current = 0;
      lastClearAt.current = now;
      o.onClear();
    } else {
      lastEscapeAt.current = now;
    }
  });

  const onPrintable = useEffectEvent((e: KeyboardEvent) => {
    if (o.mode !== "encrypt" && o.mode !== "sign") return;
    if (o.promptOpen) return;
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key.length !== 1 || hasOpenSlideOver()) return;
    // An open dialog owns the keyboard even with focus slipped to <body>.
    if (document.querySelector('[role="dialog"]')) return;
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) {
      if (active.isContentEditable) return;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName)) return;
      if (e.key === " ") return;
      if (
        active.closest(
          '[data-radix-popper-content-wrapper], [role="combobox"], [role="listbox"], [role="menu"]',
        )
      ) {
        return;
      }
    }
    const box = o.inputElRef.current;
    // Absent with files staged; a null offsetParent means another tab.
    if (!box?.offsetParent) return;
    // Focus during keydown; the browser inserts the char (IME stays native).
    box.focus();
    box.setSelectionRange(box.value.length, box.value.length);
  });

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onEscape(e);
      else onPrintable(e);
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);
}
