import { useEffect, useEffectEvent, useRef } from "react";

import type { Mode } from "./workspace-state";
import { hasOpenSlideOver } from "../shared/SlideOver";

/** Escape double-tap window, and how soon after a clear a third press
 *  also goes back to Encrypt. */
const DOUBLE_TAP_MS = 350;
const RESET_MODE_MS = 700;

/**
 * The workspace's document-level keys. Subpages and the palette own their
 * own Escapes and never let them reach here.
 *
 * Escape: in the full-output view, Back. With something staged, a quick
 * double-tap clears it (undoably); a third press soon after also returns
 * to Encrypt. With nothing staged, focus the message box -- which also
 * ends the recipient box's own Escape chain.
 *
 * Type-to-focus (encrypt and sign): a printable key pressed while nothing
 * typable has focus lands in the message box instead of vanishing.
 */
export function useWorkspaceKeyboard(o: {
  mode: Mode;
  showFullOutput: boolean;
  hasStaged: boolean;
  /** A password row is up: every keystroke is presumed passphrase and must
   *  never be diverted into the (draft-snapshotted) plaintext box. */
  promptOpen: boolean;
  onBack: () => void;
  onClear: () => void;
  onResetMode: () => void;
  focusMessageBox: () => void;
}) {
  const lastEscapeAt = useRef(0);
  const lastClearAt = useRef(0);

  const onEscape = useEffectEvent((e: KeyboardEvent) => {
    if (e.defaultPrevented || hasOpenSlideOver()) return;
    // Escapes closing a dropdown belong to the dropdown.
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
      // Space activates focused controls.
      if (e.key === " ") return;
      if (
        active.closest(
          '[data-radix-popper-content-wrapper], [role="combobox"], [role="listbox"], [role="menu"]',
        )
      ) {
        return;
      }
    }
    const box = document.getElementById("pgp-input");
    // Absent with files staged; a null offsetParent means another tab.
    if (!(box instanceof HTMLTextAreaElement) || box.offsetParent === null) {
      return;
    }
    // Focusing during keydown is enough: the browser inserts the
    // character, so IME/dead keys stay native. Caret to the end.
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
