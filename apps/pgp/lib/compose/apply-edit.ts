import type { Edit } from "./text-format";

/**
 * Write an edit into a textarea THROUGH the browser's editing path, so
 * it lands on the same undo stack as typing: Cmd/Ctrl+Z takes it back,
 * Shift+Z brings it forward, and the user's earlier keystrokes are still
 * behind it. Assigning `.value` would wipe that stack, which is why every
 * tool (formatting, replace, translate) goes through here.
 *
 * Only the span that actually changed is replaced (common prefix and
 * suffix are left alone), so an undo reverts one tool action, not the
 * whole message. `insertText` fires the `input` event, so React's
 * onChange sees the edit like a keystroke; the fallback for a realm
 * where `execCommand` is gone writes the value and reports whether the
 * caller has to notify by hand.
 *
 * Returns true when the input event fired (no manual notify needed).
 */
export function applyTextareaEdit(
  el: HTMLTextAreaElement,
  edit: Edit,
  focus = true,
): boolean {
  const before = el.value;
  const after = edit.text;
  // `insertText` acts on the focused element, so the box takes focus for
  // the write even when the caller wants it back where it was (the find
  // bar's buttons) afterwards.
  const previous = document.activeElement;
  el.focus();
  if (before !== after) {
    // Diff to the changed span.
    let p = 0;
    const max = Math.min(before.length, after.length);
    while (p < max && before[p] === after[p]) p++;
    let s = 0;
    while (
      s < max - p &&
      before[before.length - 1 - s] === after[after.length - 1 - s]
    ) {
      s++;
    }
    const insert = after.slice(p, after.length - s);
    el.setSelectionRange(p, before.length - s);
    let ok = false;
    try {
      // Deprecated but the only way onto the native undo stack; every
      // browser this extension runs in still implements it for textareas.
      ok =
        typeof document.execCommand === "function" &&
        document.execCommand("insertText", false, insert);
    } catch {
      ok = false;
    }
    if (!ok || el.value !== after) {
      el.value = after;
      el.setSelectionRange(edit.start, edit.end);
      restoreFocus(focus, previous);
      return false;
    }
  }
  el.setSelectionRange(edit.start, edit.end);
  restoreFocus(focus, previous);
  return true;
}

function restoreFocus(keep: boolean, previous: Element | null): void {
  if (!keep && previous instanceof HTMLElement) previous.focus();
}
