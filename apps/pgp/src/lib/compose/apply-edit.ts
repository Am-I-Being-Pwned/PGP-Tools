import type { Edit } from "./text-format";

/**
 * Write an edit via `insertText` so it joins the native undo stack
 * (assigning `.value` wipes it); only the changed span is replaced.
 * Returns true when the input event fired; false means the fallback
 * assigned `.value` and the caller must notify by hand.
 */
export function applyTextareaEdit(
  el: HTMLTextAreaElement,
  edit: Edit,
  focus = true,
): boolean {
  const before = el.value;
  const after = edit.text;
  // `insertText` acts on the focused element; focus is restored after.
  const previous = document.activeElement;
  el.focus();
  if (before !== after) {
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
    let ok: boolean;
    try {
      // Deprecated, but the only way onto the native undo stack.
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
