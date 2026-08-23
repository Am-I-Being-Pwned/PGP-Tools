/** Geometry helpers for "is this element actually on screen, and if not,
 *  what scrolls to reveal it" -- kept out of the hook so the rule can be
 *  tested without a layout engine. */

export interface Bounds {
  top: number;
  bottom: number;
}

/**
 * The nearest ancestor that can actually scroll `el` into view.
 *
 * "Can scroll" is both a style question and a size one: a container with
 * `overflow-y: auto` whose content fits is not a scrollport, and walking
 * past it would blame the wrong element for a card being off screen.
 * Returns null when nothing between `el` and the root scrolls, in which
 * case the viewport is the bound.
 */
export function scrollportOf(el: Element): HTMLElement | null {
  let node = el.parentElement;
  while (node) {
    const overflowY = getComputedStyle(node).overflowY;
    if (
      (overflowY === "auto" || overflowY === "scroll") &&
      node.scrollHeight > node.clientHeight
    ) {
      return node;
    }
    node = node.parentElement;
  }
  return null;
}

/** Whether `rect` sits entirely inside `bounds` on the vertical axis. */
export function isFullyVisible(rect: Bounds, bounds: Bounds): boolean {
  return rect.top >= bounds.top && rect.bottom <= bounds.bottom;
}

/** `el`'s vertical bounds and those of whatever scrolls it. */
export function verticalBounds(el: Element): { rect: Bounds; bounds: Bounds } {
  const port = scrollportOf(el);
  const rect = el.getBoundingClientRect();
  const bounds = port
    ? port.getBoundingClientRect()
    : { top: 0, bottom: window.innerHeight };
  return {
    rect: { top: rect.top, bottom: rect.bottom },
    bounds: { top: bounds.top, bottom: bounds.bottom },
  };
}
