export interface Bounds {
  top: number;
  bottom: number;
}

/** Nearest ancestor that actually scrolls (overflow auto/scroll AND
 *  content overflowing); null means the viewport. */
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

export function isFullyVisible(rect: Bounds, bounds: Bounds): boolean {
  return rect.top >= bounds.top && rect.bottom <= bounds.bottom;
}

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
