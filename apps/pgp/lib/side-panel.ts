/**
 * Side panel / sidebar shim.
 *
 * Chrome exposes `sidePanel`; Firefox exposes `sidebarAction` and has no
 * `sidePanel` at all -- touching it throws, which is why reading
 * `sidePanel.setPanelBehavior` at background startup used to kill the whole
 * background script on Firefox (blank sidebar, no context menu, no commands).
 *
 * Two shape differences the callers have to live with:
 *
 *   1. `sidebarAction.open()` takes no target. Chrome can open the panel
 *      for a specific tab; Firefox opens it for the active window only.
 *      Per-tab targeting silently degrades to per-window there.
 *   2. Firefox has no `openPanelOnActionClick`. `installActionOpener()`
 *      wires the toolbar button up by hand instead.
 *
 * Both APIs are user-gesture-bound, so every caller must still invoke
 * these synchronously inside the gesture handler -- awaiting first makes
 * Chrome reject the open, and Firefox reject it too.
 */

/**
 * `sidebarAction` and `browserAction` are MV2/Firefox-only, so WXT's
 * MV3-shaped `WxtBrowser` type doesn't declare them. Widen locally rather
 * than pretend the whole namespace is optional.
 */
const mv2 = browser as Omit<typeof browser, "browserAction"> & {
  sidebarAction?: { open: () => Promise<void> };
  // Declared non-optional upstream, but it genuinely is absent under MV3 --
  // re-declare it optional so the runtime fallback below isn't dead code.
  browserAction?: typeof browser.action;
};

/** True on Chrome (and anything else implementing MV3's sidePanel). */
export function hasSidePanel(): boolean {
  return typeof browser.sidePanel !== "undefined";
}

/**
 * Open the panel. `target` is honoured on Chrome and ignored on Firefox,
 * which can only open for the active window.
 */
export function openSidePanel(target: {
  tabId?: number;
  windowId?: number;
}): Promise<void> {
  if (hasSidePanel()) {
    return browser.sidePanel.open(
      target as Parameters<typeof browser.sidePanel.open>[0],
    );
  }

  if (typeof mv2.sidebarAction === "undefined") {
    return Promise.reject(new Error("No side panel API available"));
  }
  return mv2.sidebarAction.open();
}

/**
 * Make the toolbar button open the panel.
 *
 * Chrome does this declaratively. Firefox needs a click listener, and
 * because MV2 puts the button under `browserAction`, that is where the
 * listener goes. The listener body must stay synchronous -- an await
 * before `open()` loses the gesture.
 */
export function installActionOpener(): void {
  if (hasSidePanel()) {
    void browser.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
    return;
  }

  const action = mv2.browserAction ?? browser.action;
  action.onClicked.addListener(() => {
    void openSidePanel({}).catch(() => {
      /* already open -- harmless */
    });
  });
}
