// Pure registry operations over a list of PgpActions. The list itself
// lives in definitions.ts; keeping these functions parameterized on
// `actions` makes every code path testable with fakes.

import type { ShortcutKeyEvent } from "../shortcuts";
import type { ActionCtx, PgpAction } from "./types";
import { matchesShortcut } from "../shortcuts";
import { actionName } from "./types";

/** An action resolved against a ctx, ready for the palette to render.
 *  Disabled actions are included WITH their reason -- the palette shows
 *  them dimmed rather than hiding them. */
export interface ResolvedAction {
  action: PgpAction;
  /** Display name, with any dynamic name already resolved. */
  name: string;
  /** Present iff the action cannot run right now. */
  disabledReason: string | undefined;
}

function resolve(action: PgpAction, ctx: ActionCtx): ResolvedAction {
  return {
    action,
    name: actionName(action, ctx),
    disabledReason: action.disabledReason?.(ctx),
  };
}

/** The actions the palette should list for this ctx: everything
 *  applicable, including currently-disabled ones (with their reason). */
export function visibleActions(
  actions: readonly PgpAction[],
  ctx: ActionCtx,
): ResolvedAction[] {
  return actions
    .filter((a) => a.applicable?.(ctx) ?? true)
    .map((a) => resolve(a, ctx));
}

/**
 * Match a keydown against the applicable actions' shortcuts. Returns
 * the resolved action even when disabled -- the caller decides whether
 * to execute or to toast the disabled reason (a shortcut on a
 * disabled action explains itself instead of going dead).
 */
export function findByShortcut(
  actions: readonly PgpAction[],
  event: ShortcutKeyEvent,
  ctx: ActionCtx,
  isMac: boolean,
): ResolvedAction | null {
  for (const action of actions) {
    if (!action.shortcut) continue;
    if (!(action.applicable?.(ctx) ?? true)) continue;
    if (matchesShortcut(event, action.shortcut, isMac)) {
      return resolve(action, ctx);
    }
  }
  return null;
}

/** Case-insensitive palette filter over name + keywords. Substring
 *  match is enough at this action count; every query token must hit. */
export function filterActions(
  resolved: readonly ResolvedAction[],
  query: string,
): ResolvedAction[] {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [...resolved];
  return resolved.filter((r) => {
    const haystack = [
      r.name,
      r.action.group ?? "",
      ...(r.action.keywords ?? []),
    ]
      .join(" ")
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  });
}

/** Group resolved actions for display, preserving first-seen group
 *  order. Ungrouped actions fall under "". */
export function groupActions(
  resolved: readonly ResolvedAction[],
): { group: string; items: ResolvedAction[] }[] {
  const groups = new Map<string, ResolvedAction[]>();
  for (const r of resolved) {
    const key = r.action.group ?? "";
    const list = groups.get(key);
    if (list) list.push(r);
    else groups.set(key, [r]);
  }
  return [...groups.entries()].map(([group, items]) => ({ group, items }));
}
