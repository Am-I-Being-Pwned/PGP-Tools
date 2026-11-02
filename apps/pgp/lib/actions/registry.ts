// Pure registry operations, parameterized on `actions` for testability.

import type { ShortcutKeyEvent } from "../shortcuts";
import type { ActionCtx, PgpAction } from "./types";
import { matchesShortcut } from "../shortcuts";
import { actionName } from "./types";

export interface ResolvedAction {
  action: PgpAction;
  name: string;
  /** Present iff the action cannot run right now (shown dimmed). */
  disabledReason: string | undefined;
}

function resolve(action: PgpAction, ctx: ActionCtx): ResolvedAction {
  return {
    action,
    name: actionName(action, ctx),
    disabledReason: action.disabledReason?.(ctx),
  };
}

export function visibleActions(
  actions: readonly PgpAction[],
  ctx: ActionCtx,
): ResolvedAction[] {
  return actions
    .filter((a) => a.applicable?.(ctx) ?? true)
    .map((a) => resolve(a, ctx));
}

/** Returns disabled matches too, so the caller can toast the reason. */
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

/** Every query token must substring-match name, group or keywords. */
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

/** First-seen group order; ungrouped under "". */
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
