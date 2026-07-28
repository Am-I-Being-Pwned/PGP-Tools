// Browser-global keyboard commands (browser.commands) that open the
// side panel in a specific workspace mode. The manifest half lives in
// wxt.config.ts; the dispatch half in entrypoints/background.ts. Kept
// as a pure module so the mapping is unit-testable.

import type { WorkspaceAction } from "./messages";

/** Manifest command id -> workspace mode. Command ids are shipped in
 *  the manifest and may live in users' chrome://extensions/shortcuts
 *  bindings, so they are stable forever (like action ids). */
export const COMMAND_TO_MODE: Record<string, WorkspaceAction> = {
  "open-encrypt": "encrypt",
  "open-decrypt": "decrypt",
  "open-sign": "sign",
  "open-verify": "verify",
};

/** Resolve a browser.commands id to its workspace mode, or undefined
 *  for commands we don't route (e.g. _execute_action). */
export function commandToMode(command: string): WorkspaceAction | undefined {
  return COMMAND_TO_MODE[command];
}
