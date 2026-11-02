// chrome.commands -> workspace mode (manifest half in wxt.config.ts).

import type { WorkspaceAction } from "./messages";

/** Command ids may live in users' bindings: stable forever. */
export const COMMAND_TO_MODE: Record<string, WorkspaceAction> = {
  "open-encrypt": "encrypt",
  "open-decrypt": "decrypt",
  "open-sign": "sign",
  "open-verify": "verify",
};

export function commandToMode(command: string): WorkspaceAction | undefined {
  return COMMAND_TO_MODE[command];
}
