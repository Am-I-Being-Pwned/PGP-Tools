import { useEffect, useState } from "react";

import type { OperationAction, PendingOperation } from "../lib/messages";

const VALID_ACTIONS = new Set<OperationAction>([
  "encrypt",
  "decrypt",
  "sign",
  "verify",
]);

function isPendingOperation(msg: unknown): msg is PendingOperation {
  if (typeof msg !== "object" || msg === null) return false;
  const obj = msg as Record<string, unknown>;
  return (
    obj.type === "PENDING_OPERATION" &&
    typeof obj.id === "string" &&
    typeof obj.action === "string" &&
    VALID_ACTIONS.has(obj.action as OperationAction) &&
    typeof obj.text === "string" &&
    typeof obj.sourceTabId === "number"
  );
}

export function usePendingOperation() {
  const [pending, setPending] = useState<PendingOperation | null>(null);

  useEffect(() => {
    const listener = (
      message: unknown,
      sender: chrome.runtime.MessageSender,
      sendResponse: (response: unknown) => void,
    ) => {
      if (sender.id !== chrome.runtime.id) return;
      if (isPendingOperation(message)) {
        setPending(message);
        sendResponse({ received: true });
      }
    };

    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  return {
    pending,
    clearPending: () => setPending(null),
  };
}
