export type OperationAction = "encrypt" | "decrypt" | "sign" | "verify";

export interface PendingOperation {
  type: "PENDING_OPERATION";
  id: string;
  action: OperationAction;
  text: string;
  sourceTabId: number;
}

export interface SidePanelReady {
  type: "SIDEPANEL_READY";
}

export type RuntimeMessage = PendingOperation | SidePanelReady;
