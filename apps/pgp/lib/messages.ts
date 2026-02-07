export type OperationAction = "encrypt" | "decrypt" | "sign" | "verify";

export interface PendingOperation {
  type: "PENDING_OPERATION";
  id: string;
  action: OperationAction;
  text: string;
  sourceTabId: number;
}

export interface ImportKeyFromLink {
  type: "IMPORT_KEY_FROM_LINK";
  url: string;
  armoredKey?: string; // populated if background managed to fetch it
  error?: string; // populated if fetch failed
}

export interface AutoDecryptDownload {
  type: "AUTO_DECRYPT_DOWNLOAD";
  fileName: string;
  /** Base64-encoded file content */
  contentBase64: string;
}

export interface SidePanelReady {
  type: "SIDEPANEL_READY";
}

export type RuntimeMessage =
  | PendingOperation
  | ImportKeyFromLink
  | AutoDecryptDownload
  | SidePanelReady;
