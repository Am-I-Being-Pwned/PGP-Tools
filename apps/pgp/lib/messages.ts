/** Workspace operations triggered from the context menu. These map to
 *  modes inside the Encrypt/Decrypt/Sign/Verify view. */
export type WorkspaceAction = "encrypt" | "decrypt" | "sign" | "verify";

/** Import operations triggered from the context menu when the selection
 *  is detected to be an armored key. These route to the Keys tab and
 *  open the Import dialog with the selection prefilled. */
export type ImportAction = "import-public" | "import-private";

export type OperationAction = WorkspaceAction | ImportAction;

export interface PendingOperation {
  type: "PENDING_OPERATION";
  id: string;
  action: OperationAction;
  text: string;
  sourceTabId: number;
  /** ms since epoch. Consumers drop ops older than ~60s to avoid
   *  resurrecting stale selections that were never picked up. */
  createdAt: number;
}

export type RuntimeMessage = PendingOperation;
