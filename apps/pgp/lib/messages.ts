import type { KeyserverQuery } from "./keyserver/query";

export type WorkspaceAction = "encrypt" | "decrypt" | "sign" | "verify";

export type ImportAction = "import-public" | "import-private";

export type OperationAction = WorkspaceAction | ImportAction;

export interface PendingOperation {
  type: "PENDING_OPERATION";
  id: string;
  action: OperationAction;
  text: string;
  sourceTabId: number;
  /** Only this window's panel takes the op, so another open panel can't
   *  show it (or auto-decrypt) on the wrong screen. Absent = any panel. */
  windowId?: number;
  /** ms since epoch; see PENDING_OP_TTL_MS. */
  createdAt: number;
}

export interface GithubKeysRequest {
  type: "GITHUB_KEYS_REQUEST";
  username: string;
}

/** Tagged codes ONLY, never network prose: the panel renders its own copy. */
export type GithubKeysFailure =
  | "invalid-username"
  | "not-found"
  | "no-keys"
  | "offline"
  | "rate-limited"
  | "server-error";

export type GithubKeysResponse =
  | {
      ok: true;
      username: string;
      lines: string[];
      /** Keys held back by the worker's caps, so a truncated list isn't
       *  shown as the whole account. */
      omitted?: number;
    }
  | {
      ok: false;
      error: GithubKeysFailure;
      /** ms since epoch, `rate-limited` only. */
      resetAt?: number;
    };

/** The worker re-derives the canonical query rather than trusting it: the
 *  panel is the untrusted side of this boundary. */
export interface KeyserverKeyRequest {
  type: "KEYSERVER_KEY_REQUEST";
  query: KeyserverQuery;
}

/** Tagged codes ONLY: the 404 body echoes the query (attacker-influenced). */
export type KeyserverKeyFailure =
  "invalid-query" | "not-found" | "offline" | "rate-limited" | "server-error";

export type KeyserverKeyResponse =
  | {
      ok: true;
      /** The query actually requested, used to label the contact. */
      query: KeyserverQuery;
      /** Untrusted: `prepareImport` decides whether it is a cert. */
      armored: string;
      omitted?: number;
    }
  | {
      ok: false;
      error: KeyserverKeyFailure;
      /** ms since epoch, `rate-limited` only. */
      retryAt?: number;
    };
