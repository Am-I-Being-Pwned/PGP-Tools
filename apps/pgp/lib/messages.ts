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

/** Ask the background worker to fetch a GitHub user's public SSH keys.
 *  A request needs a reply, so this is a real message rather than the
 *  one-way `chrome.storage.session` channel used for pending ops. */
export interface GithubKeysRequest {
  type: "GITHUB_KEYS_REQUEST";
  username: string;
}

/**
 * Closed set of failure codes. Tagged codes ONLY -- never prose that
 * came off the network. Whatever GitHub writes in `{"message": ...}`
 * stays in the worker; the panel renders its own copy per code, the
 * same discipline as the `ssh-passphrase-required` AppError code.
 */
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
      /** How many of the account's published keys the worker's own caps
       *  held back (see `lib/github/response.ts`). The panel says so
       *  rather than presenting a truncated list as the whole account.
       *  Optional so an older panel build still type-checks. */
      omitted?: number;
    }
  | {
      ok: false;
      error: GithubKeysFailure;
      /** ms since epoch, only for `rate-limited`, so the panel can say
       *  when access recovers. */
      resetAt?: number;
    };
