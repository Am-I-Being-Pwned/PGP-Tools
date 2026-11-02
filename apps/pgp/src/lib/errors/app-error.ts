/** Classified by code so `presentError` never string-matches our own prose. */
export type AppErrorCode =
  | "key-not-found"
  | "key-locked"
  | "vault-locked"
  | "weak-password"
  | "password-required"
  | "passkey-failed"
  /** Not a failure: the import flow reveals its passphrase field. */
  | "ssh-passphrase-required";

export class AppError extends Error {
  readonly code: AppErrorCode;

  constructor(code: AppErrorCode, message: string) {
    super(message);
    this.name = "AppError";
    this.code = code;
  }
}
