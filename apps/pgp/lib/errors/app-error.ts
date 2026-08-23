/** Machine-readable causes for errors thrown by our own lib code.
 *  `presentError` maps each code to curated user-facing copy, so
 *  classification never depends on string-matching our own messages
 *  (WASM/Sequoia strings still need substring matching -- see present.ts). */
export type AppErrorCode =
  | "key-not-found"
  | "key-locked"
  | "vault-locked"
  | "weak-password"
  | "password-required"
  | "passkey-failed"
  /** An imported SSH key is passphrase-protected and none was given.
   *  Not a failure: the import flow reveals its passphrase field and
   *  retries from the same step. */
  | "ssh-passphrase-required";

/**
 * An error from code we control, tagged with a stable cause. The message
 * stays human-readable (call sites that show `e.message` directly keep
 * working); the code is what the presentation layer classifies on.
 */
export class AppError extends Error {
  readonly code: AppErrorCode;

  constructor(code: AppErrorCode, message: string) {
    super(message);
    this.name = "AppError";
    this.code = code;
  }
}
