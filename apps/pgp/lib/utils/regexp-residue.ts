/**
 * Drop V8's reference to the last string a regex matched. V8 keeps the
 * last successful match's subject (`RegExp.$_`) reachable from the native
 * context until another match succeeds, so wiped plaintext can outlive
 * every app reference. Call wherever plaintext is wiped. Removes the
 * reference, not the bytes (JS strings can't be overwritten).
 */
const SCRUB = /-/;

export function forgetLastRegExpMatch(): void {
  SCRUB.exec("-");
}
