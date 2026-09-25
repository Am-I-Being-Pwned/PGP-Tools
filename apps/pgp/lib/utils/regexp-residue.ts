/**
 * Drop V8's reference to the last string a regular expression matched.
 *
 * Every successful RegExp match records its subject in the realm's
 * `RegExpMatchInfo` (what the legacy `RegExp.input` / `RegExp.$_` read),
 * and it stays there -- strongly reachable from the native context --
 * until another match SUCCEEDS; a failed match leaves it alone. So a
 * decrypted message any regex matched against (armor sniffing, key
 * detection, a `\S` probe) outlives every reference the app drops, for
 * as long as nothing else in the page happens to match. The app does
 * run regexes over plaintext (the `\S` probe on every keystroke, armor
 * and key detection), so after a wipe the last subject can be the very
 * text just wiped. Seen in the reader-tab heap test as
 * `(Global handles) -> NativeContext -> regexp_last_match_info` -- that
 * instance was Playwright's own injected context, but the mechanism is
 * the same in ours, and this closes it on every wipe.
 *
 * One cheap, guaranteed match on a constant replaces it. Call wherever
 * plaintext is wiped. Removes the reference, not the bytes (JS strings
 * cannot be overwritten) -- the same limit as every other string wipe.
 */
const SCRUB = /-/;

export function forgetLastRegExpMatch(): void {
  SCRUB.exec("-");
}
