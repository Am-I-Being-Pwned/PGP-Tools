/**
 * Whether a typed confirmation matches the required text (type-to-confirm
 * gates on destructive actions). Leading/trailing whitespace is forgiven —
 * a trailing space from autocomplete shouldn't block the user — but case
 * and inner content must match exactly.
 */
export function confirmTextMatches(expected: string, typed: string): boolean {
  return typed.trim() === expected;
}
