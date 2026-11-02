/** Type-to-confirm: outer whitespace forgiven, otherwise exact (case too). */
export function confirmTextMatches(expected: string, typed: string): boolean {
  return typed.trim() === expected;
}
