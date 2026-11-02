/**
 * Lone CRs in signed text: text-mode hashing treats them as line breaks
 * but Chrome draws them zero-width, so "Approved:\rNO" reads as
 * "Approved:NO". Not refused (genuine signers produce them); the card goes
 * amber and the CR is drawn.
 */
const LONE_CR = /\r(?!\n)/g;

export function hasLoneCarriageReturn(text: string): boolean {
  return /\r(?!\n)/.test(text);
}

const CR_SYMBOL = "\u240d";

/** Display only: copy/download must use the stored text byte for byte. */
export function showLoneCarriageReturns(text: string): string {
  return text.includes("\r") ? text.replace(LONE_CR, `${CR_SYMBOL}\n`) : text;
}
