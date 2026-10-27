/**
 * Lone carriage returns in signed text.
 *
 * A CR with no LF after it is a line break to some readers (Sequoia's
 * text-mode signature hashing turns \r, \n and \r\n alike into CRLF, and
 * so does a shell reading a script saved on old Mac line endings) and to
 * others nothing at all: Chrome draws it zero-width, so a signature over
 * "Approved:\nNO" verifies over "Approved:\rNO", which reads on screen as
 * "Approved:NO". A genuine signer can produce one, so it is not refused;
 * the card goes amber and the CR is drawn where it is.
 */
const LONE_CR = /\r(?!\n)/g;

export function hasLoneCarriageReturn(text: string): boolean {
  return /\r(?!\n)/.test(text);
}

/** U+240D SYMBOL FOR CARRIAGE RETURN. */
const CR_SYMBOL = "\u240d";

/**
 * The text as the result box DRAWS it: each lone CR as a visible symbol
 * followed by a line break, since that is how the signature read it.
 * Display only -- copy and download take the stored text, byte for byte,
 * so what leaves the panel is still exactly what was signed.
 */
export function showLoneCarriageReturns(text: string): string {
  return text.includes("\r") ? text.replace(LONE_CR, `${CR_SYMBOL}\n`) : text;
}
