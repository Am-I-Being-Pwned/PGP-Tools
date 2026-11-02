import type { OperationAction } from "./messages";
import {
  looksLikeAgeMessage,
  OPENSSH_PRIVATE_BEGIN,
  splitSshPublicKeyCandidateLines,
} from "./armor-blocks";

/**
 * Pick the panel action for selected text by header (no parsing; the panel
 * re-validates). Only text BEFORE the first message header can make it an
 * import: a forged signed message quoting a key must open on Verify, where
 * the signature fails, not on an import screen. Both engines map to the
 * same actions; the engine is chosen downstream.
 */
export function classifyAction(text: string): OperationAction {
  const message = firstMessageHeader(text);
  if (message) {
    const ahead = text.slice(0, message.index);
    return keyAction(ahead) ?? message.action;
  }
  return keyAction(text) ?? (looksLikeAgeMessage(text) ? "decrypt" : "encrypt");
}

const MESSAGE_HEADERS = [
  ["-----BEGIN PGP SIGNED MESSAGE-----", "verify"],
  ["-----BEGIN PGP MESSAGE-----", "decrypt"],
] as const;

/** The EARLIEST message header (a signed message quoting `BEGIN PGP
 *  MESSAGE` is still signed). Shared with workspace paste auto-detect. */
export function firstMessageHeader(
  text: string,
): { index: number; action: "verify" | "decrypt" } | null {
  let best: { index: number; action: "verify" | "decrypt" } | null = null;
  for (const [header, action] of MESSAGE_HEADERS) {
    const index = text.indexOf(header);
    if (index >= 0 && (!best || index < best.index)) best = { index, action };
  }
  return best;
}

function keyAction(text: string): OperationAction | null {
  if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
    return "import-public";
  }
  if (text.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
    return "import-private";
  }
  if (text.includes(OPENSSH_PRIVATE_BEGIN)) return "import-private";
  // Candidate splitter (any algorithm) so unsupported `.pub`s still reach
  // the engine's refusal; the engine decides validity. Can't steal armored
  // messages: their base64 lines have no spaces.
  if (splitSshPublicKeyCandidateLines(text).length > 0) return "import-public";
  return null;
}
