import type { OperationAction } from "./messages";
import {
  looksLikeAgeMessage,
  OPENSSH_PRIVATE_BEGIN,
  splitSshPublicKeyCandidateLines,
} from "./armor-blocks";

/**
 * Classify selected text by its header to decide which action the side
 * panel should take. Substring / line checks only -- no parsing here, the
 * side panel re-validates.
 *
 * A signed or encrypted message is a message, whatever its text quotes.
 * Only what comes BEFORE the first message header can make a selection
 * an import: a forged signed message whose signed text carries a key
 * block or an SSH line must open on Verify, where the signature fails,
 * not on an import screen that never shows the verdict. The same rule as
 * `looksLikeKey` in `drop-routing.ts`, but by position rather than by
 * `startsWith`, so a stray word (or text the page hid) selected ahead of
 * the header cannot flip it. A key quoted in the signed text is still
 * offered once verified: the key-in-message banner reads the result.
 * A private key inside a message is caught by the workspace itself
 * (`applyDetection`), which keeps it out of the draft.
 *
 * Both engines answer with the SAME four actions. An age file is a
 * `decrypt` and an SSH public key is an `import-public`, because what the
 * user is doing does not change with the format -- only which engine
 * handles it, which is decided downstream where the key is actually
 * parsed.
 */
export function classifyAction(text: string): OperationAction {
  const message = firstMessageHeader(text);
  if (message) {
    // Key checks see only the text ahead of the message.
    const ahead = text.slice(0, message.index);
    return keyAction(ahead) ?? message.action;
  }
  return keyAction(text) ?? (looksLikeAgeMessage(text) ? "decrypt" : "encrypt");
}

const MESSAGE_HEADERS = [
  ["-----BEGIN PGP SIGNED MESSAGE-----", "verify"],
  ["-----BEGIN PGP MESSAGE-----", "decrypt"],
] as const;

/**
 * The earliest OpenPGP message header in `text`, and what it calls for.
 * Earliest, not "whichever is checked first": a signed message whose
 * signed text quotes a `BEGIN PGP MESSAGE` line is still a signed
 * message. Shared with the paste auto-detect in the workspace.
 */
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
  // Checked after the private container, which never contains a public
  // line at column 0 -- so this only ever sees a genuine `.pub` /
  // `authorized_keys` paste.
  //
  // The CANDIDATE splitter, matching `import/prepare.ts` and
  // `drop-routing.ts`: any `<algorithm> AAAA<base64>` line, not just the
  // two types the age engine accepts. Routing must recognise everything
  // the import flow can explain, or a pasted ECDSA / FIDO / `ssh-dss`
  // `.pub` falls through to `encrypt` and the engine's curated refusal
  // never gets a screen to appear on. Fourth instance of the pattern
  // (see the comment in `import/prepare.ts`): the engine decides
  // validity; every layer above it forwards and displays.
  //
  // It cannot steal a message from the branches below: `AAAA` must
  // follow a space at the start of a line, and armored bodies -- PGP,
  // age, OpenSSH -- carry no spaces on their base64 lines, while their
  // header lines (`Version:`, `Comment:`) hold a colon the algorithm
  // token does not admit.
  if (splitSshPublicKeyCandidateLines(text).length > 0) return "import-public";
  // age, armored or binary, is left to the caller: the binary form's
  // magic is ASCII and sits at byte 0, so a paste of it reads as text
  // well enough to route.
  return null;
}
