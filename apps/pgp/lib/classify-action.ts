import type { OperationAction } from "./messages";
import {
  looksLikeAgeMessage,
  OPENSSH_PRIVATE_BEGIN,
  splitSshPublicKeyLines,
} from "./armor-blocks";

/**
 * Classify selected text by its header to decide which action the side
 * panel should take. Substring / line checks only -- no parsing here, the
 * side panel re-validates.
 *
 * Key imports are tested BEFORE messages, and that ordering is
 * load-bearing rather than incidental: a selection holding both (a mail
 * signature that pastes a public key under a signed message) should open
 * the import flow, because importing is the act the user cannot get to
 * any other way from a right-click.
 *
 * Both engines answer with the SAME four actions. An age file is a
 * `decrypt` and an SSH public key is an `import-public`, because what the
 * user is doing does not change with the format -- only which engine
 * handles it, which is decided downstream where the key is actually
 * parsed.
 */
export function classifyAction(text: string): OperationAction {
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
  if (splitSshPublicKeyLines(text).length > 0) return "import-public";
  if (text.includes("-----BEGIN PGP MESSAGE-----")) return "decrypt";
  // age, armored or binary. The binary form's magic is ASCII and sits at
  // byte 0, so a paste of it reads as text well enough to route.
  if (looksLikeAgeMessage(text)) return "decrypt";
  if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) return "verify";
  return "encrypt";
}
