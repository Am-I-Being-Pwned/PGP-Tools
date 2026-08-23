import { useEffect, useState } from "react";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { parseKeys } from "../../lib/pgp/wasm";
import { parseUserId } from "../../lib/utils/key-naming";

/**
 * "There's a public key in here" -- offered wherever one turns up: pasted
 * into the message box, or sitting inside a message that was just
 * decrypted or verified (a correspondent sending you their new key is
 * exactly how keys travel).
 *
 * It identifies the key first, so it can say whose it is and -- the part
 * that matters -- shut up about importing a key the user already holds.
 */

interface DetectedKey {
  keyId: string;
  name: string;
  /** Already in contacts: there is nothing to import. */
  known: boolean;
}

interface DetectedKeyBannerProps {
  /** Reads the text containing the key. A getter, not a prop value, so
   *  the armor isn't copied into props or component state. */
  getText: () => string;
  /** Changes whenever the text does, so the lookup re-runs for a second,
   *  different key rather than showing the first one's identity. */
  version: number;
  contacts: PublicContactKey[];
  /** Hand the armor to the import flow. */
  onImport: (armored: string) => void;
  /** Show a key the user already holds, highlighted in the Keys list. */
  onReveal?: (keyId: string) => void;
  /** Where the key turned up; only changes the wording. */
  source: "pasted" | "message";
}

export function DetectedKeyBanner({
  getText,
  version,
  contacts,
  onImport,
  onReveal,
  source,
}: DetectedKeyBannerProps) {
  // Null while the parse is in flight, or if it failed -- the generic
  // wording still applies, so a failure just means less detail.
  const [key, setKey] = useState<DetectedKey | null>(null);

  useEffect(() => {
    let cancelled = false;
    void parseKeys(getText())
      .then((certs) => {
        const cert = certs.at(0);
        if (cancelled || !cert) return;
        const stored = contacts.find(
          (c) => c.keyId.toUpperCase() === cert.keyInfo.keyId.toUpperCase(),
        );
        const uid = (stored?.userIds ?? cert.keyInfo.userIds).at(0) ?? "";
        setKey({
          keyId: cert.keyInfo.keyId,
          name: parseUserId(uid).name || cert.keyInfo.keyId.slice(-8),
          known: !!stored,
        });
      })
      .catch(() => {
        if (!cancelled) setKey(null);
      });
    return () => {
      cancelled = true;
    };
  }, [getText, version, contacts]);

  if (key?.known) {
    // Offering to import a key we already hold is worse than saying
    // nothing: it implies we don't have it.
    return (
      <div className="rounded-md bg-green-500/10 px-3 py-2 text-xs text-green-400">
        You already have {key.name}&apos;s key.{" "}
        <button
          type="button"
          onClick={() => onReveal?.(key.keyId)}
          className="underline"
        >
          Show it in your keys
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-md bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
      {key
        ? `${source === "message" ? "This message contains" : "This is"} ${key.name}'s public key. `
        : source === "message"
          ? "This message contains someone's public key. "
          : "This looks like someone's public key. "}
      <button
        type="button"
        onClick={() => onImport(getText())}
        className="underline"
      >
        Import it as a contact
      </button>
    </div>
  );
}
