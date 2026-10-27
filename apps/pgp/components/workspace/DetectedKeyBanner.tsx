import type { ReactNode } from "react";
import { Fragment, useEffect, useState } from "react";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { t } from "../../lib/i18n";
import { parseKeys } from "../../lib/pgp/wasm";
import { parseUserId } from "../../lib/utils/key-naming";
import { KeyAvatar } from "../shared/KeyAvatar";
import { MarkedText } from "../shared/MarkedText";

/**
 * "There's a public key in here" -- offered wherever one turns up: pasted
 * into the message box, or sitting inside a message that was just
 * decrypted or verified (a correspondent sending you their new key is
 * exactly how keys travel).
 *
 * It identifies the key first, so it can say whose it is and -- the part
 * that matters -- shut up about importing a key the user already holds.
 *
 * EVERY key is described, not just the first: Import hands the whole text
 * over, so a banner naming one key while a second rides along would be
 * describing a different import from the one it starts. Names are drawn
 * with {@link MarkedText}, so a lookalike letter or an invisible character
 * in a name the sender chose is visible here too.
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
  // Empty while the parse is in flight, or if it failed -- the generic
  // wording still applies, so a failure just means less detail.
  const [keys, setKeys] = useState<DetectedKey[]>([]);

  useEffect(() => {
    let cancelled = false;
    // Forget the previous text's keys at once: until this parse lands,
    // the banner must not name whoever the LAST message carried.
    setKeys([]);
    void parseKeys(getText())
      .then((certs) => {
        if (cancelled) return;
        setKeys(
          certs.map((cert) => {
            const stored = contacts.find(
              (c) => c.keyId.toUpperCase() === cert.keyInfo.keyId.toUpperCase(),
            );
            const uid = (stored?.userIds ?? cert.keyInfo.userIds).at(0) ?? "";
            return {
              keyId: cert.keyInfo.keyId,
              name: parseUserId(uid).name || cert.keyInfo.keyId.slice(-8),
              known: !!stored,
            };
          }),
        );
      })
      .catch(() => {
        if (!cancelled) setKeys([]);
      });
    return () => {
      cancelled = true;
    };
  }, [getText, version, contacts]);

  const key = keys.length === 1 ? keys[0] : null;
  const many = keys.length > 1;
  const allKnown = keys.length > 0 && keys.every((k) => k.known);

  if (allKnown) {
    // Offering to import a key we already hold is worse than saying
    // nothing: it implies we don't have it.
    return (
      <div className="text-good flex items-start gap-2 rounded-xl bg-[#15231b] px-3.5 py-2.5 text-xs">
        <KeyAvatar fingerprint={keys[0].keyId} size={16} />
        <p className="min-w-0 flex-1">
          {many ? (
            <WithNames
              text={t("workspace_detected_keys_known", { names: SLOT })}
              keys={keys}
            />
          ) : (
            <WithNames
              text={t("workspace_detected_key_known", { name: SLOT })}
              keys={keys}
            />
          )}{" "}
          <button
            type="button"
            onClick={() => onReveal?.(keys[0].keyId)}
            className="underline underline-offset-2"
          >
            {t("workspace_detected_key_show")}
          </button>
        </p>
      </div>
    );
  }

  return (
    <div className="bg-card text-muted-foreground flex items-start gap-2 rounded-xl px-3.5 py-2.5 text-xs">
      {keys[0] && <KeyAvatar fingerprint={keys[0].keyId} size={16} />}
      <p className="min-w-0 flex-1">
        {many ? (
          <WithNames
            text={
              source === "message"
                ? t("workspace_detected_keys_in_message", { names: SLOT })
                : t("workspace_detected_keys_pasted", { names: SLOT })
            }
            keys={keys}
          />
        ) : key ? (
          <WithNames
            text={
              source === "message"
                ? t("workspace_detected_key_in_message", { name: SLOT })
                : t("workspace_detected_key_pasted", { name: SLOT })
            }
            keys={keys}
          />
        ) : source === "message" ? (
          t("workspace_detected_key_in_message_anon")
        ) : (
          t("workspace_detected_key_pasted_anon")
        )}{" "}
        <button
          type="button"
          onClick={() => onImport(getText())}
          className="text-foreground underline underline-offset-2"
        >
          {t("workspace_detected_key_import")}
        </button>
      </p>
    </div>
  );
}

/** Stands in for the names in a translated sentence, so they can be
 *  rendered as marked nodes where the translator put them. A private-use
 *  character: it cannot occur in the message text itself. */
const SLOT = "\ue000";

/** At most this many names; the rest are counted ("+3"). */
const MAX_NAMES = 4;

/** `text` with {@link SLOT} replaced by the keys' names, each marked. */
function WithNames({ text, keys }: { text: string; keys: DetectedKey[] }) {
  const shown = keys.slice(0, MAX_NAMES);
  const extra = keys.length - shown.length;
  const names: ReactNode = (
    <>
      {shown.map((k, i) => (
        <Fragment key={k.keyId + i}>
          {i > 0 && ", "}
          <MarkedText text={k.name} />
        </Fragment>
      ))}
      {extra > 0 && ` +${extra}`}
    </>
  );
  const [before, ...after] = text.split(SLOT);
  return (
    <>
      {before}
      {after.length > 0 && names}
      {after.join("")}
    </>
  );
}
