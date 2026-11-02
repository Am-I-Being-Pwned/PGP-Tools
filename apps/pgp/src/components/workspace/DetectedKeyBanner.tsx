import { Fragment, useEffect, useState, type ReactNode } from "react";

import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { MarkedText } from "~/components/shared/MarkedText";
import { useContacts } from "~/hooks/useContacts";
import { t } from "~/lib/i18n";
import { parseKeys } from "~/lib/pgp/wasm";
import { parseUserId } from "~/lib/utils/key-naming";

/**
 * "There's a public key in here" (pasted, or inside a decrypted/verified
 * message). EVERY key is described, not just the first: Import takes the
 * whole text, so naming one while a second rides along would misdescribe
 * the import. Names go through {@link MarkedText} so lookalikes show.
 */

interface DetectedKey {
  keyId: string;
  name: string;
  known: boolean;
}

interface DetectedKeyBannerProps {
  /** A getter so the armor isn't copied into props or state. */
  getText: () => string;
  /** Bumps with the text, so a second key isn't shown as the first's identity. */
  version: number;
  onImport: (armored: string) => void;
  onReveal?: (keyId: string) => void;
  source: "pasted" | "message";
}

export function DetectedKeyBanner({
  getText,
  version,
  onImport,
  onReveal,
  source,
}: DetectedKeyBannerProps) {
  const { contacts } = useContacts();
  const [keys, setKeys] = useState<DetectedKey[]>([]);

  useEffect(() => {
    let cancelled = false;
    // Must not name whoever the LAST message carried while this parse runs.
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

/** Placeholder for the names in a translated sentence (private-use char). */
const SLOT = "\ue000";

const MAX_NAMES = 4;

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
