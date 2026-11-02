import { useState } from "react";
import { InfoIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { KeyDetailsPage, type KeyDetailsTarget } from "./KeyDetailsPage";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

/** `armoredPublicKey`'s presence discriminates contacts from own keys. */
export function keyDetailsTarget(key: AnyKey): KeyDetailsTarget {
  return "armoredPublicKey" in key
    ? { kind: "contact", contact: key }
    : { kind: "own", keyBlob: key };
}

/** Opens the key-details subpage without leaving the flow; no
 *  rename/delete/encrypt-to actions are wired in. */
export function KeyDetailsButton({
  keyData,
  subtle = false,
}: {
  keyData: AnyKey;
  subtle?: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        type="button"
        // Out of the Tab order: it sits between the key picker and the message.
        tabIndex={-1}
        variant={subtle ? "ghost" : "outline"}
        aria-label={t("keys_key_details")}
        title={t("keys_key_details")}
        className={
          subtle
            ? "text-muted-foreground hover:text-foreground size-7 shrink-0"
            : "text-muted-foreground hover:text-foreground h-auto shrink-0 px-2"
        }
        onClick={() => setOpen(true)}
      >
        <InfoIcon className="h-4 w-4" />
      </Button>
      {open && (
        <KeyDetailsPage
          target={keyDetailsTarget(keyData)}
          onBack={() => setOpen(false)}
        />
      )}
    </>
  );
}
