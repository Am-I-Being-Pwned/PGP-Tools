import { useState } from "react";
import { InfoIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyDetailsTarget } from "./KeyDetailsPage";
import { t } from "../../lib/i18n";
import { KeyDetailsPage } from "./KeyDetailsPage";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

/** What the details page shows for `key`. Contacts store the armor under
 *  `armoredPublicKey`; own-key blobs don't -- that field's presence
 *  discriminates the two. */
export function keyDetailsTarget(key: AnyKey): KeyDetailsTarget {
  return "armoredPublicKey" in key
    ? { kind: "contact", contact: key }
    : { kind: "own", keyBlob: key };
}

/** A small info icon that opens the full key-details subpage for `keyData`
 *  -- the exact same overview shown from the Keys tab -- so a selected key
 *  (e.g. an encrypt recipient) can be inspected without leaving the flow.
 *  Rendered read-only: no rename/delete/encrypt-to actions are wired in. */
export function KeyDetailsButton({
  keyData,
  subtle = false,
}: {
  keyData: AnyKey;
  /** A bare icon, for use inside a row that is already a surface. */
  subtle?: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        type="button"
        // Out of the Tab order: it sits between the key picker and the
        // message, and tabbing through it on the way to typing is a stop
        // nobody wants. The same details are a click away, and on the
        // Keys tab for the keyboard.
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
