import { useState } from "react";
import { InfoIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { KeyDetailsTarget } from "./KeyDetailsPage";
import { KeyDetailsPage } from "./KeyDetailsPage";

type AnyKey = ProtectedKeyBlob | PublicContactKey;

/** A small info icon that opens the full key-details subpage for `keyData`
 *  -- the exact same overview shown from the Keys tab -- so a selected key
 *  (e.g. an encrypt recipient) can be inspected without leaving the flow.
 *  Rendered read-only: no rename/delete/encrypt-to actions are wired in. */
export function KeyDetailsButton({ keyData }: { keyData: AnyKey }) {
  const [open, setOpen] = useState(false);

  // Contacts store the armor under `armoredPublicKey`; own-key blobs don't
  // -- that field's presence discriminates the two for the details target.
  const target: KeyDetailsTarget =
    "armoredPublicKey" in keyData
      ? { kind: "contact", contact: keyData }
      : { kind: "own", keyBlob: keyData };

  return (
    <>
      <Button
        type="button"
        variant="outline"
        aria-label="Key details"
        title="Key details"
        className="text-muted-foreground hover:text-foreground h-auto shrink-0 px-2"
        onClick={() => setOpen(true)}
      >
        <InfoIcon className="h-4 w-4" />
      </Button>
      {open && <KeyDetailsPage target={target} onBack={() => setOpen(false)} />}
    </>
  );
}
