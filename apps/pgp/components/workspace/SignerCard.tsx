import type { ReactNode } from "react";

import type { SignerCardState } from "./signer-card";
import { ContactCard } from "../keys/ContactCard";

/** The signer card, from its state. `labelAction` / `noteAction` are the
 *  panel's controls (key details, keyserver lookup); the reader has none. */
export function SignerCard({
  state,
  labelAction,
  noteAction,
}: {
  state: SignerCardState;
  labelAction?: ReactNode;
  noteAction?: ReactNode;
}) {
  return (
    <ContactCard
      readOnly
      verifiedTone={state.tone}
      verifiedLabel={state.label}
      note={state.note}
      labelAction={labelAction}
      noteAction={noteAction}
      contact={state.contact}
      clash={state.clash}
    />
  );
}
