import type { useNavStack } from "~/components/shared/useNavStack";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { realIdentity } from "~/lib/utils/key-naming";
import type { KeyDetailsTarget } from "./KeyDetailsPage";

export type RenameTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob }
  | { kind: "contact"; contact: PublicContactKey };

export type DeleteTarget =
  | { kind: "own"; keyBlob: ProtectedKeyBlob }
  | { kind: "contact"; contact: PublicContactKey }
  | { kind: "crx"; keyBlob: CrxSigningKeyBlob };

/** KeysView's own subpage stack (not the app-level `KeysRoute` intent). */
export type KeysSubRoute =
  | { page: "generate" }
  | { page: "import"; initialArmored?: string | null }
  | { page: "details"; target: KeyDetailsTarget }
  | { page: "confirm-delete"; target: DeleteTarget }
  | { page: "bulk-delete" }
  | { page: "bulk-export" }
  | { page: "rename"; target: RenameTarget };

export type KeysNav = ReturnType<typeof useNavStack<KeysSubRoute>>;

/** The subject's real name, under the rename field so an alias never hides it. */
export function realIdentityOf(target: RenameTarget): string {
  if (target.kind === "crx") return target.keyBlob.extensionId;
  const record = target.kind === "own" ? target.keyBlob : target.contact;
  return realIdentity(record.userIds[0] ?? record.keyId);
}

/** Not `BlockStack`: its clip would cut the just-imported ring, so the
 *  end rows take the corners themselves (hence the `>*>*` reach). */
export const LIST_STACK =
  "flex flex-col gap-0.5 [&>*:first-child>*]:rounded-t-xl [&>*:last-child>*]:rounded-b-xl";

/** Namespaced so PGP keys, CRX keys, and contacts share one selection set. */
export const selId = (kind: "pgp" | "crx" | "contact", id: string) =>
  `${kind}:${id}`;

/** A clash holder's details page: the contact if one holds the id, else
 *  the user's own key. */
export function holderDetailsTarget(
  keyId: string,
  contacts: readonly PublicContactKey[],
  ownKeys: readonly ProtectedKeyBlob[],
): KeyDetailsTarget | null {
  const contact = contacts.find((c) => c.keyId === keyId);
  if (contact) return { kind: "contact", contact };
  const own = ownKeys.find((k) => k.keyId === keyId);
  return own ? { kind: "own", keyBlob: own } : null;
}
