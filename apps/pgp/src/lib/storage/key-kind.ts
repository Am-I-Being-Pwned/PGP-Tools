/**
 * Which engine a stored key belongs to (OpenPGP or SSH/age). The keyring
 * and contacts stores share one optional `kind` field instead of parallel
 * stores.
 *
 * Absent MEANS "pgp": every pre-existing record has no `kind`. READ it only
 * through {@link storedKeyKind} (a hand-written `kind === "pgp"` would drop
 * every legacy key). WRITE it only as "ssh" via {@link kindField}, so PGP
 * records stay byte-identical and older builds still read them.
 */

export type StoredKeyKind = "pgp" | "ssh";

/** Any stored key record carrying the discriminant. */
export interface KindDiscriminated {
  /** Absent on legacy and PGP records. Read via {@link storedKeyKind}. */
  kind?: StoredKeyKind;
}

/** The engine a stored record belongs to; absent means "pgp". */
export function storedKeyKind(record: KindDiscriminated): StoredKeyKind {
  return record.kind ?? "pgp";
}

/** True for an OpenPGP record, including every legacy one. */
export function isPgpRecord(record: KindDiscriminated): boolean {
  return storedKeyKind(record) === "pgp";
}

export function isSshRecord(record: KindDiscriminated): boolean {
  return storedKeyKind(record) === "ssh";
}

/** The `kind` field to spread into a new record: `{}` for "pgp". */
export function kindField(kind: StoredKeyKind): { kind?: "ssh" } {
  return kind === "ssh" ? { kind: "ssh" } : {};
}
