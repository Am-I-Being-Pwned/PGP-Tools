/**
 * Which engine a stored key belongs to.
 *
 * The keyring (`ProtectedKeyBlob`) and the contacts store
 * (`PublicContactKey`) each hold records for more than one engine now:
 * OpenPGP certs, and SSH keys used with age. Both stores gained the same
 * optional `kind` field rather than a parallel store, because everything
 * else about the two records is genuinely shared -- the seal, the
 * envelope, the padding, the CRUD, the lock discipline. A second store
 * would have had to reimplement all of it to express one word.
 *
 * ## `kind` is optional, and absent MEANS `"pgp"`
 *
 * Every blob already on a user's disk was written before this field
 * existed and therefore has no `kind`. Those records must keep opening,
 * untouched, forever -- so the field is optional at the type level, and
 * {@link storedKeyKind} is the ONLY way anything reads it. Nothing
 * compares `record.kind` directly; a `record.kind === "pgp"` written by
 * hand somewhere would silently exclude every pre-existing key.
 *
 * The other half of the same rule is on the WRITE side: `kind` is only
 * ever set to `"ssh"`. A PGP record is stored with the field ABSENT,
 * exactly as before, so this change adds no bytes to any existing user's
 * keyring and a downgrade to an older build still reads every PGP key.
 */

export type StoredKeyKind = "pgp" | "ssh";

/** Any stored key record carrying the discriminant. */
export interface KindDiscriminated {
  /** Absent on every record written before SSH support existed, and on
   *  every PGP record written since. Read it through
   *  {@link storedKeyKind}, never directly. */
  kind?: StoredKeyKind;
}

/** The engine a stored record belongs to. Absent means `"pgp"` -- the
 *  migration property the whole design rests on. */
export function storedKeyKind(record: KindDiscriminated): StoredKeyKind {
  return record.kind ?? "pgp";
}

/** True for an OpenPGP record, including every legacy one. */
export function isPgpRecord(record: KindDiscriminated): boolean {
  return storedKeyKind(record) === "pgp";
}

/** True for an SSH record (age engine). */
export function isSshRecord(record: KindDiscriminated): boolean {
  return storedKeyKind(record) === "ssh";
}

/**
 * The `kind` field as it should be WRITTEN, spread into a new record.
 *
 * Returns `{}` for `"pgp"` so the field never appears on a PGP record --
 * see the "write side" note above. Use this instead of assigning `kind`
 * directly, so there is one place that decides what gets persisted.
 */
export function kindField(kind: StoredKeyKind): { kind?: "ssh" } {
  return kind === "ssh" ? { kind: "ssh" } : {};
}
