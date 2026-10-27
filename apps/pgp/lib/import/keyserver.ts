/**
 * A key fetched from keys.openpgp.org, turned into the objects the
 * import panel already renders.
 *
 * Deliberately THIN, and that is the whole design. A VKS answer is an
 * armored OpenPGP certificate -- the same bytes a user pastes -- so this
 * hands it straight to {@link prepareImport} rather than growing a
 * second classification path. The GitHub import needed
 * `lib/import/github.ts` because SSH recipient lines are not certs and
 * had no preview shape; this one needs only a provenance stamp and its
 * own failure copy.
 *
 * The background worker forwards the response body's armor WITHOUT
 * deciding it is a key (see `lib/keyserver/response.ts`): the wasm
 * engine behind `prepareImport` is the only thing in this app that gets
 * to say so.
 */

import type { KeyserverQuery } from "../keyserver/query";
import type { KeyserverKeyFailure } from "../messages";
import type { ContactSource } from "../storage/contacts";
import type { PreparedImport, StoredKeys } from "./prepare";
import type { IncomingKey } from "./types";
import { t, tn } from "../i18n";
import { prepareImport } from "./prepare";

/** The host, in one place, for the copy and the provenance label. NOT a
 *  URL and never fetched -- the only origin literal in this app lives in
 *  `lib/keyserver/fetch-key.ts`, and the build audit fails if a second
 *  file names it. */
export const KEYSERVER_HOST = "keys.openpgp.org";

/**
 * The contact's upsert identity: the canonical query it was fetched for.
 *
 * The query, not the fingerprint. Looking `alice@example.com` up again
 * after she rotates her key must UPDATE Alice, not file a second
 * contact -- and her fingerprint is exactly what changed. That is the
 * same reasoning `lib/import/github.ts` gives for keying on the account
 * name, and `sameSource` composites the type in so a keyserver query and
 * a GitHub user of the same name cannot collide.
 */
export function keyserverSource(
  query: KeyserverQuery,
  fetchedAt: number,
): ContactSource {
  return { type: "keyserver", user: query.value, fetchedAt };
}

export interface PrepareKeyserverOptions {
  /** Further blocks the worker's caps held back -- see
   *  `lib/keyserver/response.ts`. */
  omitted?: number;
  /** Injectable clock, for the `fetchedAt` stamp. */
  now?: number;
}

/**
 * Fetched armor -> the preview every other import lands in.
 *
 * `prepareImport` does the classification; this only stamps the
 * provenance onto whatever came back, so the stored contact records
 * where it came from and re-fetching updates that record instead of
 * adding another.
 *
 * The engines are left OFF. A VKS answer is an OpenPGP certificate by
 * content type and by armor header, both already checked in the worker;
 * turning on the SSH or CRX engines here would only widen what a hostile
 * response could be classified as, for no case that can legitimately
 * occur.
 */
export async function prepareKeyserverImport(
  query: KeyserverQuery,
  armored: string,
  stored: StoredKeys,
  options: PrepareKeyserverOptions = {},
): Promise<PreparedImport> {
  const { now = Date.now() } = options;
  const prepared = await prepareImport(armored, stored);
  const source = keyserverSource(query, now);
  return {
    ...prepared,
    keys: prepared.keys.map((key) => {
      if (!answersQuery(key, query)) {
        return {
          ...key,
          status: "rejected" as const,
          rejection: t("import_keyserver_wrong_key", {
            host: KEYSERVER_HOST,
            subject: describeQuery(query),
          }),
        };
      }
      // A re-fetch updates the contact it was fetched for, and a NEW
      // fingerprint there replaces that contact's key -- which the preview
      // must say, not present as an unrelated new key.
      const previous = stored.contacts.find(
        (c) =>
          c.source?.type === "keyserver" &&
          c.source.user === query.value &&
          c.keyId.toUpperCase() !== key.keyId.toUpperCase(),
      );
      return {
        ...key,
        source,
        ...(key.status === "new" && previous
          ? { replaces: previous.userIds[0] ?? previous.keyId }
          : {}),
      };
    }),
  };
}

/**
 * Is this the key the lookup asked for?
 *
 * The threat model names the keyserver and anything on the path to it as
 * attackers, so its answer is checked, not assumed: a fingerprint or
 * key-ID query must return a cert whose primary key, or one of whose
 * back-signed signing subkeys, is that key; an address query a cert
 * whose OWNER bound that address (the engine's `userIds` are bound,
 * unrevoked User IDs only).
 *
 * Why only SIGNING subkeys. Binding a subkey takes the primary key's
 * signature alone, so anyone can bind Alice's public key to their own
 * cert as a flagless (or encryption) subkey -- the engine reports that
 * row as a perfectly good "active" subkey, and a lookup for Alice's key
 * ID would be "answered" by Mallory's cert. A signing subkey is the one
 * kind the SUBKEY must agree to: the engine only reports `canSign` when
 * the binding carries a valid primary-key back-signature made BY the
 * subkey (Sequoia refuses the binding otherwise, and the row comes back
 * "invalid" with every flag false). Mallory cannot make that without
 * Alice's secret key. That is also the case that matters: "Look up
 * signer" asks for the issuer of a signature, which is usually a
 * signing subkey.
 */
export function answersQuery(key: IncomingKey, query: KeyserverQuery): boolean {
  const want = asciiUpper(query.value);
  const candidates = [key.keyId, ...backSignedSubkeys(key)].map(asciiUpper);
  switch (query.kind) {
    case "fingerprint":
      return candidates.some((fpr) => fpr === want);
    case "keyid":
      return candidates.some((fpr) => fpr.endsWith(want));
    case "email":
      return key.userIds.some((uid) => asciiUpper(emailIn(uid)) === want);
  }
}

/** Fingerprints of the subkeys that consented to this cert: signing
 *  subkeys whose binding the engine accepted (see {@link answersQuery}).
 *  A revoked or expired one still counts -- it signed messages while it
 *  was live, and those are what get looked up. */
function backSignedSubkeys(key: IncomingKey): string[] {
  return (
    key.details?.keys
      .filter((k) => !k.isPrimary && k.status !== "invalid" && k.canSign)
      .map((k) => k.fingerprint) ?? []
  );
}

/** ASCII-only case folding. `toUpperCase` maps "ı" and "ſ" onto "I" and
 *  "S", so "alıce@" would answer a query for "alice@". */
function asciiUpper(s: string): string {
  return s.replace(/[a-z]/g, (c) => c.toUpperCase());
}

/** The address in a "Name <addr>" User ID, or a bare-address User ID. */
function emailIn(uid: string): string {
  const bracketed = /<([^<>]+)>\s*$/.exec(uid);
  if (bracketed) return bracketed[1].trim();
  const bare = uid.trim();
  return bare.includes("@") && !/\s/.test(bare) ? bare : "";
}

// ── failure copy ─────────────────────────────────────────────────────

/**
 * What the panel says about each failure code.
 *
 * The worker forwards a tagged code and never the keyserver's own prose
 * (see `lib/messages.ts`), so the wording is decided here -- and once, in
 * a pure function, rather than in a `switch` inside a render. The twin of
 * `githubFailureCopy`, down to the tone rule: `not-found` is the one
 * failure where the user did nothing wrong and nothing is broken, so it
 * is a notice rather than the destructive slot.
 */
export interface KeyserverFailureCopy {
  /** "error" is the destructive slot; "notice" is the amber callout. */
  tone: "error" | "notice";
  message: string;
}

/** Roughly how long until a rate limit lifts, in words. Rounded up, and
 *  vague on purpose -- a precise countdown would just be wrong a second
 *  later. */
function retryHint(retryAt: number, now: number): string {
  const minutes = Math.ceil((retryAt - now) / 60_000);
  if (minutes <= 1) return t("import_retry_minute");
  if (minutes < 60) return tn("import_retry_minutes", minutes);
  const hours = Math.ceil(minutes / 60);
  return tn("import_retry_hours", hours);
}

/** How the query reads back to the user: an address as typed, a
 *  fingerprint in the grouped form every other tool prints. */
function describeQuery(query: KeyserverQuery): string {
  if (query.kind === "email") return query.value;
  return query.value.replace(/(.{4})(?=.)/g, "$1 ");
}

export function keyserverFailureCopy(
  failure: KeyserverKeyFailure,
  query: KeyserverQuery,
  retryAt?: number,
  now: number = Date.now(),
): KeyserverFailureCopy {
  const subject = describeQuery(query);
  switch (failure) {
    case "invalid-query":
      return {
        tone: "error",
        message: t("import_keyserver_invalid_query"),
      };
    case "not-found":
      // Not an error: the lookup worked and the answer is "no key". Said
      // in full because the reason is specific and actionable --
      // keys.openpgp.org only serves an address once its owner has
      // confirmed it, so a missing key usually means unverified rather
      // than nonexistent.
      return {
        tone: "notice",
        message:
          query.kind === "email"
            ? t("import_keyserver_not_found_email", {
                host: KEYSERVER_HOST,
                subject,
              })
            : t("import_keyserver_not_found_fingerprint", {
                host: KEYSERVER_HOST,
                subject,
              }),
      };
    case "offline":
      return {
        tone: "error",
        message: t("import_keyserver_offline", { host: KEYSERVER_HOST }),
      };
    case "rate-limited":
      return {
        tone: "error",
        message: [
          t("import_keyserver_rate_limited", { host: KEYSERVER_HOST }),
          retryAt !== undefined ? retryHint(retryAt, now) : "",
        ]
          .filter(Boolean)
          .join(" "),
      };
    case "server-error":
      return {
        tone: "error",
        message: t("import_keyserver_server_error", { host: KEYSERVER_HOST }),
      };
  }
}
