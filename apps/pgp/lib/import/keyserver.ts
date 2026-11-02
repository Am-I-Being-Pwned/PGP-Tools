/**
 * A key fetched from keys.openpgp.org, handed straight to
 * {@link prepareImport} -- no second classification path. The worker
 * forwards armor without deciding it is a key; only the wasm engine does.
 */

import type { KeyserverQuery } from "../keyserver/query";
import type { KeyserverKeyFailure } from "../messages";
import type { ContactSource } from "../storage/contacts";
import type { PreparedImport, StoredKeys } from "./prepare";
import type { IncomingKey } from "./types";
import { t, tn } from "../i18n";
import { prepareImport } from "./prepare";

/** Not a URL and never fetched: the only origin literal is in
 *  `lib/keyserver/fetch-key.ts`, and the build audit enforces that. */
export const KEYSERVER_HOST = "keys.openpgp.org";

/** Upsert identity is the canonical query, not the fingerprint, so a
 *  re-fetch after rotation updates the contact instead of adding one. */
export function keyserverSource(
  query: KeyserverQuery,
  fetchedAt: number,
): ContactSource {
  return { type: "keyserver", user: query.value, fetchedAt };
}

export interface PrepareKeyserverOptions {
  omitted?: number;
  now?: number;
}

/**
 * Fetched armor -> the import preview, stamped with provenance.
 *
 * SSH/CRX engines stay OFF: they would only widen what a hostile response
 * could be classified as.
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
      // A new fingerprint for this source replaces that contact's key; say so.
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
 * Is this the key the lookup asked for? The keyserver is an attacker in
 * the threat model, so this is checked: a fingerprint/key-ID query must
 * match the primary or a back-signed SIGNING subkey; an address query a
 * bound, unrevoked User ID.
 *
 * Only signing subkeys: anyone can bind Alice's key to their cert as a
 * flagless/encryption subkey, but `canSign` requires a back-signature
 * made BY the subkey, which needs Alice's secret key.
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

/** Revoked/expired ones still count: they signed what gets looked up. */
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

function emailIn(uid: string): string {
  const bracketed = /<([^<>]+)>\s*$/.exec(uid);
  if (bracketed) return bracketed[1].trim();
  const bare = uid.trim();
  return bare.includes("@") && !/\s/.test(bare) ? bare : "";
}

// ── failure copy ─────────────────────────────────────────────────────

/** Panel copy per failure code; the twin of `githubFailureCopy`.
 *  `not-found` is a notice, not an error. */
export interface KeyserverFailureCopy {
  tone: "error" | "notice";
  message: string;
}

function retryHint(retryAt: number, now: number): string {
  const minutes = Math.ceil((retryAt - now) / 60_000);
  if (minutes <= 1) return t("import_retry_minute");
  if (minutes < 60) return tn("import_retry_minutes", minutes);
  const hours = Math.ceil(minutes / 60);
  return tn("import_retry_hours", hours);
}

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
      // Not an error. keys.openpgp.org only serves confirmed addresses, so
      // missing usually means unverified.
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
