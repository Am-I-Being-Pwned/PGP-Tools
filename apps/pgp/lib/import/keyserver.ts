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
    keys: prepared.keys.map((key) => ({ ...key, source })),
  };
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
  if (minutes <= 1) return "Try again in a minute.";
  if (minutes < 60) return `Try again in about ${minutes} minutes.`;
  const hours = Math.ceil(minutes / 60);
  return `Try again in about ${hours} hour${hours === 1 ? "" : "s"}.`;
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
        message:
          "That isn't an email address or a key fingerprint. Use the address the key is published under, or paste the full 40-character fingerprint.",
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
            ? `${KEYSERVER_HOST} has no key for ${subject}. It only publishes an address once the key's owner has confirmed it, so they may have a key there that this lookup can't find - ask them for it directly, or look it up by fingerprint.`
            : `${KEYSERVER_HOST} has no key with the fingerprint ${subject}. Check it against the one you were given - a single wrong character is enough.`,
      };
    case "offline":
      return {
        tone: "error",
        message: `Couldn't reach ${KEYSERVER_HOST}. Check your connection and try again.`,
      };
    case "rate-limited":
      return {
        tone: "error",
        message: [
          `${KEYSERVER_HOST} is rate-limiting this network.`,
          retryAt !== undefined ? retryHint(retryAt, now) : "",
        ]
          .filter(Boolean)
          .join(" "),
      };
    case "server-error":
      return {
        tone: "error",
        message: `${KEYSERVER_HOST} couldn't answer just now. Try again in a moment.`,
      };
  }
}
