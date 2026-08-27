/**
 * keys.openpgp.org query validation and URL construction. Pure -- no
 * I/O, no network, and deliberately no origin literal of its own: that
 * string lives in exactly one file, `fetch-key.ts`, which passes it in
 * as `origin`. The same split `lib/github/username.ts` makes, and for
 * the same reason -- the build audit asserts the origin appears in one
 * built file only.
 *
 * This is the most security-relevant file in `lib/keyserver`. The query
 * arrives from the side panel -- the untrusted side of the message
 * boundary -- and is interpolated into a URL path. Without the strict
 * shapes below, "look up a key" is an arbitrary-GET primitive against
 * keys.openpgp.org.
 */

/** Which VKS endpoint a query resolves to. */
export type KeyserverQueryKind = "email" | "fingerprint" | "keyid";

export interface KeyserverQuery {
  kind: KeyserverQueryKind;
  /** CANONICAL form, already safe to interpolate: an email lowercased,
   *  a fingerprint/key id uppercased with any `0x` prefix and grouping
   *  spaces stripped. This -- not the user's typing -- is what the
   *  request is made for and what the contact's source records, so
   *  looking the same person up twice cannot produce two contacts. */
  value: string;
}

/**
 * Conservative address shape. NOT a full RFC 5322 parser and not trying
 * to be: this decides what may enter a URL path, so a rejected oddity
 * costs a user one paste and an accepted one costs a request we did not
 * intend. It admits no `/`, `?`, `#`, `@` beyond the single separator,
 * `\`, `:` or whitespace -- so no traversal, no query smuggling, no
 * fragment smuggling, no credentials.
 *
 * `%` IS admitted (it is legal atext) and is what
 * {@link keyserverKeyUrl}'s percent-encoding exists to neutralise: it
 * arrives as `%25`, never as the start of an escape the user chose.
 */
const EMAIL =
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

/** Longest address the spec allows. A longer string is not an address
 *  we failed to parse, it is padding. */
const MAX_EMAIL_CHARS = 254;

const HEX_40 = /^[0-9A-F]{40}$/;
const HEX_16 = /^[0-9A-F]{16}$/;

/** Strip the two decorations people paste fingerprints with: the `0x`
 *  prefix and the four-character grouping GnuPG prints. Nothing else --
 *  in particular not `-` or `:`, which are not how either tool renders
 *  one, and admitting them would only widen the charset that reaches
 *  the hex test. */
function normalizeHex(input: string): string {
  const compact = input.replace(/\s+/g, "").toUpperCase();
  return compact.startsWith("0X") ? compact.slice(2) : compact;
}

/**
 * Classify a typed lookup into the query it is, or null when it is
 * none of them.
 *
 * ORDER IS THE DISAMBIGUATION, and there is exactly one ambiguity worth
 * naming: a 40- or 16-character all-hex string is also a syntactically
 * valid GitHub username. It is read as a fingerprint, because nobody's
 * account is called `d477040c70c2156a5c298549bb7e9101495e6bf7` and
 * everybody's fingerprint is -- and `0x` in front of it says so
 * explicitly for anyone who disagrees. `@` cannot collide at all: no
 * GitHub username contains one. See `lib/import/lookup.ts`, which is
 * where that routing decision is actually made and tested.
 */
export function parseKeyserverQuery(input: string): KeyserverQuery | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;

  if (trimmed.includes("@")) {
    const email = trimmed.toLowerCase();
    if (email.length > MAX_EMAIL_CHARS) return null;
    if (!EMAIL.test(email)) return null;
    return { kind: "email", value: email };
  }

  const hex = normalizeHex(trimmed);
  if (HEX_40.test(hex)) return { kind: "fingerprint", value: hex };
  if (HEX_16.test(hex)) return { kind: "keyid", value: hex };
  return null;
}

/** True when `v` is a query this module would itself have produced --
 *  the check the worker runs on anything the panel sends it. Canonical
 *  form is part of the test: a query that differs from what
 *  {@link parseKeyserverQuery} returns is not one we made. */
export function isKeyserverQuery(v: unknown): v is KeyserverQuery {
  if (typeof v !== "object" || v === null) return false;
  const { kind, value } = v as { kind?: unknown; value?: unknown };
  if (typeof value !== "string") return false;
  const reparsed = parseKeyserverQuery(value);
  // The VALUE is compared too, not just the kind. `keyserverKeyUrl`
  // interpolates `query.value` as it stands, so accepting a
  // non-canonical one ("Alice@Example.com") would send a request for a
  // string this module never blessed -- and would file the same person
  // under two different contact sources.
  return (
    reparsed !== null && reparsed.kind === kind && reparsed.value === value
  );
}

const PATH_SEGMENT: Record<KeyserverQueryKind, string> = {
  email: "by-email",
  fingerprint: "by-fingerprint",
  keyid: "by-keyid",
};

/**
 * Build the VKS lookup URL for `query` against `origin`.
 *
 * Belt and braces, exactly as `githubKeysUrl` is: the shapes above
 * should already make a surprising URL impossible, but we construct
 * with `new URL()` and then assert the origin and the exact pathname
 * anyway. If any encoding quirk -- or a future edit to `EMAIL` -- ever
 * let a separator through, this throws instead of issuing the request.
 */
export function keyserverKeyUrl(query: KeyserverQuery, origin: string): URL {
  if (!isKeyserverQuery(query)) {
    throw new Error("keyserverKeyUrl: invalid query");
  }

  // Encoded, not interpolated raw. An address's legal `%`, `+` and `&`
  // are path data, not syntax; `encodeURIComponent` is what says so.
  const expectedPath = `/vks/v1/${PATH_SEGMENT[query.kind]}/${encodeURIComponent(query.value)}`;
  const url = new URL(expectedPath, origin);

  if (url.origin !== new URL(origin).origin) {
    throw new Error("keyserverKeyUrl: unexpected origin");
  }
  if (url.pathname !== expectedPath) {
    throw new Error("keyserverKeyUrl: unexpected path");
  }
  if (url.search !== "" || url.hash !== "" || url.username || url.password) {
    throw new Error("keyserverKeyUrl: unexpected URL parts");
  }

  return url;
}
