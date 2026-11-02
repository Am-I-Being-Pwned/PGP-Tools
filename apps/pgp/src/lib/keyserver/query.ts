/**
 * keys.openpgp.org query validation and URL construction. Pure, and no
 * origin literal: the build audit asserts it appears only in `fetch-key.ts`.
 * The query comes from the untrusted panel and lands in a URL path; the
 * strict shapes below stop this being an arbitrary-GET primitive.
 */

export type KeyserverQueryKind = "email" | "fingerprint" | "keyid";

export interface KeyserverQuery {
  kind: KeyserverQueryKind;
  /** CANONICAL form (email lowercased; hex uppercased, no `0x`/spaces), so
   *  the same person cannot become two contacts. */
  value: string;
}

/**
 * Conservative address shape, not RFC 5322: admits no `/?#\:`, whitespace
 * or second `@`. `%` is admitted and neutralised by percent-encoding in
 * {@link keyserverKeyUrl}.
 */
const EMAIL =
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

const MAX_EMAIL_CHARS = 254;

const HEX_40 = /^[0-9A-F]{40}$/;
const HEX_16 = /^[0-9A-F]{16}$/;

/** Strip only `0x` and GnuPG's grouping spaces. */
function normalizeHex(input: string): string {
  const compact = input.replace(/\s+/g, "").toUpperCase();
  return compact.startsWith("0X") ? compact.slice(2) : compact;
}

/**
 * Classify a typed lookup, or null. All-hex 40/16 chars is read as a
 * fingerprint/key id even though it is a valid GitHub username; routing is
 * decided and tested in `lib/import/lookup.ts`.
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

/** Worker-side check: `v` must be exactly what {@link parseKeyserverQuery}
 *  would produce, value included (it is interpolated as-is). */
export function isKeyserverQuery(v: unknown): v is KeyserverQuery {
  if (typeof v !== "object" || v === null) return false;
  const { kind, value } = v as { kind?: unknown; value?: unknown };
  if (typeof value !== "string") return false;
  const reparsed = parseKeyserverQuery(value);
  return (
    reparsed !== null && reparsed.kind === kind && reparsed.value === value
  );
}

const PATH_SEGMENT: Record<KeyserverQueryKind, string> = {
  email: "by-email",
  fingerprint: "by-fingerprint",
  keyid: "by-keyid",
};

/** Belt and braces: build with `new URL()` then assert origin and exact
 *  path, so a future regex slip throws instead of issuing the request. */
export function keyserverKeyUrl(query: KeyserverQuery, origin: string): URL {
  if (!isKeyserverQuery(query)) {
    throw new Error("keyserverKeyUrl: invalid query");
  }

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
