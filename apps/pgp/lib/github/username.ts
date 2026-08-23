/**
 * GitHub username validation and URL construction. Pure -- no I/O, no
 * network, and deliberately no API origin literal of its own -- that
 * string lives in exactly one file, `fetch-keys.ts`, which passes it in
 * as `origin`.
 *
 * This is the most security-relevant file in `lib/github`. The username
 * arrives from the side panel -- the untrusted side of the message
 * boundary -- and is interpolated into a URL path. Without the strict
 * character set below, `username` is an arbitrary path fragment and
 * "fetch a user's SSH keys" becomes an arbitrary-GET primitive against
 * api.github.com.
 */

/**
 * GitHub's own account-name rule: alphanumerics and single hyphens,
 * never leading or trailing a hyphen, at most 39 characters. The
 * `-(?=[A-Za-z0-9])` lookahead is what forbids `--` and a trailing `-`.
 *
 * It admits no `/`, `.`, `%`, `?`, `#`, `@`, `\` or whitespace, so no
 * traversal, no query smuggling, no fragment smuggling, no credentials.
 */
export const GITHUB_USERNAME =
  /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

export function isGithubUsername(s: unknown): s is string {
  return typeof s === "string" && GITHUB_USERNAME.test(s);
}

/**
 * Build the public-keys URL for `username` against `origin`.
 *
 * Belt and braces: the regex above should already make a surprising URL
 * impossible, but we construct with `new URL()` and then assert the
 * origin and the exact pathname anyway. If any encoding quirk -- or a
 * future edit to the regex -- ever let a separator through, this throws
 * instead of issuing the request.
 */
export function githubKeysUrl(username: string, origin: string): URL {
  if (!isGithubUsername(username)) {
    throw new Error("githubKeysUrl: invalid GitHub username");
  }

  const expectedPath = `/users/${username}/keys`;
  const url = new URL(expectedPath, origin);

  if (url.origin !== new URL(origin).origin) {
    throw new Error("githubKeysUrl: unexpected origin");
  }
  if (url.pathname !== expectedPath) {
    throw new Error("githubKeysUrl: unexpected path");
  }
  if (url.search !== "" || url.hash !== "" || url.username || url.password) {
    throw new Error("githubKeysUrl: unexpected URL parts");
  }

  return url;
}
