/**
 * GitHub username validation and URL construction. Pure; no origin literal
 * (that lives only in `fetch-keys.ts`). The username comes from the
 * untrusted panel into a URL path; the strict charset stops an
 * arbitrary-GET primitive.
 */

/** GitHub's rule: alphanumerics and single inner hyphens, max 39. Admits
 *  no `/.%?#@\` or whitespace. */
const GITHUB_USERNAME = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

export function isGithubUsername(s: unknown): s is string {
  return typeof s === "string" && GITHUB_USERNAME.test(s);
}

/** Belt and braces: build with `new URL()` then assert origin and exact
 *  path, so a future regex slip throws instead of issuing the request. */
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
