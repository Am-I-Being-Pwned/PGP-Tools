/**
 * What a typed lookup means -- the ONE place that decides whether
 * "octocat", "alice@example.com" or a hex fingerprint goes to GitHub or
 * to keys.openpgp.org.
 *
 * Pure, and separate from both engines, because the routing rule is the
 * part a user can be surprised by and so is the part that needs a test
 * naming every case. The import field is one field on purpose (getting a
 * key is one question), which makes this function the whole of its
 * behaviour.
 */

import type { KeyserverQuery } from "../keyserver/query";
import { isGithubUsername } from "../github/username";
import { parseKeyserverQuery } from "../keyserver/query";

export type Lookup =
  | { target: "github"; username: string }
  | { target: "keyserver"; query: KeyserverQuery };

/**
 * Route `input`, or null when it is neither a GitHub account name nor a
 * keyserver query.
 *
 * KEYSERVER SHAPES ARE TRIED FIRST, and there is exactly one overlap
 * that decision settles. A GitHub username is alphanumerics and hyphens,
 * so a 40- or 16-character all-hex string satisfies BOTH rules. It is
 * read as a fingerprint or key id: nobody's account is called
 * `d477040c70c2156a5c298549bb7e9101495e6bf7`, everybody's fingerprint
 * is, and a `0x` prefix says so explicitly for anyone who disagrees.
 * (The reverse mistake -- sending a fingerprint to GitHub -- costs the
 * user a "no such account" for a string that plainly is not one.)
 *
 * An address cannot collide at all: no GitHub username contains `@`.
 */
export function classifyLookup(input: string): Lookup | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;

  const query = parseKeyserverQuery(trimmed);
  if (query) return { target: "keyserver", query };

  if (isGithubUsername(trimmed)) return { target: "github", username: trimmed };

  return null;
}
