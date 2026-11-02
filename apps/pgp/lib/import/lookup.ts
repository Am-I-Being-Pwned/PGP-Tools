/** The ONE place that routes a typed lookup to GitHub or keys.openpgp.org. */

import type { KeyserverQuery } from "../keyserver/query";
import { isGithubUsername } from "../github/username";
import { parseKeyserverQuery } from "../keyserver/query";

export type Lookup =
  | { target: "github"; username: string }
  | { target: "keyserver"; query: KeyserverQuery };

/**
 * Route `input`, or null. KEYSERVER SHAPES ARE TRIED FIRST: 40/16-char hex is
 * also a legal GitHub username, and is read as a fingerprint / key id (`0x`
 * makes it explicit). No GitHub username contains `@`.
 */
export function classifyLookup(input: string): Lookup | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;

  const query = parseKeyserverQuery(trimmed);
  if (query) return { target: "keyserver", query };

  if (isGithubUsername(trimmed)) return { target: "github", username: trimmed };

  return null;
}
