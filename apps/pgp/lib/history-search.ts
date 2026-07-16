/**
 * Pure search helpers for the history page: entry filtering, match
 * snippets, and highlight splitting. The filter (entryMatchesQuery) and
 * the snippet builder share findMatch, so a row that matched on content
 * can never fail to produce a snippet.
 *
 * All matching is case-insensitive via toLowerCase on both sides.
 * Offsets from the lowercased haystack are used to slice the original,
 * which is exact for every character whose lowercase form has the same
 * length -- true for all of ASCII, accents, CJK, emoji; the lone
 * practical exception ("İ") merely shifts a highlight by a code unit.
 */

import type { HistoryEntry } from "./storage/history";

/** A one-line match preview: `before` + `match` + `after` with runs of
 *  whitespace collapsed (so armored blocks don't render vertically). */
export interface Snippet {
  before: string;
  match: string;
  after: string;
  /** Content continues before `before` (render a leading ellipsis). */
  truncatedStart: boolean;
  /** Content continues after `after` (render a trailing ellipsis). */
  truncatedEnd: boolean;
  /** Non-overlapping occurrences beyond the first. */
  moreMatches: number;
}

/** One run of text, either part of a match or not. Segments always
 *  reassemble to the exact input: join(segments.text) === text. */
export interface HighlightSegment {
  text: string;
  match: boolean;
}

/** Index of the first case-insensitive occurrence of `query` in
 *  `content`, or undefined when absent or the query is empty. */
export function findMatch(content: string, query: string): number | undefined {
  const q = query.toLowerCase();
  if (q === "") return undefined;
  const i = content.toLowerCase().indexOf(q);
  return i === -1 ? undefined : i;
}

/** Count of non-overlapping case-insensitive occurrences. */
export function countMatches(content: string, query: string): number {
  const q = query.toLowerCase();
  if (q === "") return 0;
  const lower = content.toLowerCase();
  let count = 0;
  for (let i = lower.indexOf(q); i !== -1; i = lower.indexOf(q, i + q.length)) {
    count++;
  }
  return count;
}

function collapseWhitespace(s: string): string {
  return s.replace(/\s+/g, " ");
}

/** Build a display snippet around the first match: up to `context`
 *  characters of raw content either side, whitespace-collapsed, with
 *  truncation flags for ellipses. Undefined when the query doesn't
 *  occur (including empty query / query longer than content). */
export function buildSnippet(
  content: string,
  query: string,
  context = 40,
): Snippet | undefined {
  const idx = findMatch(content, query);
  if (idx === undefined) return undefined;
  const end = idx + query.length;
  const rawStart = Math.max(0, idx - context);
  const rawEnd = Math.min(content.length, end + context);
  const truncatedStart = rawStart > 0;
  const truncatedEnd = rawEnd < content.length;
  let before = collapseWhitespace(content.slice(rawStart, idx));
  let after = collapseWhitespace(content.slice(end, rawEnd));
  // A cut point inside a whitespace run leaves a dangling space that
  // would double up with the ellipsis; drop it.
  if (truncatedStart) before = before.trimStart();
  if (truncatedEnd) after = after.trimEnd();
  return {
    before,
    match: collapseWhitespace(content.slice(idx, end)),
    after,
    truncatedStart,
    truncatedEnd,
    moreMatches: countMatches(content, query) - 1,
  };
}

/** Split `text` into alternating plain/match segments covering every
 *  non-overlapping case-insensitive occurrence of `query`. Lossless:
 *  concatenating the segments reproduces `text` exactly. */
export function splitHighlight(
  text: string,
  query: string,
): HighlightSegment[] {
  const q = query.toLowerCase();
  if (q === "" || text === "") return [{ text, match: false }];
  const lower = text.toLowerCase();
  const segments: HighlightSegment[] = [];
  let pos = 0;
  for (
    let i = lower.indexOf(q);
    i !== -1;
    i = lower.indexOf(q, pos)
  ) {
    if (i > pos) segments.push({ text: text.slice(pos, i), match: false });
    segments.push({ text: text.slice(i, i + q.length), match: true });
    pos = i + q.length;
  }
  if (pos < text.length || segments.length === 0) {
    segments.push({ text: text.slice(pos), match: false });
  }
  return segments;
}

/** Whether an entry matches a search query, across op name, recipient
 *  names/fingerprints, captured content, and file names. The content
 *  check goes through findMatch so it can never disagree with
 *  buildSnippet. An empty query matches everything. */
export function entryMatchesQuery(entry: HistoryEntry, query: string): boolean {
  const q = query.toLowerCase();
  return (
    entry.op.includes(q) ||
    entry.recipients.some(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.fingerprint.toLowerCase().includes(q),
    ) ||
    (entry.content !== undefined &&
      findMatch(entry.content, query) !== undefined) ||
    (entry.files?.some((f) => f.name.toLowerCase().includes(q)) ?? false)
  );
}
