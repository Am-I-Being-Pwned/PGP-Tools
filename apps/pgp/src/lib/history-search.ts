/**
 * History search helpers. The filter and snippet builder share findMatch,
 * so a content match always yields a snippet. Lowercased offsets slice the
 * original; "İ" can shift a highlight by one code unit (cosmetic only).
 */

import type { HistoryEntry } from "./storage/history";

/** Whitespace-collapsed so armored blocks don't render vertically. */
export interface Snippet {
  before: string;
  match: string;
  after: string;
  truncatedStart: boolean;
  truncatedEnd: boolean;
  /** Non-overlapping occurrences beyond the first. */
  moreMatches: number;
}

/** Segments always reassemble to the exact input. */
export interface HighlightSegment {
  text: string;
  match: boolean;
}

export function findMatch(content: string, query: string): number | undefined {
  const q = query.toLowerCase();
  if (q === "") return undefined;
  const i = content.toLowerCase().indexOf(q);
  return i === -1 ? undefined : i;
}

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

export function splitHighlight(
  text: string,
  query: string,
): HighlightSegment[] {
  const q = query.toLowerCase();
  if (q === "" || text === "") return [{ text, match: false }];
  const lower = text.toLowerCase();
  const segments: HighlightSegment[] = [];
  let pos = 0;
  for (let i = lower.indexOf(q); i !== -1; i = lower.indexOf(q, pos)) {
    if (i > pos) segments.push({ text: text.slice(pos, i), match: false });
    segments.push({ text: text.slice(i, i + q.length), match: true });
    pos = i + q.length;
  }
  if (pos < text.length || segments.length === 0) {
    segments.push({ text: text.slice(pos), match: false });
  }
  return segments;
}

/** Op, recipients, content and file names; empty query matches all. */
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
