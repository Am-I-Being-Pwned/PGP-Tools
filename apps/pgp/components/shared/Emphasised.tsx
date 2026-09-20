import type { ReactNode } from "react";

/**
 * Render a translated sentence with the given literal terms wrapped in
 * `wrap` (a medium-weight span by default). The terms are the values that
 * were substituted into the message, so they are found by plain string
 * search; this keeps markup out of the message and lets the translator
 * move the term freely. Terms are matched left to right, earliest first.
 */
export function Emphasised({
  text,
  terms,
  wrap = (term, key) => (
    <span key={key} className="font-medium">
      {term}
    </span>
  ),
}: {
  text: string;
  terms: string[];
  wrap?: (term: string, key: number) => ReactNode;
}) {
  const parts: ReactNode[] = [];
  let rest = text;
  let i = 0;
  for (;;) {
    let at = -1;
    let hit = "";
    for (const term of terms) {
      if (term === "") continue;
      const idx = rest.indexOf(term);
      if (idx !== -1 && (at === -1 || idx < at)) {
        at = idx;
        hit = term;
      }
    }
    if (at === -1) break;
    if (at > 0) parts.push(rest.slice(0, at));
    parts.push(wrap(hit, i++));
    rest = rest.slice(at + hit.length);
  }
  if (rest) parts.push(rest);
  return <>{parts}</>;
}
