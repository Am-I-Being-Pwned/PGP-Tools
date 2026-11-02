import type { ReactNode } from "react";

/** Terms are found by string search, keeping markup out of the message. */
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
