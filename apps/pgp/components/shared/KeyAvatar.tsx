import { useMemo } from "react";
import { UserIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";

import { AVATAR_SIZE, hasKeyFace, keyAvatar } from "../../lib/key-avatar";

/**
 * A key's pixel-person face (see lib/key-avatar). Decorative: the
 * name and fingerprint next to it carry the meaning, so it is hidden
 * from assistive tech. One SVG with a rect per same-colour run keeps a
 * long keyring cheap to render.
 *
 * Sizes from the design language: 16 in a chip, 32 in a list row, 64+
 * as the hero on key details.
 *
 * Only a whole fingerprint gets a face (see `hasKeyFace`). A signer we
 * know by key id alone gets a plain silhouette: an invented face there
 * would not match the one the key shows once imported.
 */
export function KeyAvatar({
  fingerprint,
  size = 32,
  className,
}: {
  fingerprint: string;
  size?: number;
  className?: string;
}) {
  const face = hasKeyFace(fingerprint);
  const runs = useMemo(() => {
    if (!hasKeyFace(fingerprint)) return [];
    const { cells } = keyAvatar(fingerprint);
    const out: { x: number; y: number; w: number; fill: string }[] = [];
    for (let y = 0; y < AVATAR_SIZE; y++) {
      let x = 0;
      while (x < AVATAR_SIZE) {
        const fill = cells[y * AVATAR_SIZE + x] ?? "transparent";
        let w = 1;
        while (x + w < AVATAR_SIZE && cells[y * AVATAR_SIZE + x + w] === fill)
          w++;
        out.push({ x, y, w, fill });
        x += w;
      }
    }
    return out;
  }, [fingerprint]);

  const radius =
    size <= 16 ? "rounded-[3px]" : size <= 40 ? "rounded-md" : "rounded-xl";

  if (!face) {
    return (
      <span
        aria-hidden="true"
        style={{ width: size, height: size }}
        className={cn(
          "bg-secondary text-muted-foreground inline-flex shrink-0 items-center justify-center",
          radius,
          className,
        )}
      >
        <UserIcon style={{ width: size * 0.55, height: size * 0.55 }} />
      </span>
    );
  }

  return (
    <svg
      aria-hidden="true"
      focusable="false"
      width={size}
      height={size}
      viewBox={`0 0 ${AVATAR_SIZE} ${AVATAR_SIZE}`}
      shapeRendering="crispEdges"
      className={cn("shrink-0", radius, className)}
    >
      {runs.map((r) => (
        <rect
          key={`${r.x}-${r.y}`}
          x={r.x}
          y={r.y}
          width={r.w}
          height={1}
          fill={r.fill}
        />
      ))}
    </svg>
  );
}
