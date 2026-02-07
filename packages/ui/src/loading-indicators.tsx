import { useEffect, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LoadingStyle =
  | "radial-pulse"
  | "diagonal-sweep"
  | "scan-line"
  | "spiral"
  | "double-ripple"
  | "columns"
  | "perimeter-chase"
  | "cross-sweep"
  | "diamond-expand"
  | "sector-scan"
  | "snake"
  | "checker-flip"
  | "rain-drop"
  | "corner-converge"
  | "edge-collapse";

export interface LoadingProps {
  style: LoadingStyle;
  /** 0-100. When provided, renders a progress bar inside the container. */
  progress?: number;
  /** Show dim background cells. Defaults to false. */
  background?: boolean;
  className?: string;
}

// ---------------------------------------------------------------------------
// Animation definitions: (row, col, tick) -> opacity 0..1
// ---------------------------------------------------------------------------

type OpacityFn = (r: number, c: number, tick: number) => number;

const CX = 3; // grid centre index for 7x7

// Snake path is the same for all ticks - precompute once
const SNAKE_PATH: [number, number][] = [];
for (let r = 0; r < 7; r++) {
  if (r % 2 === 0) for (let c = 0; c < 7; c++) SNAKE_PATH.push([r, c]);
  else for (let c = 6; c >= 0; c--) SNAKE_PATH.push([r, c]);
}

const STYLES: Record<LoadingStyle, OpacityFn> = {
  "radial-pulse": (r, c, t) => {
    const dist = Math.sqrt((r - CX) ** 2 + (c - CX) ** 2);
    return Math.max(0.04, ((Math.sin(t * 0.18 - dist * 0.9) + 1) / 2) * 0.9);
  },
  "diagonal-sweep": (r, c, t) => {
    const diag = (r + c) / 14;
    return Math.max(0.04, ((Math.sin(t * 0.14 - diag * 12) + 1) / 2) * 0.85);
  },
  "scan-line": (r, _c, t) => {
    const scanRow = ((t * 0.12) % 11) - 2;
    return Math.max(0.04, Math.max(0, 1 - Math.abs(r - scanRow) * 0.45) * 0.95);
  },
  spiral: (r, c, t) => {
    const dx = c - CX,
      dy = r - CX;
    return Math.max(
      0.04,
      ((Math.sin(
        t * 0.15 -
          Math.sqrt(dx * dx + dy * dy) * 0.7 +
          Math.atan2(dy, dx) * 0.8,
      ) +
        1) /
        2) *
        0.85,
    );
  },
  "double-ripple": (r, c, t) => {
    const d1 = Math.sqrt((r - 1) ** 2 + (c - 1) ** 2);
    const d2 = Math.sqrt((r - 5) ** 2 + (c - 5) ** 2);
    return Math.max(
      0.04,
      ((Math.sin(t * 0.16 - d1 * 1.1) + Math.sin(t * 0.16 - d2 * 1.1 + 1) + 2) /
        4) *
        0.9,
    );
  },
  columns: (r, c, t) => {
    const colWave = Math.sin(t * 0.2 + c * 1.2);
    return Math.max(
      0.04,
      ((colWave + 1) / 2) * (1 - Math.abs(r - 3) / 5) * 0.9,
    );
  },
  "perimeter-chase": (r, c, t) => {
    const perimLen = 24;
    const perimIdx = () => {
      if (r === 0) return c;
      if (c === 6) return 6 + r;
      if (r === 6) return 12 + (6 - c);
      if (c === 0) return 18 + (6 - r);
      return -1;
    };
    const pi = perimIdx();
    if (pi >= 0) {
      const pos = (t * 0.4) % perimLen;
      let diff = Math.abs(pi - pos);
      diff = Math.min(diff, perimLen - diff);
      return Math.max(0.06, Math.max(0, 1 - diff * 0.2) * 0.95);
    }
    return 0.04 + Math.sin(t * 0.05) * 0.03;
  },
  "cross-sweep": (r, c, t) => {
    const distX = Math.abs(c - CX),
      distY = Math.abs(r - CX);
    const crossDist = Math.min(distX, distY);
    const armDist = Math.max(distX, distY);
    return Math.max(
      0.04,
      ((Math.sin(t * 0.18 - armDist * 0.8) + 1) / 2) *
        Math.max(0, 1 - crossDist * 0.35) *
        0.9,
    );
  },
  "diamond-expand": (r, c, t) => {
    const manhattan = Math.abs(r - CX) + Math.abs(c - CX);
    return Math.max(
      0.04,
      ((Math.sin(t * 0.2 - manhattan * 0.7) + 1) / 2) * 0.9,
    );
  },
  "sector-scan": (r, c, t) => {
    const dx = c - CX,
      dy = r - CX;
    const angle = (Math.atan2(dy, dx) + Math.PI) / (2 * Math.PI);
    const sweep = (t * 0.015) % 1;
    let diff = Math.abs(angle - sweep);
    diff = Math.min(diff, 1 - diff);
    const dist = Math.sqrt(dx * dx + dy * dy) / CX;
    return Math.max(
      0.04,
      Math.max(0, 1 - diff * 6) * Math.min(1, dist * 0.8 + 0.3) * 0.9,
    );
  },
  snake: (r, c, t) => {
    const TAIL = 8;
    const head = Math.floor(t * 0.5) % SNAKE_PATH.length;
    let minDist = Infinity;
    for (let s = 0; s < TAIL; s++) {
      const idx = (head - s + SNAKE_PATH.length) % SNAKE_PATH.length;
      const entry = SNAKE_PATH[idx];
      if (entry?.[0] === r && entry[1] === c) minDist = Math.min(minDist, s);
    }
    return minDist < TAIL ? Math.max(0.15, (1 - minDist / TAIL) * 0.95) : 0.04;
  },
  "checker-flip": (r, c, t) => {
    const phase = (r + c) % 2 === 0 ? 0 : Math.PI;
    return Math.max(0.04, ((Math.sin(t * 0.12 + phase) + 1) / 2) * 0.85);
  },
  "rain-drop": (r, c, t) => {
    let max = 0;
    for (let d = 0; d < 3; d++) {
      const dt = t - d * 8;
      const seed = Math.floor(dt / 12) * 137 + d * 57;
      const dr = Math.abs((seed * 13) % 7);
      const dc = Math.abs((seed * 29) % 7);
      const age = (dt % 12) / 12;
      const ring = Math.abs(Math.sqrt((r - dr) ** 2 + (c - dc) ** 2) - age * 5);
      max = Math.max(max, Math.max(0, 1 - ring * 0.6) * Math.max(0, 1 - age));
    }
    return Math.max(0.04, max * 0.9);
  },
  "corner-converge": (r, c, t) => {
    const corners: [number, number][] = [
      [0, 0],
      [0, 6],
      [6, 0],
      [6, 6],
    ];
    const sum = corners.reduce(
      (acc, [cr, cc], i) =>
        acc +
        Math.sin(
          t * 0.14 - Math.sqrt((r - cr) ** 2 + (c - cc) ** 2) * 0.8 + i * 1.5,
        ),
      0,
    );
    return Math.max(0.04, ((sum / 4 + 1) / 2) * 0.85);
  },
  "edge-collapse": (r, c, t) => {
    const edgeDist = Math.min(r, c, 6 - r, 6 - c);
    return Math.max(
      0.04,
      ((Math.sin(t * 0.16 + edgeDist * 1.2) + 1) / 2) * 0.9,
    );
  },
};

// Tick intervals per style (ms)
const INTERVALS: Record<LoadingStyle, number> = {
  "radial-pulse": 80,
  "diagonal-sweep": 80,
  "scan-line": 60,
  spiral: 80,
  "double-ripple": 80,
  columns: 80,
  "perimeter-chase": 50,
  "cross-sweep": 70,
  "diamond-expand": 80,
  "sector-scan": 50,
  snake: 60,
  "checker-flip": 80,
  "rain-drop": 100,
  "corner-converge": 80,
  "edge-collapse": 70,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const HEX = "0123456789ABCDEF";
const randHex = () =>
  (HEX[Math.floor(Math.random() * 16)] ?? "0") +
  (HEX[Math.floor(Math.random() * 16)] ?? "0");

function Cell({ opacity }: { opacity: number }) {
  return (
    <div
      style={{
        width: 22,
        height: 22,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: "'Courier New', monospace",
        fontSize: 9,
        fontWeight: 700,
        color: `rgba(0,255,65,${opacity})`,
        background: `rgba(0,255,65,${opacity * 0.07})`,
        borderRadius: 2,
        textShadow:
          opacity > 0.55 ? `0 0 5px rgba(0,255,65,${opacity * 0.7})` : "none",
        transition: "color 80ms, background 80ms, text-shadow 80ms",
      }}
    >
      {randHex()}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Exported component
// ---------------------------------------------------------------------------

export function Loading({
  style,
  progress,
  background = false,
  className,
}: LoadingProps) {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), INTERVALS[style]);
    return () => clearInterval(id);
  }, [style]);

  const getOpacity = STYLES[style];

  return (
    <div
      className={className}
      style={{
        display: "inline-flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 0,
      }}
    >
      <div
        style={{
          width: 200,
          height: 200,
          background: background ? "#0a0a0a" : "transparent",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: progress !== undefined ? "12px 12px 0 0" : 12,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(7, 22px)",
            gap: 2,
          }}
        >
          {Array.from({ length: 49 }, (_, i) => {
            const r = Math.floor(i / 7),
              c = i % 7;
            const raw = getOpacity(r, c, tick);
            const opacity = background ? raw : raw < 0.1 ? 0 : raw;
            return <Cell key={i} opacity={opacity} />;
          })}
        </div>
      </div>

      {progress !== undefined && (
        <div
          style={{
            width: 200,
            height: 3,
            background: "rgba(0,255,65,0.08)",
            borderRadius: "0 0 12px 12px",
            border: "1px solid #1a1a1a",
            borderTop: "none",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${Math.min(100, Math.max(0, progress))}%`,
              height: "100%",
              background: "rgba(0,255,65,0.55)",
              boxShadow: "0 0 6px rgba(0,255,65,0.4)",
              transition: "width 200ms ease",
            }}
          />
        </div>
      )}
    </div>
  );
}
