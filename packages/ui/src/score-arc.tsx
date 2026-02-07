interface ScoreArcProps {
  score: number;
  className?: string;
}

function arcColor(score: number): string {
  if (score >= 80) return "#10b981";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

/**
 * Circular arc gauge showing a 0-100 security score.
 * The arc spans 270 degrees, opening at the bottom.
 * Size is controlled via className (e.g. "w-36 h-36").
 */
export function ScoreArc({ score, className = "w-40 h-40" }: ScoreArcProps) {
  const cx = 50;
  const cy = 50;
  const r = 36;
  const circumference = 2 * Math.PI * r;
  const trackArc = circumference * 0.75;
  const fillArc = trackArc * (score / 100);
  const color = arcColor(score);

  return (
    <div className={`relative ${className}`}>
      <svg viewBox="0 0 100 100" className="h-full w-full">
        <defs>
          <filter id="score-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Track */}
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          className="stroke-muted"
          strokeWidth="6"
          strokeDasharray={`${trackArc} ${circumference}`}
          strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
        />

        {/* Fill */}
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={`${fillArc} ${circumference}`}
          strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
          filter="url(#score-glow)"
        />
      </svg>

      {/* Text overlay - HTML flexbox for reliable centering */}
      <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 pt-5">
        <span className="text-foreground text-2xl leading-none font-bold tabular-nums">
          {score}
        </span>
        <span className="text-muted-foreground text-[0.5rem] leading-none font-medium tracking-[0.15em] uppercase">
          Score
        </span>
      </div>
    </div>
  );
}
