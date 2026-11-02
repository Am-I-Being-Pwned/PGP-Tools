/** Expiry choices offered when generating a key. "custom" is a date the
 *  user picks; the rest are fixed spans. */
export type ExpiryOption = "never" | "1y" | "2y" | "3y" | "custom";
export type ExpiryPreset = Exclude<ExpiryOption, "custom">;

const YEAR_SECONDS = 365 * 24 * 60 * 60;

/** 0 means "never expires". */
export const EXPIRY_SECONDS: Record<ExpiryPreset, number> = {
  never: 0,
  "1y": YEAR_SECONDS,
  "2y": 2 * YEAR_SECONDS,
  "3y": 3 * YEAR_SECONDS,
};

export const DEFAULT_EXPIRY: ExpiryPreset = "2y";

/** Seconds from `now` until expiry; 0 for never (or a custom date that
 *  is missing or not in the future). */
export function expiryToSeconds(
  option: ExpiryOption,
  customDate: Date | undefined,
  now: number = Date.now(),
): number {
  if (option === "custom") {
    if (!customDate) return 0;
    const diff = Math.floor((customDate.getTime() - now) / 1000);
    return diff > 0 ? diff : 0;
  }
  return EXPIRY_SECONDS[option];
}
