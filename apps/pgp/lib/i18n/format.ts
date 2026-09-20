import { uiLanguage } from "./index";

/**
 * Locale-aware date rendering via `Intl`, replacing date-fns `format`
 * and `formatDistanceToNow` in user-facing text. date-fns' `PP`/`PPP`
 * tokens are English-only unless a locale bundle is imported per
 * language; `Intl` already knows Chrome's UI language.
 */

function locale(): string {
  return uiLanguage();
}

function safe<T>(make: () => T, fallback: () => T): T {
  try {
    return make();
  } catch {
    return fallback();
  }
}

/** "20 Sept 2026" style; date-fns `PPP`. */
export function formatDate(input: Date | number): string {
  const d = new Date(input);
  return safe(
    () => new Intl.DateTimeFormat(locale(), { dateStyle: "long" }).format(d),
    () => new Intl.DateTimeFormat("en", { dateStyle: "long" }).format(d),
  );
}

/** "20 Sept 2026" compact; date-fns `PP`. */
export function formatDateShort(input: Date | number): string {
  const d = new Date(input);
  return safe(
    () => new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(d),
    () => new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(d),
  );
}

/** "20 Sept 2026, 14:32" style; replaces `Date#toLocaleString()`, which
 *  follows the OS locale rather than Chrome's UI language. */
export function formatDateTime(input: Date | number): string {
  const d = new Date(input);
  const opts: Intl.DateTimeFormatOptions = {
    dateStyle: "medium",
    timeStyle: "short",
  };
  return safe(
    () => new Intl.DateTimeFormat(locale(), opts).format(d),
    () => new Intl.DateTimeFormat("en", opts).format(d),
  );
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

/** "in 3 days" / "2 hours ago"; date-fns `formatDistanceToNow` with
 *  `addSuffix`. Anything under a minute reads as "now". */
export function formatRelative(input: Date | number, now = Date.now()): string {
  const seconds = Math.round((new Date(input).getTime() - now) / 1000);
  const make = (tag: string) => {
    const rtf = new Intl.RelativeTimeFormat(tag, { numeric: "auto" });
    for (const [unit, size] of UNITS) {
      if (Math.abs(seconds) >= size)
        return rtf.format(Math.round(seconds / size), unit);
    }
    return rtf.format(0, "second");
  };
  return safe(
    () => make(locale()),
    () => make("en"),
  );
}
