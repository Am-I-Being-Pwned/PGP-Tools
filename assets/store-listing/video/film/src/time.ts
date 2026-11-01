/**
 * Time and motion helpers. The whole film is a pure function of `T.t`:
 * seek() sets it, then everything (3D and DOM) reads it. Nothing reads a
 * clock, so a frame is the same whether it is rendered live or stepped.
 */
export const T = { t: 0 };

export const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x));
/** Progress of t through [a, b], clamped to 0..1. */
export const P = (t: number, a: number, b: number) => clamp((t - a) / (b - a));
export const lerp = (a: number, b: number, x: number) => a + (b - a) * x;

/** Linear's curve: fast out, long smooth settle, no overshoot. */
export const expo = (x: number) => (x >= 1 ? 1 : 1 - 2 ** (-10 * x));
export const io = (x: number) => (x < 0.5 ? 4 * x * x * x : 1 - (-2 * x + 2) ** 3 / 2);
export const io5 = (x: number) => (x < 0.5 ? 16 * x ** 5 : 1 - (-2 * x + 2) ** 5 / 2);
export const out5 = (x: number) => 1 - (1 - x) ** 5;

/** 0→1 entering over [a, a+fi], 1→0 leaving over [b-fo, b]. */
export const win = (t: number, a: number, b: number, fi = 0.4, fo = 0.4) =>
  Math.min(expo(P(t, a, a + fi)), 1 - io(P(t, b - fo, b)));

type Vec = number[];
/**
 * Keyframes [[t, [..values]], ...]. Between neighbours the value moves on
 * `ease`; before the first and after the last it holds.
 */
export function keys(k: [number, Vec][], t: number, ease = io5): Vec {
  if (t <= k[0][0]) return k[0][1];
  for (let i = 1; i < k.length; i++) {
    if (t <= k[i][0]) {
      const [t0, a] = k[i - 1], [t1, b] = k[i];
      const x = ease(P(t, t0, t1));
      return a.map((v, j) => lerp(v, b[j], x));
    }
  }
  return k[k.length - 1][1];
}

/** Deterministic hash → [0, 1). */
export const rnd = (a: number, b = 0) => {
  let h = (a * 374761393 + b * 668265263) | 0;
  h = (h ^ (h >>> 13)) * 1274126177;
  return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
};

/**
 * Keyframes through a monotone cubic (Hermite) spline: velocity is
 * continuous through every key, so a chain of moves reads as one smooth
 * camera move rather than a series of stops and starts. Where a value holds
 * or turns back, its tangent is zero (no overshoot, holds stay still). Two
 * keys less than 0.01s apart are a cut: each side is its own spline.
 */
export function smoothKeys(k: [number, Vec][], t: number): Vec {
  const segs: [number, Vec][][] = [];
  let cur: [number, Vec][] = [k[0]];
  for (let i = 1; i < k.length; i++) {
    if (k[i][0] - k[i - 1][0] < 0.01) { segs.push(cur); cur = [k[i]]; } else cur.push(k[i]);
  }
  segs.push(cur);
  let seg = segs[0];
  for (const s of segs) if (t >= s[0][0]) seg = s;
  return hermite(seg, t);
}

function tangent(k: [number, Vec][], i: number, j: number) {
  if (i === 0 || i === k.length - 1) return 0;
  const d0 = (k[i][1][j] - k[i - 1][1][j]) / (k[i][0] - k[i - 1][0]);
  const d1 = (k[i + 1][1][j] - k[i][1][j]) / (k[i + 1][0] - k[i][0]);
  if (d0 * d1 <= 0) return 0; // a hold or a turn: stop here
  return 2 / (1 / d0 + 1 / d1); // harmonic mean keeps it monotone
}

function hermite(k: [number, Vec][], t: number): Vec {
  if (t <= k[0][0]) return k[0][1];
  const last = k[k.length - 1];
  if (t >= last[0]) return last[1];
  let i = 0;
  while (t > k[i + 1][0]) i++;
  const [t0, p0] = k[i], [t1, p1] = k[i + 1], h = t1 - t0, s = (t - t0) / h;
  const h00 = 2 * s ** 3 - 3 * s ** 2 + 1, h10 = s ** 3 - 2 * s ** 2 + s, h01 = -2 * s ** 3 + 3 * s ** 2, h11 = s ** 3 - s ** 2;
  return p0.map((v, j) => h00 * v + h10 * h * tangent(k, i, j) + h01 * p1[j] + h11 * h * tangent(k, i + 1, j));
}
