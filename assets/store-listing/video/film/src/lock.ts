/**
 * The padlock, as one physical thing: a solid body the shackle's legs run
 * down into. Opening turns the key, springs the shackle up and swings it out
 * on its LEFT leg (the open-lock icon's shape); closing swings it back, drops
 * it in hard enough to squash the body, and turns the key back.
 */
import { clamp, P } from "./time";

/** A damped spring released at t0: 0 → 1 with overshoot set by z. */
export function spr(t: number, t0: number, f = 2.2, z = 0.55) {
  const s = t - t0;
  if (s <= 0) return 0;
  const w = 2 * Math.PI * f, wd = w * Math.sqrt(1 - z * z);
  return 1 - Math.exp(-z * w * s) * (Math.cos(wd * s) + ((z * w) / wd) * Math.sin(wd * s));
}

export interface LockPose { lift: number; swing: number; key: number; click: number }

export function lockPose(t: number, cues: [number, "open" | "close"][], open0: boolean): LockPose {
  let lift = open0 ? 1 : 0, swing = lift, key = lift, click = 0;
  let prev = lift;
  for (const [t0, kind] of cues) {
    const o = kind === "open" ? 1 : 0;
    if (kind === "open") {
      key += (o - prev) * spr(t, t0, 2.6, 0.6);
      lift += (o - prev) * spr(t, t0 + 0.14, 2.1, 0.42);
      swing += (o - prev) * spr(t, t0 + 0.3, 1.9, 0.5);
    } else {
      swing += (o - prev) * spr(t, t0, 2.6, 0.68);
      lift += (o - prev) * spr(t, t0 + 0.16, 2.6, 0.32);
      key += (o - prev) * spr(t, t0 + 0.32, 2.6, 0.6);
      click = Math.max(click, Math.sin(Math.PI * P(t, t0 + 0.2, t0 + 0.55)));
    }
    prev = o;
  }
  return { lift, swing, key, click };
}

/** Draw the lock into `g`, filling a `size` px square, in the 24-unit icon grid. */
export function drawLock(g: CanvasRenderingContext2D, size: number, pose: LockPose, stroke: string, bodyFill: string) {
  g.save();
  g.scale(size / 24, size / 24);
  g.lineWidth = 1.8;
  g.lineCap = "round";
  g.lineJoin = "round";
  g.strokeStyle = stroke;
  // Shackle: legs to y=13, inside the body; lifted, then swung on the left leg.
  g.save();
  g.translate(0, -5 * Math.max(pose.lift, -0.4));
  g.translate(7, 13);
  g.rotate((-30 * pose.swing * Math.PI) / 180);
  g.translate(-7, -13);
  g.beginPath();
  g.moveTo(7, 13); g.lineTo(7, 7); g.arc(12, 7, 5, Math.PI, 0); g.lineTo(17, 13);
  g.stroke();
  g.restore();
  // Body, squashed when the shackle overshoots into it.
  const sq = clamp(-pose.lift, 0, 1);
  g.save();
  g.translate(12, 22);
  g.scale(1 + sq * 0.3, 1 - sq * 0.4);
  g.translate(-12, -22);
  g.beginPath(); g.roundRect(3, 11, 18, 11, 2);
  g.fillStyle = bodyFill; g.fill(); g.stroke();
  // Keyhole, turned by the key.
  g.translate(12, 15.6); g.rotate((90 * pose.key * Math.PI) / 180); g.translate(-12, -15.6);
  g.fillStyle = stroke;
  g.beginPath(); g.arc(12, 15.6, 1.4, 0, Math.PI * 2); g.fill();
  g.beginPath(); g.moveTo(12, 16.6); g.lineTo(12, 18.8); g.stroke();
  g.restore();
  g.restore();
}
