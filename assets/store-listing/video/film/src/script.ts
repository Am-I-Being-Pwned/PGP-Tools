/**
 * The film's running order, in film seconds. Take beats are derived from
 * each take's own recorded clicks, so the camera and copy land on the real
 * moment Alice is picked or Encrypt is pressed.
 */
import { takes } from "./takes";

// Quick in: the panel is open by 1.4s, up off the window by 2.8s, and the
// pointer is on it at ~3.4s. Everything after is relative to the take.
export const SLIDE = [0.7, 1.4] as const; // Chrome slides the panel in
export const LIFT = [1.7, 2.8] as const; // the panel lifts off the window
/** How far the panel has slid in (0 closed, 1 open): fast out, soft landing. */
export const slideProgress = (t: number) => {
  const x = Math.min(1, Math.max(0, (t - SLIDE[0]) / (SLIDE[1] - SLIDE[0])));
  return 1 - (1 - x) ** 3;
};

export const ENCRYPT_AT = 2.5;
export const ARMOR_OUT = [ENCRYPT_AT + 8.55, ENCRYPT_AT + 9.55] as const; // the message lifts out of the panel
export const ARMOR_LOCK = ENCRYPT_AT + 10.3; // its lock snaps shut
export const DECRYPT_AT = ENCRYPT_AT + 13.2;
/** The armored message flies back in, landing as the decrypt take pastes it. */
export const ARMOR_IN = [DECRYPT_AT + 0.15, DECRYPT_AT + 0.95] as const;
export const TAMPERED_AT = DECRYPT_AT + 4.3;
export const KEYS_AT = TAMPERED_AT + 4.5;
export const END_AT = KEYS_AT + 6.2; // everything falls away; the lockup arrives
export const DURATION = END_AT + 5.6;

/** Which take plays when: [name, film time its t=0 lands on]. In order. */
export const SCHEDULE: [string, number][] = [
  ["encrypt", ENCRYPT_AT],
  ["decrypt", DECRYPT_AT],
  ["tampered", TAMPERED_AT],
  ["keys", KEYS_AT],
];

/** The take on the panel at film time t, and its own time. */
export function activeTake(t: number): { name: string; tt: number } {
  let cur = SCHEDULE[0];
  for (const s of SCHEDULE) if (t >= s[1]) cur = s;
  return { name: cur[0], tt: t - cur[1] };
}

/** Film time of take `name`'s nth click. */
export function click(name: string, n: number) {
  const start = SCHEDULE.find((s) => s[0] === name)?.[1] ?? 0;
  return start + (takes.get(name)?.clicks[n]?.t ?? n * 1.5);
}
/** Back-compat for the encrypt take's clicks (0 recipients, 1 Alice, 2 message, 3 Sign, 4 Encrypt). */
export const encClick = (n: number) => click("encrypt", n);
