import * as THREE from "three";

/**
 * Takes: recordings of the real extension (apps/pgp/e2e-capture/takes.spec.ts),
 * stored as the distinct frames it showed plus when each appeared. A take
 * plays on a texture; before each film frame, seek() asks every scheduled
 * take for the frame at its own time, so playback is exact, not real-time.
 */
export interface Pointer { t: number; x: number; y: number; down?: boolean }
interface Index { w: number; h: number; dpr: number; duration: number; frames: { t: number; file: string }[] }
export interface Take {
  name: string;
  index: Index;
  pointer: Pointer[];
  /** Times (take seconds) the pointer pressed, in order. */
  clicks: { t: number; x: number; y: number }[];
  tex: THREE.Texture;
  shown: number;
}

const BASE = "/sl/video/ui/takes";
export const takes = new Map<string, Take>();

async function bitmap(url: string) {
  const blob = await (await fetch(url)).blob();
  return createImageBitmap(blob, { imageOrientation: "flipY", premultiplyAlpha: "none" });
}

export async function loadTake(name: string) {
  const index = (await (await fetch(`${BASE}/${name}/frames.json`)).json()) as Index;
  const pointer = (await (await fetch(`${BASE}/${name}/pointer.json`)).json()) as Pointer[];
  const tex = new THREE.Texture();
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.flipY = false; // the bitmap is already flipped
  tex.minFilter = THREE.LinearMipmapLinearFilter;
  tex.anisotropy = 8;
  tex.image = await bitmap(`${BASE}/${name}/${index.frames[0].file}`);
  tex.needsUpdate = true;
  const clicks = pointer.filter((p) => p.down).map(({ t, x, y }) => ({ t, x, y }));
  takes.set(name, { name, index, pointer, clicks, tex, shown: 0 });
}

/** Put the frame for take time `tt` on the take's texture. */
export async function showTake(name: string, tt: number) {
  const take = takes.get(name);
  if (!take) return;
  const f = take.index.frames;
  let lo = 0, hi = f.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (f[mid].t <= tt) lo = mid; else hi = mid - 1; }
  if (lo === take.shown) return;
  const old = take.tex.image as ImageBitmap | undefined;
  const next = await bitmap(`${BASE}/${name}/${f[lo].file}`);
  // Texture storage is allocated once at the first size; a frame of a
  // different size (the squeeze narrows every frame) needs fresh storage,
  // or it is written into a corner of the old one and the rest ghosts.
  if (old && (old.width !== next.width || old.height !== next.height)) take.tex.dispose();
  take.tex.image = next;
  take.tex.needsUpdate = true;
  take.shown = lo;
  old?.close();
}

/** The pointer at take time `tt`: position (panel CSS px) and whether it is pressed. */
export function pointerAt(take: Take, tt: number) {
  const p = take.pointer;
  if (!p.length) return { x: 0, y: 0, down: false };
  if (tt <= p[0].t) return { x: p[0].x, y: p[0].y, down: false };
  for (let i = 1; i < p.length; i++) {
    if (p[i].t >= tt) {
      const a = p[i - 1], b = p[i], k = (tt - a.t) / Math.max(b.t - a.t, 1e-6);
      return { x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k, down: !!a.down };
    }
  }
  const last = p[p.length - 1];
  return { x: last.x, y: last.y, down: false };
}

/** The real ciphertext the encrypt take produced, and Alice's KeyAvatar. */
export const extras = { armor: "", aliceFace: null as null | { p: string[]; c: string } };
export async function loadExtras() {
  extras.armor = (await (await fetch(`${BASE}/armored.asc`)).text()).trim();
  // avatars.js (written by ../avatars.ts from lib/key-avatar) is a script
  // assigning a JSON array; face 0 is Alice, the `standard` fixture.
  const js = await (await fetch("/sl/video/avatars.js")).text();
  const faces = JSON.parse(js.slice(js.indexOf("["), js.lastIndexOf("]") + 1)) as { p: string[]; c: string }[];
  extras.aliceFace = faces[0];
}
