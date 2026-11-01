import { Environment, Lightformer, RoundedBox, useTexture } from "@react-three/drei";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Bloom, EffectComposer, Noise, Vignette } from "@react-three/postprocessing";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";

import { drawLock, lockPose } from "./lock";
import { screenMaterial } from "./ScreenMaterial";
import {
  slideProgress,
  activeTake, ARMOR_IN, ARMOR_LOCK, ARMOR_OUT, click, DECRYPT_AT, encClick, END_AT, KEYS_AT, LIFT, SLIDE, TAMPERED_AT,
} from "./script";
import { extras, pointerAt, takes } from "./takes";
import { clamp, expo, io, lerp, P, smoothKeys, T } from "./time";

export { DURATION } from "./script";

// World scale: 200 capture px = 1 unit. The Chrome captures are 3200x2000
// (a 1600x1000 window on a 2x display), so the window is 16 x 10 units.
const PX = 1 / 200;
const WIN_W = 3200 * PX, WIN_H = 2000 * PX, WIN_D = 0.3;
const FACE = WIN_D / 2 + 0.002; // screens sit just proud of the slab's front
// The side panel in the open-window capture (capture px): its whole card,
// and the page area inside it, which is exactly a take (360x865 CSS px).
const OUTER = { x0: 2448, y0: 160, x1: 3196, y1: 1996 };
const PAGE = { x0: 2462, y0: 252, x1: 3182, y1: 1982 };
const OW = (OUTER.x1 - OUTER.x0) * PX, OH = (OUTER.y1 - OUTER.y0) * PX;
const OCX = ((OUTER.x0 + OUTER.x1) / 2 - 1600) * PX, OCY = -((OUTER.y0 + OUTER.y1) / 2 - 1000) * PX;
const PW = (PAGE.x1 - PAGE.x0) * PX, PH = (PAGE.y1 - PAGE.y0) * PX;
const PCX = ((PAGE.x0 + PAGE.x1) / 2 - (OUTER.x0 + OUTER.x1) / 2) * PX;
const PCY = -((PAGE.y0 + PAGE.y1) / 2 - (OUTER.y0 + OUTER.y1) / 2) * PX;
const OUV = { u0: OUTER.x0 / 3200, u1: OUTER.x1 / 3200, v0: 1 - OUTER.y1 / 2000, v1: 1 - OUTER.y0 / 2000 };
// Where the panel ends up once lifted (window-local), and its scale.
const LIFTED = new THREE.Vector3(OCX - 0.35, OCY + 0.15, FACE + 1.9);
const LIFT_SCALE = 1.03;
const TAKE_W = 360, TAKE_H = 865;
// The page area in the Chrome-window captures (capture px): it starts under
// the toolbar at y=174 and, with the panel open, is 2444 px wide.
const SQ_Y0 = 174, SQ_H = 2000 - SQ_Y0, SQ_OPEN = 2444;
// The armored-message card: 700x788 CSS px, at 0.006 units per px.
const CARD_PX = [700, 788] as const, CARD_U = 0.006;
const CARD_AT = new THREE.Vector3(LIFTED.x - 4.5, LIFTED.y + 0.55, LIFTED.z + 0.9);

/** A point on the take's page (take CSS px) in panel-local coordinates. */
const onPage = (x: number, y: number, z = 0) =>
  new THREE.Vector3(PCX - PW / 2 + (x / TAKE_W) * PW, PCY + PH / 2 - (y / TAKE_H) * PH, z);
/** The same point once the panel has lifted, in window-local coordinates. */
const liftedPoint = (x: number, y: number) => onPage(x, y).multiplyScalar(LIFT_SCALE).add(LIFTED);

function canvasTex(c: HTMLCanvasElement) {
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 8;
  return tex;
}
function softShadow(w: number, h: number, blur: number) {
  const pad = blur * 2;
  const c = document.createElement("canvas");
  c.width = w + pad * 2; c.height = h + pad * 2;
  const g = c.getContext("2d")!;
  g.filter = `blur(${blur}px)`;
  g.fillStyle = "#000";
  g.beginPath(); g.roundRect(pad, pad, w, h, 24); g.fill();
  return { tex: canvasTex(c), sx: c.width / w, sy: c.height / h };
}
/** The macOS pointer, drawn once at high resolution. */
function cursorTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  g.scale(128 / 22, 128 / 22);
  g.lineJoin = "round";
  const p = new Path2D("M3 2 L3 18 L7.5 13.8 L10.4 20.2 L13.2 19 L10.4 12.7 L16.6 12.7 Z");
  g.shadowColor = "rgba(0,0,0,0.45)"; g.shadowBlur = 1.5; g.shadowOffsetY = 0.6;
  g.fillStyle = "#fff"; g.fill(p);
  g.shadowColor = "transparent";
  g.strokeStyle = "#000"; g.lineWidth = 1.2; g.stroke(p);
  return canvasTex(c);
}
function ringTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  g.fillStyle = "rgba(255,255,255,0.55)";
  g.beginPath(); g.arc(64, 64, 60, 0, Math.PI * 2); g.fill();
  return canvasTex(c);
}

/**
 * The armored-message card, drawn in the design language: a block stack
 * (flat #151515 blocks, 2px gaps) with the recipient on top and the real
 * ciphertext below. The lock block is left blank; it is its own surface.
 */
const LOCK_BLOCK = 120; // CSS px square, top-left of the card
function cardTexture() {
  const [w, h] = CARD_PX, s = 2;
  const c = document.createElement("canvas");
  c.width = w * s; c.height = h * s;
  const g = c.getContext("2d")!;
  g.scale(s, s);
  const block = (x: number, y: number, bw: number, bh: number, r: number[]) => {
    g.fillStyle = "#151515"; g.beginPath(); g.roundRect(x, y, bw, bh, r); g.fill();
  };
  // Header: [lock] [Alice] [signed]
  block(LOCK_BLOCK + 2, 0, w - LOCK_BLOCK - 2 - 212, LOCK_BLOCK, [6]);
  block(w - 210, 0, 210, LOCK_BLOCK, [6, 20, 6, 6]);
  // Alice's real KeyAvatar.
  const face = extras.aliceFace;
  if (face) {
    const fx = LOCK_BLOCK + 26, fy = 30, fs = 60, cell = fs / 16;
    g.save(); g.beginPath(); g.roundRect(fx, fy, fs, fs, 11); g.clip();
    for (let k = 0; k < 256; k++) { g.fillStyle = face.p[parseInt(face.c[k], 36)]; g.fillRect(fx + (k % 16) * cell, fy + Math.floor(k / 16) * cell, cell + 0.5, cell + 0.5); }
    g.restore();
  }
  g.fillStyle = "#ededed"; g.font = "600 27px Inter"; g.fillText("Alice Example", LOCK_BLOCK + 104, 58);
  g.fillStyle = "#8a8a8a"; g.font = "400 20px Inter"; g.fillText("the only one who can read it", LOCK_BLOCK + 104, 88);
  g.strokeStyle = "#6dbd8a"; g.lineWidth = 2.6; g.lineCap = "round"; g.lineJoin = "round";
  g.beginPath(); g.moveTo(w - 182, 61); g.lineTo(w - 174, 69); g.lineTo(w - 160, 53); g.stroke();
  g.fillStyle = "#6dbd8a"; g.font = "500 22px Inter"; g.fillText("Signed by you", w - 150, 68);
  // Body: the armored message.
  block(0, LOCK_BLOCK + 2, w, h - LOCK_BLOCK - 2, [6, 6, 20, 20]);
  const lines = extras.armor.split("\n");
  g.font = "400 18.5px ui-monospace, 'SF Mono', Menlo, monospace";
  lines.forEach((l, i) => {
    g.fillStyle = l.startsWith("-----") ? "#ededed" : "#6dbd8a";
    g.fillText(l, 30, LOCK_BLOCK + 2 + 44 + i * 30.4);
  });
  return canvasTex(c);
}

function useCapture(url: string) {
  const tex = useTexture(url);
  const gl = useThree((s) => s.gl);
  useMemo(() => {
    tex.colorSpace = THREE.SRGBColorSpace;
    tex.anisotropy = gl.capabilities.getMaxAnisotropy();
    tex.minFilter = THREE.LinearMipmapLinearFilter;
    tex.needsUpdate = true;
  }, [tex, gl]);
  return tex;
}

/** The dark, glossy body every screen sits in. Its edges carry the light. */
function bodyMaterial() {
  return new THREE.MeshPhysicalMaterial({
    color: "#0b0c0d", metalness: 0.65, roughness: 0.32, clearcoat: 1, clearcoatRoughness: 0.12, envMapIntensity: 1.1,
  });
}

/** How far the panel falls back while the armored message has the stage. */
const panelBack = (t: number) => Math.min(io(P(t, ARMOR_OUT[0] + 0.1, ARMOR_OUT[1])), 1 - io(P(t, ARMOR_IN[0], ARMOR_IN[1] + 0.2)));
/** Everything falls away for the end lockup. */
const ending = (t: number) => io(P(t, END_AT, END_AT + 1.2));

/** The real Chrome window; the real side panel slides in, lifts off, and runs. */
function ChromeWindow() {
  const closed = useCapture("/sl/video/ui/chrome-window-closed.png");
  const open = useCapture("/sl/video/ui/chrome-window.png");
  const card = useRef<THREE.Group>(null!);
  const cardFace = useRef<THREE.Mesh>(null!);
  const cardBody = useRef<THREE.Mesh>(null!);
  const page = useRef<THREE.Mesh>(null!);
  const shadowMesh = useRef<THREE.Mesh>(null!);
  const cursor = useRef<THREE.Mesh>(null!);
  const ripple = useRef<THREE.Mesh>(null!);
  const root = useRef<THREE.Group>(null!);
  const squeeze = useRef<THREE.Mesh>(null!);
  const edgeShadow = useRef<THREE.Mesh>(null!);
  const edgeTex = useMemo(() => {
    const c = document.createElement("canvas");
    c.width = 64; c.height = 4;
    const g = c.getContext("2d")!;
    const gr = g.createLinearGradient(0, 0, 64, 0);
    gr.addColorStop(0, "rgba(0,0,0,0)"); gr.addColorStop(1, "rgba(0,0,0,1)");
    g.fillStyle = gr; g.fillRect(0, 0, 64, 4);
    return canvasTex(c);
  }, []);

  const m = useMemo(() => {
    const pageClosed = screenMaterial(closed, 22, [3200, 2000]);
    const pageOpen = screenMaterial(open, 22, [3200, 2000]);
    const cardMat = screenMaterial(open, 14, [OUTER.x1 - OUTER.x0, OUTER.y1 - OUTER.y0]);
    const pageMat = screenMaterial(takes.get("encrypt")!.tex, 0, [PAGE.x1 - PAGE.x0, PAGE.y1 - PAGE.y0]);
    const squeezeMat = screenMaterial(takes.get("squeeze")!.tex, 0, [3200, SQ_H]);
    return { pageClosed, pageOpen, cardMat, pageMat, squeezeMat, body: bodyMaterial(), cardBody: bodyMaterial() };
  }, [closed, open]);
  const shadow = useMemo(() => softShadow(OUTER.x1 - OUTER.x0, OUTER.y1 - OUTER.y0, 60), []);
  const cursorTex = useMemo(cursorTexture, []);
  const rippleTex = useMemo(ringTexture, []);

  useFrame(() => {
    const t = T.t;
    // The real panel slides in over the page from the window's right edge
    // (we see more of its left side each frame). The page keeps its layout
    // until the panel lands, then settles into its narrower, reflowed one
    // underneath it with a short blend: no empty gap for the panel to fill.
    // While it slides, the page is the REAL reflow (takes/squeeze: GitHub
    // laid out at each width), drawn exactly as wide as the panel leaves it.
    const opened = t >= SLIDE[0];
    const p = Math.max(slideProgress(t), 0.0001);
    const sliding = opened && t < SLIDE[1];
    const reflow = t >= SLIDE[1] ? 1 : 0;
    const pageW = SQ_OPEN + (3200 - SQ_OPEN) * (1 - p); // capture px
    const sq = squeeze.current;
    sq.visible = sliding;
    sq.scale.set(pageW * PX, SQ_H * PX, 1);
    sq.position.set((-1600 + pageW / 2) * PX, -((SQ_Y0 + 2000) / 2 - 1000) * PX, FACE + 0.0008);
    m.squeezeMat.uniforms.size.value.set(pageW, SQ_H);
    m.cardMat.uniforms.uvRect.value.set(OUV.u0, OUV.v0, OUV.u0 + (OUV.u1 - OUV.u0) * p, OUV.v1);
    m.cardMat.uniforms.size.value.set((OUTER.x1 - OUTER.x0) * p, OUTER.y1 - OUTER.y0);
    cardFace.current.scale.set(OW * p, OH, 1);
    cardFace.current.position.x = OW / 2 - (OW * p) / 2;
    card.current.visible = opened;
    page.current.visible = p >= 0.9999;
    // A soft shadow on the panel's leading edge while it moves over the page.
    const edge = edgeShadow.current;
    edge.visible = opened && p < 0.9999;
    edge.position.set(OW / 2 - OW * p - 0.16, 0, 0.001);
    edge.scale.set(0.32, OH, 1);
    (edge.material as THREE.MeshBasicMaterial).opacity = 0.7 * Math.min(1, (1 - p) * 6);

    // The panel lifts off the window towards us, casting a soft shadow.
    // Eased in and out: a lift that starts at full speed reads as a jolt.
    const lift = io(P(t, LIFT[0], LIFT[1]));
    card.current.position.lerpVectors(new THREE.Vector3(OCX, OCY, FACE), LIFTED, lift);
    card.current.scale.setScalar(1 + lift * (LIFT_SCALE - 1));
    cardBody.current.visible = lift > 0.001;
    const sh = shadowMesh.current;
    sh.visible = lift > 0.001;
    sh.position.set(OCX + 0.25 + lift * 0.3, OCY - 0.35 - lift * 0.35, FACE + 0.001);
    sh.scale.set(OW * shadow.sx * (1 + lift * 0.08), OH * shadow.sy * (1 + lift * 0.05), 1);
    (sh.material as THREE.MeshBasicMaterial).opacity = 0.75 * lift;

    // The page falls back as the panel comes forward; the panel itself
    // falls back while the armored message has the stage; all of it goes
    // for the lockup.
    const end = ending(t);
    const back = io(P(t, LIFT[0] + 0.1, LIFT[1] + 0.2));
    for (const mat of [m.pageClosed, m.pageOpen]) {
      mat.uniforms.dim.value = 0.6 * back + 0.4 * end;
      mat.uniforms.defocus.value = back;
    }
    const pb = panelBack(t);
    for (const mat of [m.cardMat, m.pageMat]) {
      mat.uniforms.dim.value = 0.55 * pb + 0.45 * end;
      mat.uniforms.defocus.value = 0.7 * pb + 0.6 * end;
    }
    // Gone entirely for the lockup: screens fade, bodies hide.
    m.pageClosed.uniforms.opacity.value = 1 - end;
    m.pageOpen.uniforms.opacity.value = reflow * (1 - end);
    m.cardMat.uniforms.opacity.value = m.pageMat.uniforms.opacity.value = 1 - end;
    // Bodies fade too; flipping `transparent` needs a shader rebuild.
    for (const b of [m.body, m.cardBody]) {
      if (b.transparent !== end > 0) { b.transparent = end > 0; b.needsUpdate = true; }
      b.opacity = 1 - end;
    }
    root.current.visible = end < 0.999;
    (shadowMesh.current.material as THREE.MeshBasicMaterial).opacity *= 1 - end;

    // Whatever take is on, and the pointer exactly where its pointer was.
    const { name, tt } = activeTake(t);
    const take = takes.get(name)!;
    m.pageMat.uniforms.map.value = take.tex;
    const live = tt > -0.2 && tt < take.index.duration - 0.6;
    const fade = Math.min(clamp((tt + 0.2) / 0.3), clamp((take.index.duration - 0.6 - tt) / 0.3)) * (1 - pb);
    cursor.current.visible = live && fade > 0.01;
    (cursor.current.material as THREE.MeshBasicMaterial).opacity = fade;
    if (live) {
      const ptr = pointerAt(take, Math.max(tt, 0));
      const at = onPage(ptr.x, ptr.y, 0.004);
      const s = 0.28 * (ptr.down ? 0.86 : 1);
      // The arrow's tip is near (3/22, 2/22) of the texture.
      cursor.current.position.set(at.x + s * (0.5 - 3 / 22), at.y - s * (0.5 - 2 / 22), at.z);
      cursor.current.scale.setScalar(s);
    }
    let rk = -1, rp = { x: 0, y: 0 };
    for (const c of take.clicks) {
      const k = (tt - c.t) / 0.55;
      if (k >= 0 && k < 1) { rk = k; rp = c; }
    }
    ripple.current.visible = rk >= 0;
    if (rk >= 0) {
      ripple.current.position.copy(onPage(rp.x, rp.y, 0.003));
      ripple.current.scale.setScalar(0.08 + expo(rk) * 0.22);
      (ripple.current.material as THREE.MeshBasicMaterial).opacity = 0.32 * (1 - rk) ** 2;
    }
  });

  return (
    <group ref={root}>
      <RoundedBox args={[WIN_W, WIN_H, WIN_D]} radius={0.12} smoothness={8} material={m.body} />
      <mesh position={[0, 0, FACE]} scale={[WIN_W, WIN_H, 1]} material={m.pageClosed} renderOrder={1}>
        <planeGeometry />
      </mesh>
      <mesh position={[0, 0, FACE + 0.0005]} scale={[WIN_W, WIN_H, 1]} material={m.pageOpen} renderOrder={2}>
        <planeGeometry />
      </mesh>
      <mesh ref={squeeze} material={m.squeezeMat} renderOrder={2}>
        <planeGeometry />
      </mesh>
      <mesh ref={shadowMesh} renderOrder={3}>
        <planeGeometry />
        <meshBasicMaterial map={shadow.tex} transparent depthWrite={false} toneMapped={false} />
      </mesh>
      <group ref={card}>
        <RoundedBox ref={cardBody} position={[0, 0, -0.062]} args={[OW, OH, 0.12]} radius={0.06} smoothness={6} material={m.cardBody} />
        <mesh ref={edgeShadow} renderOrder={3}>
          <planeGeometry />
          <meshBasicMaterial map={edgeTex} transparent depthWrite={false} toneMapped={false} />
        </mesh>
        <mesh ref={cardFace} position={[0, 0, 0.0015]} material={m.cardMat} renderOrder={4}>
          <planeGeometry />
        </mesh>
        <mesh ref={page} position={[PCX, PCY, 0.0025]} scale={[PW, PH, 1]} material={m.pageMat} renderOrder={5}>
          <planeGeometry />
        </mesh>
        <mesh ref={ripple} renderOrder={6}>
          <planeGeometry />
          <meshBasicMaterial map={rippleTex} transparent depthWrite={false} toneMapped={false} />
        </mesh>
        <mesh ref={cursor} renderOrder={7}>
          <planeGeometry />
          <meshBasicMaterial map={cursorTex} transparent depthWrite={false} toneMapped={false} />
        </mesh>
      </group>
    </group>
  );
}

/**
 * The real armored message, lifted out of the panel's Copy button as a card
 * of its own; its lock snaps shut; later it flies back into the panel just as
 * the decrypt take pastes it.
 */
function ArmorCard() {
  const group = useRef<THREE.Group>(null!);
  const face = useRef<THREE.Mesh>(null!);
  const lockPlane = useRef<THREE.Mesh>(null!);
  const tex = useMemo(cardTexture, []);
  const lock = useMemo(() => {
    const c = document.createElement("canvas");
    c.width = c.height = LOCK_BLOCK * 2;
    return { c, g: c.getContext("2d")!, tex: canvasTex(c) };
  }, []);
  const faceMat = useMemo(() => screenMaterial(tex, 0, [CARD_PX[0] * 2, CARD_PX[1] * 2]), [tex]);
  const lockMat = useMemo(() => screenMaterial(lock.tex, 0, [LOCK_BLOCK * 2, LOCK_BLOCK * 2]), [lock]);
  const body = useMemo(bodyMaterial, []);
  const [cw, ch] = [CARD_PX[0] * CARD_U, CARD_PX[1] * CARD_U];

  useFrame(() => {
    const t = T.t;
    const out = expo(P(t, ARMOR_OUT[0], ARMOR_OUT[1]));
    const back = io(P(t, ARMOR_IN[0], ARMOR_IN[1]));
    group.current.visible = t >= ARMOR_OUT[0] && t < ARMOR_IN[1];
    if (!group.current.visible) return;
    // Out of the Copy button, then back into the message box.
    const from = liftedPoint(258, 792), into = liftedPoint(180, 378);
    const pos = new THREE.Vector3().lerpVectors(from, CARD_AT, out).lerp(into, back);
    group.current.position.copy(pos);
    group.current.scale.setScalar(lerp(0.08, 1, out) * lerp(1, 0.05, back));
    group.current.rotation.set(lerp(0.12, 0, out) - back * 0.1, lerp(-0.35, 0.06, out) + back * 0.3, 0);
    faceMat.uniforms.opacity.value = 1 - P(t, ARMOR_IN[1] - 0.25, ARMOR_IN[1]);
    lockMat.uniforms.opacity.value = faceMat.uniforms.opacity.value;
    // The lock: arrives open, snaps shut, and the block turns green.
    const pose = lockPose(t, [[ARMOR_LOCK, "close"]], true);
    const shut = P(t, ARMOR_LOCK + 0.35, ARMOR_LOCK + 0.55);
    const bg = shut > 0.5 ? "#1f2a23" : "#151515", ink = shut > 0.5 ? "#6dbd8a" : "#8a8a8a";
    const g = lock.g, S = LOCK_BLOCK * 2;
    g.clearRect(0, 0, S, S);
    g.fillStyle = bg; g.beginPath(); g.roundRect(0, 0, S, S, [40, 12, 12, 12]); g.fill();
    g.save(); g.translate(S * 0.22, S * 0.2); drawLock(g, S * 0.56, pose, ink, bg); g.restore();
    lock.tex.needsUpdate = true;
    lockPlane.current.scale.setScalar(LOCK_BLOCK * CARD_U * (1 + pose.click * 0.06));
  });

  return (
    <group ref={group}>
      <RoundedBox position={[0, 0, -0.05]} args={[cw, ch, 0.08]} radius={0.04} smoothness={5} material={body} />
      <mesh ref={face} position={[0, 0, 0.0015]} scale={[cw, ch, 1]} material={faceMat} renderOrder={8}>
        <planeGeometry />
      </mesh>
      <mesh
        ref={lockPlane}
        position={[-cw / 2 + (LOCK_BLOCK / 2) * CARD_U, ch / 2 - (LOCK_BLOCK / 2) * CARD_U, 0.003]}
        material={lockMat}
        renderOrder={9}
      >
        <planeGeometry />
      </mesh>
    </group>
  );
}

/** Studio lights, seen only in reflections: they draw the bodies' edges. */
function Studio() {
  return (
    <Environment frames={1} resolution={256}>
      <Lightformer form="rect" intensity={2.2} position={[0, 6, 4]} rotation-x={Math.PI / 2} scale={[14, 3, 1]} />
      <Lightformer form="rect" intensity={1.4} position={[-8, 0, 3]} rotation-y={Math.PI / 2} scale={[10, 1.2, 1]} />
      <Lightformer form="rect" intensity={1.0} position={[8, 1, 3]} rotation-y={-Math.PI / 2} scale={[10, 0.8, 1]} />
    </Environment>
  );
}

/**
 * The camera, in the window's frame. Each beat is overview → in on the part
 * that matters → back out for the decisive click. Every cue is aimed at a
 * real point on the take's page and timed off the take's real clicks. Two
 * cues a hair apart make a cut.
 */
const WIN_ROT = new THREE.Euler(0.03, -0.12, 0);
const windowFrame = new THREE.Object3D();
windowFrame.rotation.copy(WIN_ROT);
windowFrame.updateMatrixWorld();
const tmp = new THREE.Vector3(), look = new THREE.Vector3();
const CUT = 0.0005;

function Rig() {
  const camera = useThree((s) => s.camera);
  const cues = useMemo(() => {
    // Frame a point of the take's page from `d` away, the panel set right
    // of centre (look a little left of it) so copy has room on the left.
    const at = (x: number, y: number, d: number, side = 1.4, up = 0.3): number[] => {
      const p = liftedPoint(x, y);
      return [p.x - side, p.y + up, p.z + d, p.x - side, p.y, p.z];
    };
    const overview = (d = 20.5, side = 2.8) => at(180, 432, d, side, 0.3);
    const writing = at(190, 250, 11.5, 1.35);
    // The armor beat frames the card and the panel together.
    const mid = new THREE.Vector3().addVectors(CARD_AT, LIFTED).multiplyScalar(0.5);
    const armor = [mid.x - 0.2, mid.y + 0.1, mid.z + 13.2, mid.x - 0.2, mid.y - 0.35, mid.z];
    const dec = (n: number) => click("decrypt", n);
    const tam = (n: number) => click("tampered", n);
    const key = (n: number) => click("keys", n);
    return [
      [0, [-5, 2.6, 34, 0.2, 0.2, 0]],
      [1.5, [-1.2, 0.8, 27.5, 0.6, 0, 0]],
      [2.7, overview(21)],
      // Encrypt: the overview as the pointer arrives, in on recipient +
      // message as the picker opens, out for the click.
      [encClick(0) - 0.25, overview(20.5)],
      [encClick(0) + 0.4, writing],
      [encClick(3) + 0.35, at(200, 240, 11, 1.3)],
      [encClick(4) - 0.45, overview(20.5)],
      [ARMOR_OUT[0] + 0.15, overview(20)],
      [ARMOR_OUT[1] + 0.3, armor],
      [ARMOR_IN[0], armor],
      // Decrypt: overview for the paste and the click, in on the result.
      [ARMOR_IN[1] + 0.25, overview(20.5)],
      [dec(1) + 0.25, overview(20)],
      [dec(1) + 1.0, at(180, 175, 10.5, 1.3)],
      [TAMPERED_AT, at(180, 170, 10, 1.3)],
      // Tampered: cut to the overview, in on the failure.
      [TAMPERED_AT + CUT, overview(19.5, 2.6)],
      [tam(1) + 0.25, overview(19)],
      [tam(1) + 0.95, at(180, 150, 10, 1.3)],
      [KEYS_AT, at(180, 145, 9.6, 1.3)],
      // Keys: cut to the overview, drift down the list, in on Alice's key.
      [KEYS_AT + CUT, overview(21, 3)],
      [KEYS_AT + 1.4, overview(20.5, 3)],
      [key(1) - 0.4, at(180, 330, 14, 1.6)],
      [key(1) + 0.9, at(200, 210, 11, 1.35)],
      [END_AT, at(200, 215, 10.6, 1.35)],
      [END_AT + 1.6, overview(30, 1)],
    ] as [number, number[]][];
  }, []);
  useFrame(() => {
    const [x, y, z, lx, ly, lz] = smoothKeys(cues, T.t);
    camera.position.copy(windowFrame.localToWorld(tmp.set(x, y, z)));
    camera.lookAt(windowFrame.localToWorld(look.set(lx, ly, lz)));
  });
  return null;
}

function Ready({ onReady }: { onReady: () => void }) {
  useEffect(onReady, [onReady]);
  return null;
}

export function Film({ onReady }: { onReady: () => void }) {
  return (
    <Canvas
      frameloop="never"
      gl={{ preserveDrawingBuffer: true, antialias: true }}
      camera={{ fov: 28, near: 0.3, far: 200, position: [0, 0, 30] }}
      style={{ position: "absolute", inset: 0, background: "#08090a" }}
    >
      <color attach="background" args={["#08090a"]} />
      <Studio />
      <group rotation={WIN_ROT}>
        <ChromeWindow />
        <ArmorCard />
      </group>
      <Rig />
      <Ready onReady={onReady} />
      <EffectComposer multisampling={4}>
        <Bloom mipmapBlur intensity={0.2} luminanceThreshold={0.9} luminanceSmoothing={0.1} />
        <Noise premultiply opacity={0.06} />
        <Vignette offset={0.32} darkness={0.45} />
      </EffectComposer>
    </Canvas>
  );
}
