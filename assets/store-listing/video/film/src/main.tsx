import { advance } from "@react-three/fiber";
import { Suspense } from "react";
import { createRoot } from "react-dom/client";

import { DURATION, Film } from "./Film";
import { Overlay, overlay } from "./Overlay";
import { SCHEDULE, slideProgress } from "./script";
import { loadExtras, loadTake, showTake, takes } from "./takes";
import { T } from "./time";

declare global {
  interface Window {
    seek: (t: number) => Promise<void>;
    ready: Promise<void>;
    DURATION: number;
  }
}

let resolveReady!: () => void;
window.ready = new Promise((r) => (resolveReady = r));
window.DURATION = DURATION;

/**
 * The only way time moves: set it, put every take on the right frame, update
 * the type layer, draw one frame. Async because a take frame is fetched.
 */
window.seek = async (t: number) => {
  T.t = t;
  await Promise.all([
    // The page squeezing as the panel opens: its frame follows the slide.
    showTake("squeeze", slideProgress(t)),
    ...SCHEDULE.map(([name, start]) => {
      const take = takes.get(name);
      return take ? showTake(name, Math.min(Math.max(t - start, 0), take.index.duration)) : undefined;
    }),
  ]);
  overlay(t);
  advance(t * 1000);
};

const render = new URLSearchParams(location.search).has("render");

function onReady() {
  void document.fonts.ready.then(async () => {
    await window.seek(0);
    resolveReady();
  });
}

function Stage() {
  return (
    <div id="stage">
      <Suspense fallback={null}>
        <Film onReady={onReady} />
      </Suspense>
      <Overlay />
    </div>
  );
}

// Takes, the armor and the fonts first: the scene builds its materials and
// draws its canvases from them.
await Promise.all([...SCHEDULE.map(([name]) => loadTake(name)), loadTake("squeeze"), loadExtras(), document.fonts.load("600 27px Inter"), document.fonts.load("600 80px 'Space Grotesk'")]);
createRoot(document.getElementById("root")!).render(<Stage />);

// Live preview with a scrub bar; never present in a rendered frame.
if (!render) {
  void window.ready.then(() => {
    const bar = document.createElement("div");
    bar.id = "player";
    bar.innerHTML = '<button id="pp">pause</button><input id="scrub" type="range" min="0" step="0.01" /><span id="tc"></span>';
    document.body.appendChild(bar);
    const scrub = bar.querySelector<HTMLInputElement>("#scrub")!;
    scrub.max = String(DURATION);
    let t = Number(new URLSearchParams(location.search).get("t") ?? 0), playing = true, last: number | null = null, busy = false;
    const draw = async () => { busy = true; await window.seek(t); busy = false; scrub.value = String(t); bar.querySelector("#tc")!.textContent = t.toFixed(2); };
    const loop = (now: number) => {
      if (playing && !busy) { if (last != null) t = (t + (now - last) / 1000) % DURATION; last = now; void draw(); } else if (!playing) last = null;
      requestAnimationFrame(loop);
    };
    scrub.oninput = () => { t = Number(scrub.value); void draw(); };
    const toggle = () => { playing = !playing; bar.querySelector("#pp")!.textContent = playing ? "pause" : "play"; };
    bar.querySelector<HTMLButtonElement>("#pp")!.onclick = toggle;
    addEventListener("keydown", (e) => { if (e.code === "Space") { e.preventDefault(); toggle(); } });
    requestAnimationFrame(loop);
  });
} else document.body.classList.add("render");
