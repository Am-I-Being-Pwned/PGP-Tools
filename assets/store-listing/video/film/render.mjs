#!/usr/bin/env node
/**
 * Render the film to video, frame by frame.
 *
 * The film is a pure function of time (window.seek(t)), so this builds it,
 * serves it, steps it at exactly 1/fps, screenshots each frame and pipes the
 * PNGs into ffmpeg. Output does not depend on machine speed.
 *
 *     node render.mjs                        # out/pgp-tools-film-1280x720.mp4 (720p, the default)
 *     node render.mjs --from 0 --to 8        # one stretch
 *     node render.mjs --still 1,3.5,6        # review frames as PNG
 *     node render.mjs --scale 1              # 1080p; only when asked for
 *
 * Writes to <name>.part and renames on success, so an interrupted render
 * never clobbers the last good video.
 */
import { spawn } from "node:child_process";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import { build, preview } from "vite";

const HERE = import.meta.dirname;
// Playwright comes from the extension's own dev dependencies.
const require = createRequire(path.resolve(HERE, "../../../../apps/pgp/package.json"));
const { chromium } = require("@playwright/test");

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i < 0 ? dflt : args[i + 1];
};
const fps = +opt("fps", 60);
const scale = +opt("scale", 2 / 3); // 1920x1080 stage → 1280x720
const stills = opt("still", null);
const OUT = path.resolve(HERE, "../out");
mkdirSync(OUT, { recursive: true });

await build({ root: HERE, logLevel: "warn" });
const server = await preview({ root: HERE, preview: { port: 0, strictPort: false }, logLevel: "warn" });
const url = server.resolvedUrls.local[0];

const browser = await chromium.launch({
  channel: "chromium", // full Chromium in new-headless mode, which keeps the GPU
  args: ["--use-angle=metal", "--enable-gpu", "--ignore-gpu-blocklist", "--force-color-profile=srgb"],
});
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: scale });
// A page error means a broken frame: stop rather than render garbage (or hang).
let pageError = null;
page.on("pageerror", (e) => { console.error("page error:", e.message); pageError ??= e; });
page.on("console", (m) => m.type() === "error" && console.error("console:", m.text()));
// --query adds URL flags, e.g. --query clip for the cut-in version.
const query = opt("query", "");
await page.goto(`${url}?render${query ? `&${query}` : ""}`);
await Promise.race([page.evaluate(() => window.ready), new Promise((_, rej) => setTimeout(() => rej(new Error("film never became ready")), 60_000))]);
const gpu = await page.evaluate(() => {
  const gl = document.createElement("canvas").getContext("webgl2");
  const ext = gl?.getExtension("WEBGL_debug_renderer_info");
  return ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : "unknown";
});
console.log("renderer:", gpu);
const duration = await page.evaluate(() => window.DURATION);
const stage = page.locator("#stage");

async function frame(t) {
  if (pageError) { await done(); throw pageError; }
  await page.evaluate((t) => window.seek(t), t);
  return stage.screenshot({ type: "png", animations: "disabled", caret: "hide" });
}

async function done() {
  await browser.close();
  await new Promise((r) => server.httpServer.close(r));
}

if (stills) {
  for (const t of stills.split(",").map(Number)) {
    const file = path.join(OUT, `film-${t.toFixed(2)}.png`);
    writeFileSync(file, await frame(t));
    console.log("wrote", path.relative(HERE, file));
  }
  await done();
  process.exit(0);
}

const from = +opt("from", 0);
const to = Math.min(+opt("to", duration), duration);
const W = Math.round(1920 * scale), H = Math.round(1080 * scale);
const name = opt("out", `pgp-tools-film-${W}x${H}${from > 0 || to < duration ? `-${from}-${to}` : ""}.mp4`);
const file = path.join(OUT, name);

const ff = spawn("ffmpeg", [
  "-y", "-loglevel", "error",
  "-f", "image2pipe", "-framerate", String(fps), "-i", "-",
  "-c:v", "libx264", "-preset", "slow", "-crf", "16",
  "-pix_fmt", "yuv420p", "-color_primaries", "bt709", "-color_trc", "bt709", "-colorspace", "bt709",
  "-movflags", "+faststart", "-f", "mp4", file + ".part",
], { stdio: ["pipe", "inherit", "inherit"] });
const closed = new Promise((res, rej) => ff.on("close", (c) => (c ? rej(new Error(`ffmpeg exited ${c}`)) : res())));

const total = Math.round((to - from) * fps);
const started = Date.now();
for (let i = 0; i < total; i++) {
  const png = await frame(from + i / fps);
  if (!ff.stdin.write(png)) await new Promise((r) => ff.stdin.once("drain", r));
  if (i % fps === 0) {
    const el = (Date.now() - started) / 1000;
    process.stdout.write(`\r${i}/${total} frames  ${(i / Math.max(el, 0.001)).toFixed(1)} fps  eta ${Math.round(((total - i) * el) / Math.max(i, 1))}s   `);
  }
}
ff.stdin.end();
await closed;
renameSync(file + ".part", file);
await done();
console.log(`\nwrote ${path.relative(HERE, file)}`);
