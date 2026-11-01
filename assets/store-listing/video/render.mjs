#!/usr/bin/env node
/**
 * Render promo.html to video, frame by frame.
 *
 * The page is a pure function of time (window.seek(t)), so this steps it at
 * exactly 1/fps, screenshots each frame and pipes the PNGs into ffmpeg. The
 * output does not depend on how fast the machine is.
 *
 *     node render.mjs                      # out/pgp-tools-promo-1920x1080.mp4, 60fps
 *     node render.mjs --fps 30 --from 8 --to 20   # a quick draft of one stretch
 *     node render.mjs --still 3,10.5,24    # out/still-<t>.png, for review
 *     node render.mjs --scale 2            # 3840x2160
 *     node render.mjs --blur 4             # motion blur: 4 sub-frames per frame
 *
 * Needs ffmpeg on PATH and the captures in ui/ (apps/pgp/e2e-capture/video.spec.ts).
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const HERE = import.meta.dirname;
// Playwright comes from the extension's own dev dependencies.
const require = createRequire(path.resolve(HERE, "../../../apps/pgp/package.json"));
const { chromium } = require("@playwright/test");

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i < 0 ? dflt : args[i + 1];
};
const fps = +opt("fps", 60);
const scale = +opt("scale", 1);
const stills = opt("still", null);
// Motion blur: N sub-frames spread over a 180-degree shutter (half the
// frame interval), averaged by ffmpeg's tmix. 1 = off.
const blur = Math.max(1, Math.round(+opt("blur", 1)));

const OUT = path.join(HERE, "out");
mkdirSync(OUT, { recursive: true });

// The captured ciphertext, as a script the page can load from file://.
const armorPath = path.join(HERE, "ui", "armored.asc");
if (!existsSync(armorPath)) throw new Error("ui/ is empty: run apps/pgp/e2e-capture/video.spec.ts first");
writeFileSync(path.join(HERE, "ui", "data.js"), `window.ARMOR = ${JSON.stringify(readFileSync(armorPath, "utf8"))};\n`);

const browser = await chromium.launch({ args: ["--allow-file-access-from-files", "--force-color-profile=srgb"] });
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: scale });
page.on("pageerror", (e) => console.error("page error:", e.message));
// --query adds URL flags, e.g. --query cut for the assembled promo.
const query = opt("query", "");
await page.goto(pathToFileURL(path.join(HERE, "promo.html")).href + "?render" + (query ? `&${query}` : ""));
await page.evaluate(() => window.ready);
const duration = await page.evaluate(() => window.DURATION);
const stage = page.locator("#stage");

async function frame(t) {
  await page.evaluate((t) => window.seek(t), t);
  return stage.screenshot({ type: "png", animations: "disabled", caret: "hide" });
}

if (stills) {
  for (const t of stills.split(",").map(Number)) {
    const file = path.join(OUT, `still-${t.toFixed(2)}.png`);
    writeFileSync(file, await frame(t));
    console.log("wrote", path.relative(HERE, file));
  }
  await browser.close();
  process.exit(0);
}

const from = +opt("from", 0);
const to = Math.min(+opt("to", duration), duration);
const W = 1920 * scale, H = 1080 * scale;
const name = opt("out", `pgp-tools-promo-${W}x${H}${from > 0 || to < duration ? `-${from}-${to}` : ""}.mp4`);
const file = path.join(OUT, name);

const ff = spawn("ffmpeg", [
  "-y", "-loglevel", "error",
  "-f", "image2pipe", "-framerate", String(fps * blur), "-i", "-",
  ...(blur > 1 ? ["-vf", `tmix=frames=${blur},select='eq(mod(n\\,${blur})\\,${blur - 1})'`, "-r", String(fps)] : []),
  "-c:v", "libx264", "-preset", "slow", "-crf", "14", "-tune", "animation",
  "-pix_fmt", "yuv420p", "-color_primaries", "bt709", "-color_trc", "bt709", "-colorspace", "bt709",
  // Written beside the target and renamed at the end, so an interrupted
  // render never clobbers the last good video.
  "-movflags", "+faststart", "-f", "mp4", file + ".part",
], { stdio: ["pipe", "inherit", "inherit"] });
const done = new Promise((res, rej) => ff.on("close", (c) => (c ? rej(new Error(`ffmpeg exited ${c}`)) : res())));

const total = Math.round((to - from) * fps);
const started = Date.now();
for (let i = 0; i < total; i++) {
  for (let k = 0; k < blur; k++) {
    const png = await frame(from + i / fps + (blur > 1 ? ((k / (blur - 1)) - 1) * (0.5 / fps) : 0));
    if (!ff.stdin.write(png)) await new Promise((r) => ff.stdin.once("drain", r));
  }
  if (i % fps === 0) {
    const el = (Date.now() - started) / 1000;
    process.stdout.write(`\r${i}/${total} frames  ${(i / Math.max(el, 0.001)).toFixed(1)} fps  eta ${Math.round(((total - i) * el) / Math.max(i, 1))}s   `);
  }
}
ff.stdin.end();
await done;
renameSync(file + ".part", file);
await browser.close();
console.log(`\nwrote ${path.relative(HERE, file)}`);
