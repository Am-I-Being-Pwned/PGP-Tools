# Promo video

A ~64s, 1920x1080 / 60fps product video in the same design language as the
store tiles (`../promo`): one flat `#0a0a0a` page, flat `#151515` blocks split
by 2px gaps, green only for go/on/good, red only for a stop, shadow only on
what floats (the panel and the OS passkey sheet). No soundtrack, so add one
in an editor.

## Build

```sh
cd apps/pgp && pnpm build                                          # .output/chrome-mv3
npx playwright test --config=playwright.capture.config.ts video    # -> ../../assets/store-listing/video/ui/
cd ../../assets/store-listing/video
node render.mjs --blur 3               # final: out/pgp-tools-promo-1920x1080.mp4, motion blur (~20 min)
node render.mjs                        # same, no blur (~6 min)
node render.mjs --fps 30 --from 8 --to 20   # draft one stretch
node render.mjs --still 3,14.3,29.2    # review frames as PNG
node render.mjs --scale 2              # 4K
open promo.html                        # live preview with a scrub bar (space = play)
```

Run `render.mjs` once before opening `promo.html` directly: it writes
`ui/data.js` (the captured ciphertext) that the page loads.

## How it works

- **The panel is real.** Every panel frame is a screenshot of the shipped
  build, taken by `apps/pgp/e2e-capture/video.spec.ts` at 4x so the camera
  can push in on a control and stay sharp. It reuses the e2e fixtures, so it
  breaks loudly when a selector moves. The typing is one capture per word,
  and the ciphertext card shows the real armor from that run.
- **Faces are real.** `avatars.ts` writes `avatars.js` from the extension's
  own `lib/key-avatar`. Face 0 is Alice (the `standard` fixture), and the rest
  come from throwaway fingerprints that belong to no key.
  `npx tsx assets/store-listing/video/avatars.ts` from the repo root.
- **Time is a parameter.** `promo.html` has no CSS animations or
  transitions. `seek(t)` sets every style from `t`, so `render.mjs` can step
  it at exactly 1/fps and pipe the PNG frames to ffmpeg, and the output does
  not depend on machine speed.

- **Motion is springs.** `spr()` is an analytic damped spring, so it is
  exact at any `t`. Entrances, the cursor and the camera all use it
  (`SP` holds the presets); camera keys are cues that release a spring
  toward the next pose, so moves chain and overlap.
- **The lock** (`lock()`) is a solid body the shackle's legs run down into.
  Open turns the key, springs the shackle up and swings it out on its right
  leg; close swings it back and drops it in hard enough to squash the body.
- **Motion blur**: `--blur N` renders N sub-frames over a 180-degree shutter
  and averages them with ffmpeg's `tmix`. Renders write to `.part` and rename
  on success, so an interrupted render never clobbers the last good video.

## Editing the timeline

All timings live at the top of the `<script>` in `promo.html`:

- `SHOTS`: which capture is on screen from when.
- `CAM`: camera keyframes per segment: the focus point in panel px (400x640
  below the 34px header), zoom, where that point sits on stage, and tilt.
  Each segment also sets the window the panel is seen through, so a push-in
  never slides under the caption column.
- `RINGS`, `CURSOR`, `CLICKS`: the highlight ring, the pointer and its clicks.
- `CAPS`, `WIPES`, and the per-scene windows in `seek()`.

## Claims

Same rule as the tiles: everything traces to the repo. The features in the
grid are the README's feature list. The security lines are from the README
security table and `SECURITY.md`. "No analytics, no accounts, no content
scripts" is the claim slide `e` already makes. Contacts are `example.com`
fixtures; the user's own identity is `james@amibeingpwned.com`, as on the
tiles.
