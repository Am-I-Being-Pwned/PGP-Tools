# Store listing artwork

Artwork for the Chrome Web Store and Edge Add-ons listings.

The tiles are plain HTML rendered headless at exact pixel sizes, using the same
dark tokens the side panel renders with (`packages/tailwind-config`, mirrored
into `parts.css`) and the extension's own shipped icon. Nothing lives in a
design tool, so the artwork is reviewable in a diff and a token change is a
one-line change here.

This mirrors the AIBP store-listing pipeline (`assets/aibp/store-listing-v2` in
the main repo) so the two listings read as one brand.

## Build

```sh
python3 build.py --render     # everything, into exports/
python3 build.py a --render   # one tile
open build/lab.html           # every tile side by side, with download buttons
```

Slide `a` embeds a real screenshot of the side panel, not a mock. It lives in
`../ui/` and is produced by Playwright driving the built extension.

It is captured NARROW (400px, about a real side panel) and rendered WIDE (486px
in the tile), so the UI comes out ~1.2x larger than life. That is deliberate: at
store-thumbnail size a life-sized UI is unreadable grey texture, and the panel
has to read as a panel. A 3x device scale factor pays for the upscale. The three
numbers are coupled - capture 400x560, so the render is 1.4x as tall as it is
wide, and 486 is simply the widest that fits 800px of canvas once Chrome's
header strip is added. Change the capture viewport and the frame width in
`parts.css` has to move with it. 560 is also the height floor: shorter and the
composer collides with the Recipients label.

```sh
cd ../../../apps/pgp
pnpm build                                                  # .output/chrome-mv3
npx playwright test --config=playwright.capture.config.ts   # -> ../../assets/store-listing/ui/
```

Re-run that whenever the workspace UI changes, then re-render the tiles. The
capture reuses the e2e fixtures and helpers on purpose, so it breaks loudly
when a selector moves rather than quietly shipping a stale picture. It sits
outside `e2e/` (the e2e config's `testDir`) so CI never runs it and the e2e
count stays a count of tests.

`build/` is generated and git-ignored. `exports/` holds the PNGs that get
uploaded, and is committed.

Rendering shells out to headless Chrome at `--force-device-scale-factor=1`, so
output is exactly the declared size. Verify with `sips -g pixelWidth -g pixelHeight`
before uploading: the stores reject anything off by a pixel.

## Sizes

| File                    | Size     | Slot                   |
| ----------------------- | -------- | ---------------------- |
| `a`, `b`, `c`, `d`, `e` | 1280x800 | CWS / Edge screenshot  |
| `m1`                    | 1400x560 | CWS marquee promo tile |

The 440x280 small promo tile is not cut yet. It is required, along with the
marquee, to be eligible for store featuring; `assets/pgptools-tile-static.png`
is the closest thing that exists today.

## The rules

**Everything is drawn for thumbnail size.** These are shown as ~320px-wide
cards in the store grid and most people never open one full size. Headlines run
60-68px, body copy 26px, icons 26px and up, and nothing sits below ~17px. The
top of `lab.html` renders all five at that size for exactly this reason: if a
line is unreadable there, the fix is fewer words, never smaller type. A slide
that needs a paragraph to land is the wrong slide.

**One exception to the size floor: real UI.** The panel screenshot on slide
`a` renders at the app's own type sizes, which are below the floor. That is
correct. A store screenshot of an app is supposed to look like the app, and
shrinking the UI's own text to match the tile would make it a picture of
something that does not exist. The headline still has to carry the slide at
thumbnail size, and it does.

**No em-dashes.** House style, and it survives the round trip: a colon, a
comma or a full stop always does the same job. Applies to the tiles and to
this file.

**No counts, no percentages.** Test totals, coverage and star ratings all move
on their own, and a stale number on a store listing is the one claim here that
can quietly become false. Everything the tiles assert is structural - it is
true of the architecture, so it stays true between releases.

## Slides

The order is the argument: convenience first, because that is why someone
installs this over the CLI, then the security that makes the convenience safe.
`b` sits second on purpose - "what is this thing doing with my data?" is the
objection that stops an install, so it gets answered early.

| Slide | Headline                          | Carries                                        |
| ----- | --------------------------------- | ---------------------------------------------- |
| `a`   | Encrypt without leaving the tab   | The product. Real panel screenshot, shortcuts. |
| `b`   | Encrypted at rest. All of it.     | Every store sealed - contacts and settings too. |
| `c`   | No passphrase. Just Touch ID.     | Passkey unlock, Argon2id fallback, auto-lock.  |
| `d`   | Bad signature, no plaintext       | Atomic decrypt+verify, both outcomes drawn.    |
| `e`   | Nothing here is a black box       | Open source, Rust/WASM, what it will not do.   |

Slide `a` is the one most people see, so it is the only one that shows the UI.

`m1` is the marquee and stands alone, so it carries the whole product rather
than one slide's argument. It reuses slide `a`'s capture, but `.uicrop` frames a
window onto the composer instead of shrinking the whole panel: at 560px tall
there is no room for a full panel at a size worth looking at. A separate
short-and-wide capture was tried first and does not work, because below roughly
500px of viewport height the composer collapses onto the Recipients label
whatever the width.

## Layout

- `parts/*.html` - one tile each, plus the shared `i-*` icon fragments. A tile
  carries its own scoped `<style>`; only genuinely shared rules go in
  `parts.css`.
- `parts.css` - dark tokens, the 1280x800 canvas, the type scale, and the
  shared components (card shell, icon rows, verdict rows, the sealed-store
  list, the side panel frame, the OS passkey sheet).
- `../ui/` - screenshots of the real extension, inlined by `__DATA:`. Generated,
  not hand-made; see the capture command above.
- `<name>.html` - thin wrapper that drops one part on a page.
- `lab.html` - review page: the thumbnail strip, then every tile at 80% with a
  download button each.

`__PART:x__` includes `parts/x.html`. `__DATA:path__` inlines an asset as a
base64 data URI, resolved against `assets/store-listing`. Unlike the AIBP
pipeline, which reads the fonts straight out of `apps/marketing/public`, this
repo has no marketing app - so `../font` holds copies of the two woff2 files
and `../icon/128.png` is a copy of `apps/pgp/public/icon-128.png`. If the icon
changes, re-copy it.

## Claims

Store reviewers read these, so everything on a tile traces to the repo:

- Slide `a`: the panel is a screenshot of the shipped build, so it is accurate
  by construction. Only the header strip above it is drawn in CSS, because that
  strip is Chrome's own: the browser renders the extension icon, name and close
  button above every side panel. The shortcuts are the real `commands` block in
  `wxt.config.ts`. The recipient is the `standard` e2e fixture, "Alice Example
  <alice@example.com>" - `example.com` is IANA-reserved for exactly this, so do
  not swap it for a plausible-looking address.
- Slide `b`: every store sealed under the master session - keyring, contacts,
  settings, CRX keys, history - each bound to its own `chrome.storage` key by
  an HKDF subkey and the AEAD's AAD. Source: `SECURITY.md` 11.1 and
  `lib/storage/encrypted-store.ts`; the size-padding claim is
  `normalizePadding`. "No analytics, no accounts" is defensible because the
  extension makes exactly one network request in its life - the opt-in GitHub
  SSH-key lookup, on an explicit button press (`SECURITY.md` 5). Do NOT soften
  it to "never touches the network": that is the one version of this claim
  that is false. The history row is tagged `opt-in` for the same reason - the
  feature is off by default, so most installs never create that store.
- Slide `c`: WebAuthn PRF unlock, Argon2id at 64 MB, and the three auto-lock
  modes. Source: `README.md` security model table.
- Slide `d`: atomic decrypt+verify with no TOCTOU window. Source: `README.md`.
- Slide `e`: Sequoia-PGP in WASM, AES-256-GCM with per-key AAD, SSH-key import
  for age. "No content scripts" is true of the manifest.

Slide `e` says "nothing here is a black box" without naming a competitor. That
is deliberate: a CWS asset that names another live listing invites a complaint,
and the claim is just as strong without it.

The sample identity across the tiles is `James Arnott
<james@amibeingpwned.com>`. Keep it - a real-looking personal address in a
screenshot invites someone to mail it.
