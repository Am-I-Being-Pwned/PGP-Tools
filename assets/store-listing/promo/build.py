#!/usr/bin/env python3
"""Build the Chrome Web Store listing artwork for PGP Tools.

Tiles are plain HTML rendered headless at exact pixel sizes. They reuse the
extension's own design tokens (packages/tailwind-config theme, the same tokens
the side panel renders with) and its shipped icon, so the listing and the
product stay one design and nothing lives in a design tool -- the artwork is
reviewable in a diff.

Assets referenced as __DATA:<path>__ are inlined as base64 data URIs, resolved
against ../ (assets/store-listing), so a built page is a single self-contained
file that renders identically anywhere.

Copy is not in the parts: every user-facing string is a __T:key__ token
resolved from i18n/<locale>.json, so the same tiles render in every UI
language the extension ships. __UI:<file>__ inlines ../ui/<locale>/<file>,
the real panel captured in that language by apps/pgp/e2e-capture, and
__LANG__ is the page's lang attribute. The marquee (m1) is not localised
because the store does not localise marquee tiles.

Usage:
    python3 build.py                     # every tile + lab page, every locale
    python3 build.py a lab               # only these tiles, every locale
    python3 build.py --locale de         # one locale (or --locale en,de,fr)
    python3 build.py --render            # build, then render exports/<locale>/*.png
"""
import json

import base64
import mimetypes
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
EXPORTS = os.path.join(HERE, "exports")
I18N = os.path.join(HERE, "i18n")
UI = os.path.abspath(os.path.join(HERE, "..", "ui"))

# Tiles that carry no copy of their own, so one render serves every locale.
UNLOCALISED = {"m1"}

# Asset roots, searched in order. Unlike the AIBP listing (which reads straight
# out of apps/marketing/public), this repo has no marketing app, so the two
# woff2 files and the icon are copied into ../font and ../icon.
ROOTS = [
    os.path.abspath(os.path.join(HERE, "..")),
]

# name -> (width, height). 1280x800 is the CWS / Edge screenshot size;
# 1400x560 is the marquee promo tile.
TILES = {
    "a": (1280, 800),
    "b": (1280, 800),
    "c": (1280, 800),
    "d": (1280, 800),
    "e": (1280, 800),
    "m1": (1400, 560),
}

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def data_uri(rel):
    for root in ROOTS:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            if path.endswith(".woff2"):
                mime = "font/woff2"
            with open(path, "rb") as handle:
                blob = base64.b64encode(handle.read()).decode()
            return "data:%s;base64,%s" % (mime, blob)
    raise SystemExit("missing asset: %s (looked in %s)" % (rel, ", ".join(ROOTS)))


def part(name):
    with open(os.path.join(HERE, "parts", name + ".html")) as handle:
        return handle.read()


def locales():
    return sorted(
        f[:-5] for f in os.listdir(I18N) if f.endswith(".json") and f != "en.json"
    )


def strings(locale):
    """Copy for `locale`, falling back to en key by key like chrome.i18n."""
    with open(os.path.join(I18N, "en.json")) as handle:
        table = json.load(handle)
    if locale != "en":
        with open(os.path.join(I18N, locale + ".json")) as handle:
            table.update(json.load(handle))
    return table


def ui_uri(rel, locale):
    """The panel capture for `locale`, or en's if it has not been captured."""
    for candidate in (os.path.join(UI, locale, rel), os.path.join(UI, "en", rel), os.path.join(UI, rel)):
        if os.path.exists(candidate):
            return data_uri(os.path.relpath(candidate, ROOTS[0]))
    raise SystemExit("missing panel capture: ui/%s/%s" % (locale, rel))


def expand(text, css, locale):
    table = strings(locale)
    text = text.replace("__CSS__", css).replace("__LANG__", locale.replace("_", "-"))
    # Parts can include parts, so keep substituting until it settles.
    for _ in range(4):
        grown = re.sub(r"__PART:([a-z0-9\-]+)__", lambda m: part(m.group(1)), text)
        if grown == text:
            break
        text = grown

    def t(m):
        key = m.group(1)
        if key not in table:
            raise SystemExit("i18n/%s.json: no string for %s" % (locale, key))
        return table[key]

    text = re.sub(r"__T:([a-z0-9_.]+)__", t, text)
    text = re.sub(r"__UI:([^_]+?)__", lambda m: ui_uri(m.group(1), locale), text)
    return re.sub(r"__DATA:([^_]+?)__", lambda m: data_uri(m.group(1)), text)


def build(names, css, locale):
    out_dir = os.path.join(BUILD, locale)
    os.makedirs(out_dir, exist_ok=True)
    for name in names:
        if name in UNLOCALISED and locale != "en":
            continue
        with open(os.path.join(HERE, name + ".html")) as handle:
            page = expand(handle.read(), css, locale)
        out = os.path.join(out_dir, name + ".html")
        with open(out, "w") as handle:
            handle.write(page)
        print("built", os.path.relpath(out, HERE))


def render(names, locale):
    if not os.path.exists(CHROME):
        raise SystemExit("Chrome not found at %s" % CHROME)
    out_dir = os.path.join(EXPORTS, locale)
    os.makedirs(out_dir, exist_ok=True)
    for name in names:
        if name not in TILES or (name in UNLOCALISED and locale != "en"):
            continue
        width, height = TILES[name]
        out = os.path.join(out_dir, "%s-%dx%d.png" % (name, width, height))
        subprocess.run(
            [
                CHROME,
                "--headless",
                "--disable-gpu",
                "--hide-scrollbars",
                "--force-device-scale-factor=1",
                "--window-size=%d,%d" % (width, height),
                "--virtual-time-budget=3000",
                "--screenshot=" + out,
                "file://" + os.path.join(BUILD, locale, name + ".html"),
            ],
            check=True,
            capture_output=True,
        )
        print("rendered", os.path.relpath(out, HERE))


def main():
    argv = sys.argv[1:]
    do_render = "--render" in argv
    wanted = ["en"] + locales()
    if "--locale" in argv:
        wanted = argv[argv.index("--locale") + 1].split(",")
        del argv[argv.index("--locale") : argv.index("--locale") + 2]
    args = [a for a in argv if a != "--render"]
    names = args or (list(TILES) + ["lab"])

    with open(os.path.join(HERE, "parts.css")) as handle:
        css = handle.read()

    for locale in wanted:
        build(names, css, locale)
        if do_render:
            render(names, locale)


if __name__ == "__main__":
    main()
