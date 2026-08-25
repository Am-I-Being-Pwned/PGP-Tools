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

Usage:
    python3 build.py            # build every tile + the review page
    python3 build.py a lab      # build only these
    python3 build.py --render   # build, then render exports/*.png (needs Chrome)
"""

import base64
import mimetypes
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
EXPORTS = os.path.join(HERE, "exports")

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


def expand(text, css):
    text = text.replace("__CSS__", css)
    # Parts can include parts, so keep substituting until it settles.
    for _ in range(4):
        grown = re.sub(r"__PART:([a-z0-9\-]+)__", lambda m: part(m.group(1)), text)
        if grown == text:
            break
        text = grown
    return re.sub(r"__DATA:([^_]+?)__", lambda m: data_uri(m.group(1)), text)


def build(names, css):
    os.makedirs(BUILD, exist_ok=True)
    for name in names:
        with open(os.path.join(HERE, name + ".html")) as handle:
            page = expand(handle.read(), css)
        out = os.path.join(BUILD, name + ".html")
        with open(out, "w") as handle:
            handle.write(page)
        print("built", os.path.relpath(out, HERE))


def render(names):
    if not os.path.exists(CHROME):
        raise SystemExit("Chrome not found at %s" % CHROME)
    os.makedirs(EXPORTS, exist_ok=True)
    for name in names:
        if name not in TILES:
            continue
        width, height = TILES[name]
        out = os.path.join(EXPORTS, "%s-%dx%d.png" % (name, width, height))
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
                "file://" + os.path.join(BUILD, name + ".html"),
            ],
            check=True,
            capture_output=True,
        )
        print("rendered", os.path.relpath(out, HERE))


def main():
    args = [a for a in sys.argv[1:] if a != "--render"]
    do_render = "--render" in sys.argv
    names = args or (list(TILES) + ["lab"])

    with open(os.path.join(HERE, "parts.css")) as handle:
        css = handle.read()

    build(names, css)
    if do_render:
        render(names)


if __name__ == "__main__":
    main()
