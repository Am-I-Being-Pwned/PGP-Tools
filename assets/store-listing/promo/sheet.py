#!/usr/bin/env python3
"""Contact sheets: every locale's five tiles at the size the store shows them.

    python3 sheet.py            # exports/<locale>/sheet.png for every locale
    python3 sheet.py de ja      # only these

Needs Pillow (`pip install pillow`); build.py itself does not.
"""
import os
import sys

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
EXPORTS = os.path.join(HERE, "exports")
W, H, PAD, LABEL = 640, 400, 16, 22  # 640x400 is roughly the listing carousel

locales = sys.argv[1:] or sorted(
    d for d in os.listdir(EXPORTS) if os.path.isdir(os.path.join(EXPORTS, d))
)
for locale in locales:
    sheet = Image.new("RGB", (PAD * 3 + W * 2, PAD * 4 + (H + LABEL) * 3), "#0c0c0c")
    draw = ImageDraw.Draw(sheet)
    for i, name in enumerate("abcde"):
        src = os.path.join(EXPORTS, locale, "%s-1280x800.png" % name)
        tile = Image.open(src).convert("RGB").resize((W, H), Image.LANCZOS)
        x = PAD + (i % 2) * (W + PAD)
        y = PAD + (i // 2) * (H + LABEL + PAD)
        draw.text((x, y + 4), "%s  tile %s  (store size)" % (locale, name), fill="#898989")
        sheet.paste(tile, (x, y + LABEL))
    out = os.path.join(EXPORTS, locale, "sheet.png")
    sheet.save(out)
    print("wrote", os.path.relpath(out, HERE))
