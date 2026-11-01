#!/usr/bin/env python3
"""Render coloured terminal output to a PNG for the README.

    CLICOLOR_FORCE=1 ./unlisted check -f demo/registry.yml --config-root demo \\
      | python3 scripts/render-demo.py "unlisted check -f registry.yml" docs/demo.png

Needs Pillow and a monospace font with box-drawing glyphs. Dev-only: nothing in
the Go build depends on it.
"""
import re
import sys

from PIL import Image, ImageDraw, ImageFont

FONTS = [
    ("/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
     "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
]
SIZE = 17
SCALE = 2  # render at 2x so the PNG stays sharp on retina screens
BG = (22, 24, 29)
FG = (205, 210, 220)
CHROME = (33, 36, 43)

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def xterm(n):
    if n < 16:
        base = [(0, 0, 0), (205, 49, 49), (13, 188, 121), (229, 229, 16), (36, 114, 200), (188, 63, 188),
                (17, 168, 205), (229, 229, 229), (102, 102, 102), (241, 76, 76), (35, 209, 139),
                (245, 245, 67), (59, 142, 234), (214, 112, 214), (41, 184, 219), (255, 255, 255)]
        return base[n]
    if n >= 232:
        v = 8 + (n - 232) * 10
        return (v, v, v)
    n -= 16
    lv = [0, 95, 135, 175, 215, 255]
    return (lv[n // 36], lv[(n // 6) % 6], lv[n % 6])


def parse(text):
    """Yield lines of (char, colour, bold, dim) cells."""
    lines = []
    colour, bold, dim = FG, False, False
    for raw in text.rstrip("\n").split("\n"):
        cells, pos = [], 0
        for m in SGR.finditer(raw):
            for ch in raw[pos:m.start()]:
                cells.append((ch, colour, bold, dim))
            pos = m.end()
            codes = [int(c) if c else 0 for c in m.group(1).split(";")]
            i = 0
            while i < len(codes):
                c = codes[i]
                if c == 0:
                    colour, bold, dim = FG, False, False
                elif c == 1:
                    bold = True
                elif c == 2:
                    dim = True
                elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                    colour = xterm(codes[i + 2])
                    i += 2
                i += 1
        for ch in raw[pos:]:
            cells.append((ch, colour, bold, dim))
        lines.append(cells)
    return lines


def main():
    title = sys.argv[1] if len(sys.argv) > 1 else "unlisted check"
    out = sys.argv[2] if len(sys.argv) > 2 else "docs/demo.png"
    text = sys.stdin.read()

    for reg, bold_path in FONTS:
        try:
            font = ImageFont.truetype(reg, SIZE * SCALE)
            bfont = ImageFont.truetype(bold_path, SIZE * SCALE)
            break
        except OSError:
            continue
    else:
        sys.exit("no monospace font found")

    cw = int(font.getlength("M"))
    lh = int(SIZE * SCALE * 1.45)
    lines = parse(text)
    cols = max(len(l) for l in lines)
    pad = 28 * SCALE
    bar = 44 * SCALE
    prompt_h = lh * 2
    w = cols * cw + pad * 2
    h = bar + pad + prompt_h + len(lines) * lh + pad

    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, bar], fill=CHROME)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        cx = pad + i * 26 * SCALE
        cy = bar // 2
        r = 7 * SCALE
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=c)
    tfont = ImageFont.truetype(FONTS[0][0], 14 * SCALE) if FONTS[0][0] else font
    tw = tfont.getlength(title)
    d.text(((w - tw) / 2, bar // 2 - 9 * SCALE), title, font=tfont, fill=(140, 146, 158))

    y = bar + pad
    d.text((pad, y), "$ " + title, font=bfont, fill=(120, 200, 140))
    y += prompt_h
    for cells in lines:
        x = pad
        for ch, colour, bold, dim in cells:
            if dim:
                colour = tuple(int(c * 0.55 + b * 0.45) for c, b in zip(colour, BG))
            if ch != " ":
                d.text((x, y), ch, font=bfont if bold else font, fill=colour)
            x += cw
        y += lh
    img.save(out, optimize=True)
    print("wrote", out, img.size)


if __name__ == "__main__":
    main()
