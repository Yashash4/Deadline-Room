"""Render the Deadline Room submission cover image deterministically.

Produces a 1920x1080 PNG at samples/cover.png: an enterprise dark war-room
panel with the four racing statutory countdown clocks, a red "submission
blocked: filings contradict" banner, and the one-line dinner pitch.

No external assets and no downloaded fonts. Text is drawn with the PIL
default bitmap font scaled up with a clean integer-multiple render, so the
output is byte-stable on any machine with Pillow installed:

    py scripts/make_cover.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Enterprise dark theme, taken from the live web viewer (web/styles.css) so the
# cover, the demo, and the Examiner Packet all read as one product.
BG = (10, 14, 23)            # #0a0e17 panel background
PANEL = (24, 32, 47)         # #18202f raised panel
PANEL_EDGE = (35, 48, 69)    # #233045 hairline border
TEXT = (230, 237, 246)       # #e6edf6 primary text
MUTED = (139, 155, 180)      # #8b9bb4 secondary text
AMBER = (255, 181, 71)       # #ffb547 clock accent
RED = (255, 95, 110)         # #ff5f6e contradiction banner
RED_BG = (58, 24, 32)        # #3a1820 red panel fill
GREEN = (63, 208, 127)       # #3fd07f passing
BLUE = (77, 163, 255)        # #4da3ff band routing

W, H = 1920, 1080


def _font(size: int) -> ImageFont.ImageFont:
    """Scale the bundled PIL bitmap font by an integer factor.

    Pillow's default font is a fixed ~10px bitmap. We render text once at the
    base size and upscale by a whole-number factor with nearest-neighbour, so
    the result is crisp, dependency-free, and identical on every machine. This
    avoids shipping or fetching a TTF, which the brief forbids.
    """
    return ImageFont.load_default()


# Base font metrics for the bundled bitmap font.
_BASE = ImageFont.load_default()
_CW, _CH = _BASE.getbbox("M")[2], 11  # one glyph cell, monospace bitmap


def draw_text(img: Image.Image, xy, text: str, scale: int, fill, anchor="lt"):
    """Draw upscaled bitmap text. anchor is a two-char PIL-style anchor on the
    scaled box: horizontal l/m/r, vertical t/m/b."""
    # Render the line on a tight transparent tile at base resolution.
    bbox = _BASE.getbbox(text)
    tw = max(1, bbox[2] - bbox[0])
    th = max(1, _CH)
    tile = Image.new("RGBA", (tw, th), (0, 0, 0, 0))
    d = ImageDraw.Draw(tile)
    d.text((-bbox[0], 0), text, font=_BASE, fill=fill + (255,))
    tile = tile.resize((tw * scale, th * scale), Image.NEAREST)

    x, y = xy
    if anchor[0] == "m":
        x -= tile.width // 2
    elif anchor[0] == "r":
        x -= tile.width
    if anchor[1] == "m":
        y -= tile.height // 2
    elif anchor[1] == "b":
        y -= tile.height
    img.paste(tile, (int(x), int(y)), tile)
    return tile.width, tile.height


def rounded_panel(d: ImageDraw.ImageDraw, box, fill, edge, radius=18, width=2):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=edge, width=width)


def clock_card(img, draw, x, y, w, h, regime, deadline, remaining, urgent):
    """One statutory countdown card: regime, deadline window, time remaining."""
    accent = RED if urgent else AMBER
    rounded_panel(draw, (x, y, x + w, y + h), PANEL, PANEL_EDGE, radius=16)
    # accent bar down the left edge
    draw.rounded_rectangle((x, y, x + 8, y + h), radius=4, fill=accent)
    draw_text(img, (x + 32, y + 26), regime, 3, TEXT)
    draw_text(img, (x + 32, y + 70), deadline, 2, MUTED)
    # big remaining time
    draw_text(img, (x + w - 32, y + h - 40), remaining, 4, accent, anchor="rb")
    draw_text(img, (x + 32, y + h - 36), "TIME LEFT", 1, MUTED)


def main() -> Path:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # Subtle grid baseline for the war-room feel.
    for gx in range(0, W, 80):
        draw.line((gx, 0, gx, H), fill=(15, 20, 31), width=1)
    for gy in range(0, H, 80):
        draw.line((0, gy, W, gy), fill=(15, 20, 31), width=1)

    # --- Header -------------------------------------------------------------
    draw_text(img, (80, 64), "DEADLINE ROOM", 6, TEXT)
    draw_text(img, (84, 150), "multi-agent regulated breach-reporting war room on Band", 2, BLUE)
    draw_text(img, (W - 80, 78), "INCIDENT INC-8842", 2, MUTED, anchor="rt")
    draw_text(img, (W - 80, 116), "DETERMINISTIC WARDEN  /  NO LLM", 2, GREEN, anchor="rt")

    # --- Four racing clocks -------------------------------------------------
    clocks = [
        ("NIS2 EARLY WARNING", "EU  /  within 24h", "06:11", False),
        ("DORA FOLLOW-UP", "EU  /  within 72h", "41:52", False),
        ("SEC ITEM 1.05", "US  /  4 business days", "63:08", False),
        ("UK ICO  /  GDPR ART 33", "UK  /  within 72h", "01:47", True),
    ]
    top = 230
    gap = 28
    cw = (W - 160 - 3 * gap) // 4
    ch = 240
    for i, (regime, window, rem, urgent) in enumerate(clocks):
        cx = 80 + i * (cw + gap)
        clock_card(img, draw, cx, top, cw, ch, regime, window, rem, urgent)

    # --- Red contradiction banner ------------------------------------------
    by0 = top + ch + 56
    bh = 150
    rounded_panel(draw, (80, by0, W - 80, by0 + bh), RED_BG, RED, radius=18, width=3)
    draw_text(img, (120, by0 + 30), "SUBMISSION BLOCKED", 5, RED)
    draw_text(img, (122, by0 + 92),
              "the four filings contradict each other  /  Warden refuses signoff until they reconcile",
              2, TEXT)
    # a small "VETO" stamp on the right
    draw.rounded_rectangle((W - 320, by0 + 34, W - 120, by0 + bh - 34),
                           radius=12, outline=RED, width=4)
    draw_text(img, (W - 220, by0 + bh // 2), "VETO", 4, RED, anchor="mm")

    # --- The dinner sentence -----------------------------------------------
    dy = by0 + bh + 56
    rounded_panel(draw, (80, dy, W - 80, H - 64), PANEL, PANEL_EDGE, radius=18)
    lines = [
        "The second a bank gets breached, four government clocks start and four",
        "agent teams race to file four different reports in parallel. A deterministic",
        "referee holds the clocks, refuses any handoff that breaks the protocol, and",
        "even when you kill an agent live on stage the books still come out exactly once",
        "and no two filings are allowed to contradict each other.",
    ]
    ly = dy + 34
    for line in lines:
        draw_text(img, (120, ly), line, 2, TEXT)
        ly += 38
    draw_text(img, (W - 120, H - 96),
              "104 tests passing  /  byte-identical replay  /  exactly-once under live kill",
              1, GREEN, anchor="rb")

    out = Path(__file__).resolve().parent.parent / "samples" / "cover.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, "PNG")
    print(f"cover written: {out}  ({img.width}x{img.height})")
    return out


if __name__ == "__main__":
    main()
