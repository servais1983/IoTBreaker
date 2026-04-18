#!/usr/bin/env python3
"""Generate a pixel-perfect terminal screenshot for IoTBreaker README.
Uses JetBrains Mono (true monospace) for perfect ASCII art alignment.
"""

from PIL import Image, ImageDraw, ImageFont

FONT_REG  = "/tmp/jbmono/fonts/ttf/JetBrainsMono-Regular.ttf"
FONT_BOLD = "/tmp/jbmono/fonts/ttf/JetBrainsMono-Bold.ttf"

# ── Palette ────────────────────────────────────────────────────────────────
BG       = (13,  17,  23)
SURFACE  = (22,  27,  34)
BORDER   = (48,  54,  61)
BORDER2  = (33,  38,  45)
BLUE     = (31, 111, 235)
BLUE_LT  = (88, 166, 255)
GREEN    = (63, 185,  80)
RED      = (248, 81,  73)
ORANGE   = (227, 179,  65)
YELLOW   = (210, 153,  34)
MUTED    = (139, 148, 158)
WHITE    = (230, 237, 243)
GRAY_DIM = (72,  79,  88)
DOT_RED  = (255,  95,  87)
DOT_YEL  = (254, 188,  46)
DOT_GRN  = (40,  200,  64)

# ── Canvas ─────────────────────────────────────────────────────────────────
W, H     = 1600, 900
PAD_X    = 50
RADIUS   = 12
ASCII_SZ = 20   # 12.0px/char — perfectly monospace
BODY_SZ  = 15
SMALL_SZ = 13

# ── ASCII art (exact copy from tool output) ────────────────────────────────
ASCII_ART = [
    "  ___    _____   ____                  _",
    " |_ _|  |_   _| | __ )  _ __  ___  __ _| | _____ _ __",
    "  | |     | |   |  _ \\ | '__|/ _ \\/ _` | |/ / _ \\ '__|",
    "  | |     | |   | |_) || |  |  __/ (_| |   <  __/ |",
    " |___|    |_|   |____/ |_|   \\___|\\_,_|_|\\_\\___|_|",
]

# ── Output lines: list of (text, color, bold) tuples ──────────────────────
LINES = [
    [("$ ", GRAY_DIM, False), ("python3 iotbreaker.py audit --network 192.168.1.0/24 --format html", WHITE, True)],
    [("[*] ", BLUE_LT, False), ("Session ID: 20260418_143201  |  Module: AUDIT  |  Threads: 100", MUTED, False)],
    [("[*] ", BLUE_LT, False), ("Phase 1/4 -- Network Discovery (ARP + ICMP + TCP + mDNS + SSDP)", MUTED, False)],
    [("[+] ", GREEN, False),   ("Discovered 14 live hosts in 4.2s", GREEN, False)],
    [("[*] ", BLUE_LT, False), ("Phase 2/4 -- Port Scan & Device Fingerprinting", MUTED, False)],
    [("[+] ", GREEN, False),   ("192.168.1.100   Hikvision DS-2CD2143G2-I   [80, 443, 554, 8000]   Linux 3.4", GREEN, False)],
    [("[+] ", GREEN, False),   ("192.168.1.101   Dahua IPC-HDW2831T-AS      [80, 443, 37777]       Linux 3.10", GREEN, False)],
    [("[*] ", BLUE_LT, False), ("Phase 3/4 -- Vulnerability Assessment (Telnet / SSH / MQTT / HTTP / RTSP / SNMP)", MUTED, False)],
    [("[!] CRITICAL   CVE-2021-36260   CVSS 9.8   Hikvision Unauthenticated RCE            192.168.1.100:80", RED, True)],
    [("[!] CRITICAL   CVE-2023-1389    CVSS 9.8   Telnet Default Credentials admin:admin   192.168.1.101:23", RED, True)],
    [("[!] HIGH       CVE-2017-7650    CVSS 7.5   MQTT Anonymous Authentication Bypass     192.168.1.100:1883", ORANGE, False)],
    [("[!] HIGH                        CVSS 7.5   RTSP Unauthenticated Stream Access       192.168.1.100:554", ORANGE, False)],
    [("[!] MEDIUM     CVE-1999-0517    CVSS 5.3   SNMP Default Community String 'public'  192.168.1.1:161", YELLOW, False)],
    [("[*] ", BLUE_LT, False), ("Phase 4/4 -- Generating Reports", MUTED, False)],
    [("[+] ", GREEN, False),   ("reports/iotbreaker_20260418_143201.html  |  reports/iotbreaker_20260418_143201.json", GREEN, False)],
    [("[*] ", MUTED, False),   ("Completed in 38.4s  |  14 host(s)  |  5 finding(s)  |  Risk Score: ", MUTED, False), ("8.6 / 10.0", RED, True)],
]


def render_segments(draw, x, y, segments, fnt_reg, fnt_bold):
    for seg in segments:
        text, color, bold = seg
        fnt = fnt_bold if bold else fnt_reg
        draw.text((x, y), text, font=fnt, fill=color)
        bbox = draw.textbbox((0, 0), text, font=fnt)
        x += bbox[2] - bbox[0]


def main():
    img  = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # ── Terminal window ──────────────────────────────────────────────────────
    draw.rounded_rectangle([20, 20, W-20, H-20], radius=RADIUS,
                           fill=SURFACE, outline=BORDER, width=2)

    # Title bar separator
    draw.line([(22, 72), (W-22, 72)], fill=BORDER2, width=1)

    # Traffic lights
    for i, col in enumerate([DOT_RED, DOT_YEL, DOT_GRN]):
        cx = 52 + i * 24
        draw.ellipse([cx-8, 46-8, cx+8, 46+8], fill=col)

    # Title label
    fnt_small = ImageFont.truetype(FONT_REG, SMALL_SZ)
    label = "iotbreaker -- bash -- 160x40"
    bbox  = draw.textbbox((0, 0), label, font=fnt_small)
    draw.text((W - 20 - PAD_X - (bbox[2]-bbox[0]), 39), label,
              font=fnt_small, fill=GRAY_DIM)

    # ── ASCII art (JetBrains Mono = perfect monospace) ───────────────────────
    fnt_ascii = ImageFont.truetype(FONT_BOLD, ASCII_SZ)
    y = 90
    for line in ASCII_ART:
        draw.text((PAD_X, y), line, font=fnt_ascii, fill=BLUE)
        y += ASCII_SZ + 8

    # ── Subtitle ─────────────────────────────────────────────────────────────
    fnt_body = ImageFont.truetype(FONT_REG, BODY_SZ)
    y += 4
    draw.text((PAD_X, y), "  IoT Security Assessment Framework  v4.0.0",
              font=fnt_body, fill=MUTED)
    y += BODY_SZ + 5
    draw.text((PAD_X, y), "  Professional Penetration Testing Toolkit for IoT Devices",
              font=fnt_body, fill=MUTED)
    y += BODY_SZ + 5
    draw.text((PAD_X, y), "  " + "-" * 55,
              font=fnt_body, fill=BORDER)
    y += BODY_SZ + 20

    # ── Output lines ─────────────────────────────────────────────────────────
    fnt_reg  = ImageFont.truetype(FONT_REG,  BODY_SZ)
    fnt_bold = ImageFont.truetype(FONT_BOLD, BODY_SZ)
    LINE_H   = BODY_SZ + 11

    for segments in LINES:
        render_segments(draw, PAD_X, y, segments, fnt_reg, fnt_bold)
        y += LINE_H

    out = "/home/ubuntu/IoTBreaker/assets/terminal_demo.png"
    img.save(out, "PNG")
    print(f"Saved: {out}  ({W}x{H})")


if __name__ == "__main__":
    main()
