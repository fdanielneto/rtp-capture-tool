from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 2048, 760
OUT_DIR = Path("artifacts/palette-previews")
OUT_DIR.mkdir(parents=True, exist_ok=True)

PALETTES = [
    {
        "name": "paleta-1-operacional-equilibrada",
        "yellow": "#FFD84D",
        "green": "#39D98A",
        "blue": "#4EA1FF",
        "purple": "#A78BFA",
        "pink": "#8FA9D8",
        "base": "#D7E3FF",
    },
    {
        "name": "paleta-2-alto-contraste",
        "yellow": "#FFE45C",
        "green": "#22C55E",
        "blue": "#3B82F6",
        "purple": "#8B5CF6",
        "pink": "#93A8CC",
        "base": "#E5EEFF",
    },
    {
        "name": "paleta-3-fria-tecnica",
        "yellow": "#FACC15",
        "green": "#34D399",
        "blue": "#60A5FA",
        "purple": "#A78BFA",
        "pink": "#9DB4D9",
        "base": "#DCE7FF",
    },
    {
        "name": "paleta-4-moderna-clean",
        "yellow": "#FDE047",
        "green": "#4ADE80",
        "blue": "#38BDF8",
        "purple": "#C084FC",
        "pink": "#A7B8D6",
        "base": "#E2EAFF",
    },
    {
        "name": "paleta-5-enfase-criticos",
        "yellow": "#FFDD57",
        "green": "#2DD4BF",
        "blue": "#4F8CFF",
        "purple": "#9F7AEA",
        "pink": "#95A9CF",
        "base": "#D9E6FF",
    },
]

BG_TOP = "#132B59"
BG_BOTTOM = "#041939"
PANEL_BG = "#001738"
PANEL_BORDER = "#2A64B8"
BUTTON_BG = "#2C6CE3"
BUTTON_TEXT = "#F2F7FF"


def get_fonts():
    try:
        title_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 56)
        mono_small = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 32)
        return title_font, mono_small
    except Exception:
        return ImageFont.load_default(), ImageFont.load_default()


def lerp(a, b, t):
    return int(a + (b - a) * t)


def gradient_bg():
    image = Image.new("RGB", (W, H), BG_BOTTOM)
    draw = ImageDraw.Draw(image)
    c1 = tuple(int(BG_TOP[i : i + 2], 16) for i in (1, 3, 5))
    c2 = tuple(int(BG_BOTTOM[i : i + 2], 16) for i in (1, 3, 5))

    for y in range(H):
        t = y / (H - 1)
        c = (lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t))
        draw.line([(0, y), (W, y)], fill=c)

    return image


def draw_token_line(draw, x, y, chunks, font, default_fill):
    current_x = x
    for text, color in chunks:
        fill = color or default_fill
        draw.text((current_x, y), text, font=font, fill=fill)
        bbox = draw.textbbox((current_x, y), text, font=font)
        current_x = bbox[2]


def generate_one(index, palette, title_font, mono_font):
    image = gradient_bg()
    draw = ImageDraw.Draw(image)

    draw.text((34, 16), "Logs", font=title_font, fill=palette["base"])

    draw.rounded_rectangle((1765, 10, 1915, 56), radius=14, fill=BUTTON_BG)
    draw.text((1784, 22), "Download logs", font=mono_font, fill=BUTTON_TEXT)
    draw.rounded_rectangle((1928, 10, 2028, 56), radius=14, fill=BUTTON_BG)
    draw.text((1956, 22), "Clear", font=mono_font, fill=BUTTON_TEXT)

    panel_x0, panel_y0, panel_x1, panel_y1 = 36, 76, 2010, 720
    draw.rounded_rectangle(
        (panel_x0, panel_y0, panel_x1, panel_y1),
        radius=14,
        fill=PANEL_BG,
        outline=PANEL_BORDER,
        width=3,
    )

    lines = [
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("Packet selection ", palette["base"]),
            ("analysis_packet=1 ", palette["purple"]),
            ("invite_cipher_packet=7 ", palette["purple"]),
            ("200ok_cipher_packet=37 ", palette["purple"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("INFO: Packet selection ", palette["base"]),
            ("analysis_packet=1 ", palette["pink"]),
            ("invite_cipher_packet=7 ", palette["pink"]),
            ("200ok_cipher_packet=37", palette["pink"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("Encryption expectation detected=True reasons=", palette["base"]),
            ("['invite:protocol=RTP/SAVP', 'invite:sdes=2']", palette["base"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("Carrier/Core resolved from SIP: ", palette["base"]),
            ("carrier=201.163.57.129 ", palette["pink"]),
            ("core=54.244.51.1", palette["pink"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("INFO: SDES material selected for decrypt phase:", palette["base"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            (
                "Decrypt material selected direction=outbound role=request suite=",
                palette["base"],
            ),
            ("AES_CM_128_HMAC_SHA1_80 ", palette["pink"]),
            ("packet_number=7", palette["purple"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("[carrier-rtpengine] ", palette["base"]),
            ("FILTER: ", palette["green"]),
            ("\"ip.src==54.243.121.233 && udp.port==30240\" ", palette["base"]),
            ("[media_stream_from_carrier_to_rtpengine]", palette["yellow"]),
        ],
        [
            ("[2026-03-01 04:43:13,275] [INFO] ", palette["blue"]),
            ("[rtpengine-carrier] ", palette["base"]),
            ("FILTER: ", palette["green"]),
            ("\"udp.srcport==22544 && ip.dst==54.243.121.233\" ", palette["base"]),
            ("[media stream from rtpengine to carrier]", palette["yellow"]),
        ],
    ]

    y = 94
    for _ in range(2):
        for line in lines:
            draw_token_line(draw, 52, y, line, mono_font, palette["base"])
            y += 42
            if y > panel_y1 - 50:
                break
        if y > panel_y1 - 50:
            break

    legend_y = panel_y1 + 8
    draw.text(
        (42, legend_y),
        f"Preview {index}: amarelo>verde>azul>roxo>rosa (fundo fixo)",
        font=mono_font,
        fill=palette["base"],
    )

    output_file = OUT_DIR / f"{index:02d}-{palette['name']}.png"
    image.save(output_file)
    return output_file


def main():
    title_font, mono_font = get_fonts()
    generated = []
    for i, palette in enumerate(PALETTES, start=1):
        generated.append(generate_one(i, palette, title_font, mono_font))

    for file in generated:
        print(file)


if __name__ == "__main__":
    main()
