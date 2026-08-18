from pathlib import Path
from PIL import Image, ImageDraw, ImageColor

ROOT = Path(__file__).resolve().parent

# Create a custom icon for the network scanner.
img = Image.new("RGBA", (256, 256), (12, 22, 36, 255))
draw = ImageDraw.Draw(img)

# Gradient-ish background effect.
for y in range(256):
    alpha = int(255 * (y / 255))
    color = ImageColor.getcolor(f"#{34 + (y // 4):02x}9bff", "RGB")
    draw.line((0, y, 255, y), fill=(color[0], color[1], color[2], alpha))

# Outer hex/rounded badge-like shape.
shape = [
    (54, 48), (202, 48), (236, 128), (202, 208), (54, 208), (20, 128)
]
draw.polygon(shape, fill=(18, 33, 61, 220), outline=(109, 201, 255, 255), width=6)

# Network nodes and connections.
points = [
    (80, 88), (176, 88), (128, 150), (80, 188), (176, 188), (128, 100)
]
for x, y in points:
    draw.ellipse((x - 12, y - 12, x + 12, y + 12), fill=(130, 227, 255, 255), outline=(8, 18, 35, 255), width=2)

# Connections.
connectors = [
    ((80, 88), (128, 150)),
    ((176, 88), (128, 150)),
    ((80, 188), (128, 150)),
    ((176, 188), (128, 150)),
    ((80, 88), (176, 88)),
    ((80, 188), (176, 188)),
]
for a, b in connectors:
    draw.line(a + b, fill=(109, 201, 255, 240), width=4)

# Center "scan" ring.
scan_circle = (128, 128, 90)
draw.ellipse((128 - 48, 128 - 48, 128 + 48, 128 + 48), outline=(255, 255, 255, 200), width=6)
draw.ellipse((128 - 22, 128 - 22, 128 + 22, 128 + 22), fill=(64, 224, 192, 255), outline=(8, 18, 35, 255), width=2)

# Small highlight for a polished look.
for i in range(5):
    offset = 18 + i * 8
    draw.arc((40 + i * 14, 34 + i * 10, 220 - i * 14, 220 - i * 10), start=200, end=330, fill=(255, 255, 255, 80), width=2)

# Save both PNG and ICO.
img.save(ROOT / "app_icon.png")
img.save(ROOT / "app_icon.ico")

print("Created:")
print(ROOT / "app_icon.png")
print(ROOT / "app_icon.ico")
