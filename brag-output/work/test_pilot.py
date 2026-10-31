from PIL import Image, ImageDraw, ImageFont
import math

width, height = 1920, 1080
img = Image.new("RGB", (width, height), (244, 239, 230))
draw = ImageDraw.Draw(img)

# Fonts
font_serif_lg = ImageFont.truetype(r"C:\Windows\Fonts\georgiab.ttf", 64)
font_serif_md = ImageFont.truetype(r"C:\Windows\Fonts\georgia.ttf", 32)
font_sans_sm = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 18)
font_mono = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 20)

# Draw hairline border
draw.rectangle([60, 60, width - 60, height - 60], outline=(226, 221, 213), width=1)

# Draw top masthead
draw.text((80, 80), "ISSUE N° 48 • AUTUMN 2026 • THE AEGIS HARNESS SPECIFICATION • KOLKATA, WEST BENGAL", fill=(110, 107, 102), font=font_sans_sm)
draw.line([(80, 115), (width - 80, 115)], fill=(226, 221, 213), width=1)

# Draw Title
draw.text((width//2, 360), "Can your AI agent be trusted?", fill=(26, 26, 26), font=font_serif_lg, anchor="mm")
draw.text((width//2, 450), "Put it to the test.", fill=(178, 58, 34), font=font_serif_lg, anchor="mm")
draw.text((width//2, 540), "Challenge AI agents. Expose unauthorized actions. Verify that every operation remains under control.", fill=(110, 107, 102), font=font_serif_md, anchor="mm")

img.save(r"brag-output\work\test_frame.png")
print("SUCCESS: test_frame.png created")

