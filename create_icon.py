import os
import cairosvg
from PIL import Image

# Convert SVG to PNG
svg_file = 'app_icon.svg'
png_file = 'app_icon.png'
ico_file = 'app_icon.ico'

# Convert SVG to PNG
cairosvg.svg2png(url=svg_file, write_to=png_file, output_width=256, output_height=256)

# Convert PNG to ICO with multiple sizes
img = Image.open(png_file)
icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
img.save(ico_file, sizes=icon_sizes)

print(f"Icon created: {ico_file}")

# Clean up the temporary PNG file
os.remove(png_file)
