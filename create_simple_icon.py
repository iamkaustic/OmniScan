from PIL import Image, ImageDraw

# Create a new image with a dark background
img = Image.new('RGB', (256, 256), color=(26, 37, 48))  # #1a2530

# Get a drawing context
draw = ImageDraw.Draw(img)

# Define the green color
green_color = (46, 204, 113)  # #2ecc71

# Draw curved lines to approximate the SVG
for i, offset in enumerate(range(40, 120, 20)):
    # Draw arcs that form a stylized "O" shape
    draw.arc((offset, offset, 256-offset, 256-offset), 
             start=0, end=270, fill=green_color, width=12)

# Save as ICO with multiple sizes
icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
img.save('new_app_icon.ico', format='ICO', sizes=icon_sizes)

print("Created icon: new_app_icon.ico")
