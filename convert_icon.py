import os
from PIL import Image
import cairosvg
import io

def convert_svg_to_ico():
    """Convert SVG to ICO format."""
    svg_file = 'new_app_icon.svg'
    ico_file = 'new_app_icon.ico'
    
    # Convert SVG to PNG in memory
    png_data = cairosvg.svg2png(url=svg_file, output_width=256, output_height=256)
    
    # Load the PNG data into a PIL Image
    img = Image.open(io.BytesIO(png_data))
    
    # Create ICO with multiple sizes
    icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(ico_file, format='ICO', sizes=icon_sizes)
    
    print(f"Icon created: {ico_file}")

if __name__ == "__main__":
    try:
        convert_svg_to_ico()
    except Exception as e:
        print(f"Error: {e}")
        
        # Alternative approach if cairosvg fails
        try:
            from PIL import Image
            print("Trying alternative approach with Pillow...")
            
            # Create a simple colored image as icon
            img = Image.new('RGB', (256, 256), color=(26, 37, 48))
            
            # Draw green arcs (simplified version of the SVG)
            from PIL import ImageDraw
            draw = ImageDraw.Draw(img)
            green_color = (46, 204, 113)  # #2ecc71
            
            # Draw some curved lines to approximate the SVG
            for offset in range(20, 100, 20):
                draw.arc((offset, offset, 256-offset, 256-offset), 
                         start=0, end=270, fill=green_color, width=10)
            
            # Save as ICO
            icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
            img.save('new_app_icon.ico', format='ICO', sizes=icon_sizes)
            print("Created alternative icon: new_app_icon.ico")
        except Exception as e2:
            print(f"Alternative approach also failed: {e2}")
            print("Please install an SVG to ICO converter or use an online service.")
