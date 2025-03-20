import os
import sys
import shutil

def fix_imports():
    """Create a fixed version of wol_app.py with proper imports."""
    # Read the original file
    with open('wol_app.py', 'r') as f:
        content = f.read()
    
    # Create a fixed version
    fixed_content = """
# Add the current directory to the path to ensure modules can be found
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

""" + content
    
    # Write the fixed version
    with open('wol_app_fixed.py', 'w') as f:
        f.write(fixed_content)
    
    print("Created fixed version of wol_app.py")

if __name__ == "__main__":
    fix_imports()
