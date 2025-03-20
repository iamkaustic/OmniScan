import os
import subprocess
import sys
import shutil

def build_exe():
    """Build the executable using PyInstaller."""
    # Clean up previous build files
    for folder in ['build', 'dist']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    
    # Define the PyInstaller command
    cmd = [
        "pyinstaller",
        "--name=OmniScan",
        "--onefile",
        "--windowed",
        "--add-data=app_icon.svg;.",
        "--add-data=ad_tools.py;.",
        "omniscan_launcher.py"
    ]
    
    # Run PyInstaller
    print("Building executable with PyInstaller...")
    subprocess.run(cmd, check=True)
    
    print("\nBuild completed successfully!")
    print("Executable location: dist/OmniScan.exe")

if __name__ == "__main__":
    build_exe()
