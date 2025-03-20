import os
import subprocess
import sys

def build_exe():
    """Build the executable using PyInstaller."""
    # Define the PyInstaller command
    cmd = [
        "pyinstaller",
        "--name=OmniScan",
        "--onefile",
        "--windowed",
        "--add-data=app_icon.svg;.",
        "--hidden-import=ad_tools",
        "--add-data=ad_tools.py;.",
        "wol_app.py"
    ]
    
    # Run PyInstaller
    print("Building executable with PyInstaller...")
    subprocess.run(cmd, check=True)
    
    print("\nBuild completed successfully!")
    print("Executable location: dist/OmniScan.exe")

if __name__ == "__main__":
    build_exe()
