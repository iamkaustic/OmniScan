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
        "--icon=new_app_icon.ico",
        "--add-data=new_app_icon.ico;.",
        "--add-data=app_icon.svg;.",
        "--add-data=ad_tools.py;.",
        "wol_app_fixed.py"
    ]
    
    # Run PyInstaller
    print("Building executable with PyInstaller...")
    subprocess.run(cmd, check=True)
    
    print("\nBuild completed successfully!")
    print("Executable location: dist/OmniScan.exe")

if __name__ == "__main__":
    build_exe()
