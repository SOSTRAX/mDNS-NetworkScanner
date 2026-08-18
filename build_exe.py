from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
script = ROOT / "mDNS-NetworkScanner-GUI.py"
icon = ROOT / "app_icon.ico"

cmd = [
    "pyinstaller",
    "--onefile",
    "--windowed",
    "--noconsole",
    "--clean",
    "--name",
    "mDNS-NetworkScanner",
    "--icon",
    str(icon),
    str(script),
]

print("Running build command:")
print(" ".join(cmd))
subprocess.run(cmd, cwd=str(ROOT), check=True)
print("\nEXE created in:")
print(ROOT / "dist")
