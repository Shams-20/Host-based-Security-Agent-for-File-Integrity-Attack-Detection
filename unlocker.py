import subprocess
import sys

def unlock_file(file_path):
    try:
        subprocess.run(["icacls", file_path, "/remove:d", "Everyone"], check=True)
        subprocess.run(["icacls", file_path, "/inheritance:e"], check=True)
        print(f"🔓 Unlocked file: {file_path}")
    except Exception as e:
        print(f"⚠️ Failed to unlock file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unlocker.py <file_path>")
    else:
        unlock_file(sys.argv[1])