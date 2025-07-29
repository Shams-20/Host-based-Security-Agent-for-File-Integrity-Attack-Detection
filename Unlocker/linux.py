import os
import subprocess
from pathlib import Path
import getpass

def unlock_everything(base_path):
    user = getpass.getuser()

    for root, dirs, files in os.walk(base_path):
        # First fix dir perms so you can reach inside
        subprocess.run(["sudo", "chmod", "755", root], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "chown", f"{user}:{user}", root], stderr=subprocess.DEVNULL)

        for name in files:
            file_path = os.path.join(root, name)
            try:
                subprocess.run(["sudo", "chattr", "-i", file_path], stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "chmod", "644", file_path], check=True)
                subprocess.run(["sudo", "chown", f"{user}:{user}", file_path], check=True)
                print(f"✅ Unlocked: {file_path}")
            except Exception as e:
                print(f"❌ Still locked: {file_path} → {e}")

if __name__ == "__main__":
    target = input("Enter path to unlock: ").strip()
    if not os.path.exists(target):
        print("🚫 Path doesn't exist, go touch grass.")
        exit(1)

    unlock_everything(target)
