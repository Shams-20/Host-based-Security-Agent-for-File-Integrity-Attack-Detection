import time
import os
import hashlib
import json
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

event_cooldown = {}
COOLDOWN_SECONDS = 2
baseline_file = "hashes.json"

def format_event(event_type, filepath, status, emoji, msg):
    name = Path(filepath).name
    return f"[ {event_type:^9} ] {name:<25} → {status:<7} {emoji} {msg}"

# Load baseline hashes
try:
    with open(baseline_file, 'r') as f:
        baseline_hashes = json.load(f)
    print("✅ Loaded baseline hashes.")
except FileNotFoundError:
    print("❌ Baseline file not found. Run baseline_checker.py first.")
    sys.exit(1)

def calculate_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

import subprocess
import platform

def lock_file(file_path):
    if platform.system() == "Windows":
        lock_file_windows(file_path)
    else:
        lock_file_linux(file_path)

def lock_file_windows(file_path):
    try:
        subprocess.run(["icacls", file_path, "/inheritance:r"], check=True)
        subprocess.run(["icacls", file_path, "/deny", "Everyone:(F)"], check=True)
        print(f"🔒 Locked down: {file_path}")
    except Exception as e:
        print(f"⚠️ Error locking file {file_path}: {e}")

def lock_file_linux(file_path):
    try:
        subprocess.run(["chmod", "000", file_path], check=True)
        print(f"🔒 Locked down: {file_path}")
    except Exception as e:
        print(f"⚠️ Error locking file {file_path}: {e}")

class FileChangeHandler(FileSystemEventHandler):

    def on_modified(self, event):
        now = time.time()
        last_event_time = event_cooldown.get(event.src_path, 0)
        if now - last_event_time < COOLDOWN_SECONDS:
            return

        event_cooldown[event.src_path] = now

        if os.path.isfile(event.src_path):
            new_hash = calculate_hash(event.src_path)
            old_hash = baseline_hashes.get(event.src_path)

            if old_hash is None:
                print(format_event("MODIFIED", event.src_path, "NEW", "🆕", "Not in baseline"))
            elif new_hash != old_hash:
                print(format_event("MODIFIED", event.src_path, "ALERT", "⚠️", "Hash mismatch"))
                lock_file(event.src_path)
            else:
                print(format_event("MODIFIED", event.src_path, "OK", "✅", "Hash unchanged"))

    def on_created(self, event):
        if os.path.isfile(event.src_path):
            new_hash = calculate_hash(event.src_path)
            old_hash = baseline_hashes.get(event.src_path)

            if old_hash is None:
                print(format_event("CREATED", event.src_path, "NEW", "🆕", "Not in baseline"))
            elif new_hash != old_hash:
                print(format_event("CREATED", event.src_path, "ALERT", "⚠️", "Hash mismatch"))
                lock_file(event.src_path)
            else:
                print(format_event("CREATED", event.src_path, "OK", "✅", "Hash matches baseline"))

    def on_deleted(self, event):
        print(format_event("DELETED", event.src_path, "REMOVED", "🗑️", "File deleted"))

if __name__ == "__main__":
    path = input("Enter directory to monitor: ")
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    print(f"🚨 Monitoring changes in: {path}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("🛑 Monitoring stopped.")

    observer.join()
