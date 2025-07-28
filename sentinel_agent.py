import time
import os
import hashlib
import json
import sys

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

baseline_file = "hashes.json"

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

class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"[MODIFIED] {event.src_path}")
        if os.path.isfile(event.src_path):
            try:
                new_hash = calculate_hash(event.src_path)
                old_hash = baseline_hashes.get(event.src_path)
                
                if old_hash is None:
                    print(f"🆕 [WARNING] New file not in baseline: {event.src_path}")
                elif new_hash != old_hash:
                    print(f"⚠️ [ALERT] Hash mismatch detected! Possible tampering: {event.src_path}")
                else:
                    print(f"✅ [OK] File modified but hash is unchanged: {event.src_path}")
            except Exception as e:
                print(f"❌ Error hashing file: {event.src_path} — {e}")

    def on_created(self, event):
        print(f"[CREATED] {event.src_path}")
        if os.path.isfile(event.src_path):
            try:
                new_hash = calculate_hash(event.src_path)
                old_hash = baseline_hashes.get(event.src_path)
                
                if old_hash is None:
                    print(f"🆕 [WARNING] New file not in baseline: {event.src_path}")
                elif new_hash != old_hash:
                    print(f"⚠️ [ALERT] Hash mismatch detected! Possible tampering: {event.src_path}")
                else:
                    print(f"✅ [OK] File created and hash matches baseline: {event.src_path}")
            except Exception as e:
                print(f"❌ Error hashing file: {event.src_path} — {e}")

    def on_deleted(self, event):
        print(f"[DELETED] {event.src_path}")

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
