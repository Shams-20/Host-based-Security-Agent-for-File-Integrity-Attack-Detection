import time
import os
import hashlib
import json
import sys
import subprocess
import platform
import yara

from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Custom modules (assuming these exist)
from yara_scanner import compile_rules, scan_file_with_yara
from event_logger import log_event

# Constants
COOLDOWN_SECONDS = 2
event_cooldown = {}
baseline_file = "hashes.json"
locked_files = set()  # 🔒 Tracks already locked files so we ignore them after

# Load baseline hashes
try:
    with open(baseline_file, 'r') as f:
        baseline_hashes = json.load(f)
    print("✅ Loaded baseline hashes.")
except FileNotFoundError:
    print("❌ Baseline file not found. Run baseline_checker.py first.")
    sys.exit(1)


def format_event(event_type, filepath, status, emoji, msg):
    name = Path(filepath).name
    return f"[ {event_type:^9} ] {name:<25} → {status:<7} {emoji} {msg}"


def calculate_hash(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
    except PermissionError:
        print(f"❌ Permission denied while hashing: {filepath}")
        return None
    return hasher.hexdigest()

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
    if not os.path.exists(file_path):
        print(f"⚠️ File vanished before it could be locked: {file_path}")
        return
    try:
        subprocess.run(["chmod", "000", file_path], check=True)
        print(f"🔒 Locked down: {file_path}")
    except Exception as e:
        print(f"⚠️ Error locking file {file_path}: {e}")


def process_file_event(file_path, event_type, yara_rules, baseline_hashes):
    if not os.path.isfile(file_path):
        return
    if file_path in locked_files:
        return

    try:
        new_hash = calculate_hash(file_path)
        if new_hash is None:
            return

        if yara_rules:
            matches = scan_file_with_yara(file_path, yara_rules)
            if matches:
                print(f"⚠️ YARA Match in {file_path} → Rule(s): {[m.rule for m in matches]}")
                log_event("YARA", file_path, "ALERT", f"Matched rules: {[m.rule for m in matches]}")
                lock_file(file_path)
                locked_files.add(file_path)
                print(f"🔍 Currently locked files: {locked_files}")  # Tells us what files are locked
                return  # Skip further processing if locked
                
        old_hash = baseline_hashes.get(file_path)

        if old_hash is None:
            print(format_event(event_type, file_path, "NEW", "🆕", "Not in baseline"))
            log_event(event_type, file_path, "NEW", "Not in baseline")
        elif new_hash != old_hash:
            print(format_event(event_type, file_path, "ALERT", "⚠️", "Hash mismatch"))
            log_event(event_type, file_path, "ALERT", "Hash mismatch")
            # No locking unless YARA matches!
        else:
            print(format_event(event_type, file_path, "OK", "✅", "Hash unchanged"))
            log_event(event_type, file_path, "OK", "Hash unchanged")

    except PermissionError:
        print(format_event(event_type, file_path, "SKIPPED", "🔒", "Permission denied"))
        log_event(event_type, file_path, "SKIPPED", "Permission denied")


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, yara_rules):
        self.yara_rules = yara_rules

    def on_modified(self, event):
        now = time.time()
        last_event_time = event_cooldown.get(event.src_path, 0)
        if now - last_event_time < COOLDOWN_SECONDS:
            return
        event_cooldown[event.src_path] = now

        # Handle GNOME weird temp file shenanigans
        if os.path.basename(event.src_path).startswith('.goutputstream'):
            time.sleep(0.5)
            parent_dir = os.path.dirname(event.src_path)
            for f in os.listdir(parent_dir):
                full_path = os.path.join(parent_dir, f)
                if not f.startswith('.goutputstream') and os.path.isfile(full_path):
                    if abs(os.path.getmtime(full_path) - time.time()) < 2:
                        process_file_event(full_path, "MODIFIED", self.yara_rules, baseline_hashes)
            return

        process_file_event(event.src_path, "MODIFIED", self.yara_rules, baseline_hashes)

    def on_created(self, event):
        # Handle GNOME file save behavior
        if os.path.basename(event.src_path).startswith('.goutputstream'):
            time.sleep(0.5)
            parent_dir = os.path.dirname(event.src_path)
            for f in os.listdir(parent_dir):
                full_path = os.path.join(parent_dir, f)
                if not f.startswith('.goutputstream') and os.path.isfile(full_path):
                    if abs(os.path.getmtime(full_path) - time.time()) < 2:
                        process_file_event(full_path, "MODIFIED", self.yara_rules, baseline_hashes)
            return

        process_file_event(event.src_path, "CREATED", self.yara_rules, baseline_hashes)

    def on_deleted(self, event):
        print(format_event("DELETED", event.src_path, "REMOVED", "🗑️", "File deleted"))
        log_event("DELETED", event.src_path, "REMOVED", "File deleted")


if __name__ == "__main__":
    path = input("Enter directory to monitor: ").strip()

    if not os.path.isdir(path):
        print("❌ Provided path is not a valid directory.")
        sys.exit(1)

    try:
        yara_rules = compile_rules("yara_rules")
        print("✅ YARA rules loaded.")
    except Exception as e:
        print(f"🛑 Failed to load YARA rules: {e}")
        sys.exit(1)

    event_handler = FileChangeHandler(yara_rules)
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

