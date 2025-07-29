import time
import os
import hashlib
import json
import sys
import subprocess
import platform
import yara

from yara_scanner import compile_rules, scan_file_with_yara

from event_logger import log_event


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
    def __init__(self, yara_rules):
        self.yara_rules = yara_rules

    def on_modified(self, event):
        now = time.time()
        last_event_time = event_cooldown.get(event.src_path, 0)
        if now - last_event_time < COOLDOWN_SECONDS:
            return

        event_cooldown[event.src_path] = now

        if os.path.isfile(event.src_path):
            new_hash = calculate_hash(event.src_path)

            if self.yara_rules:
                    matches = scan_file_with_yara(event.src_path, self.yara_rules)
                    if matches:
                        print(f"⚠️ YARA Match in {event.src_path} → Rule(s): {[m.rule for m in matches]}")
                        log_event("YARA", event.src_path, "ALERT", f"Matched rules: {[m.rule for m in matches]}")
                        lock_file(event.src_path)

            old_hash = baseline_hashes.get(event.src_path)

            if old_hash is None:
                print(format_event("MODIFIED", event.src_path, "NEW", "🆕", "Not in baseline"))
                log_event("MODIFIED", event.src_path, "NEW", "Not in baseline")
            elif new_hash != old_hash:
                print(format_event("MODIFIED", event.src_path, "ALERT", "⚠️", "Hash mismatch"))
                log_event("MODIFIED", event.src_path, "ALERT", "Hash mismatch")
                lock_file(event.src_path)
            else:
                print(format_event("MODIFIED", event.src_path, "OK", "✅", "Hash unchanged"))
                log_event("MODIFIED", event.src_path, "OK", "Hash unchanged")

    def on_created(self, event):
        if os.path.isfile(event.src_path):
            try:
                new_hash = calculate_hash(event.src_path)

                if self.yara_rules:
                    matches = scan_file_with_yara(event.src_path, self.yara_rules)
                    if matches:
                        print(f"⚠️ YARA Match in {event.src_path} → Rule(s): {[m.rule for m in matches]}")
                        log_event("YARA", event.src_path, "ALERT", f"Matched rules: {[m.rule for m in matches]}")
                        lock_file(event.src_path)

            except PermissionError:
                print(format_event("CREATED", event.src_path, "SKIPPED", "🔒", "Permission denied"))
                log_event("CREATED", event.src_path, "SKIPPED", "Permission denied")
                lock_file(event.src_path)
                return

            old_hash = baseline_hashes.get(event.src_path)

            if old_hash is None:
                print(format_event("CREATED", event.src_path, "NEW", "🆕", "Not in baseline"))
                log_event("CREATED", event.src_path, "NEW", "Not in baseline")
            elif new_hash != old_hash:
                print(format_event("CREATED", event.src_path, "ALERT", "⚠️", "Hash mismatch"))
                log_event("CREATED", event.src_path, "ALERT", "Hash mismatch")
                lock_file(event.src_path)
            else:
                print(format_event("CREATED", event.src_path, "OK", "✅", "Hash matches baseline"))
                log_event("CREATED", event.src_path, "OK", "Hash matches baseline")

    def on_deleted(self, event):
        print(format_event("DELETED", event.src_path, "REMOVED", "🗑️", "File deleted"))
        log_event("DELETED", event.src_path, "REMOVED", "File deleted")


if __name__ == "__main__":
    path = input("Enter directory to monitor: ")

    rules_dir = "yara_rules"
    yara_rules = compile_rules(rules_dir)
    if yara_rules:
        print("✅ YARA rules loaded.")
    else:
        print("⚠️ No YARA rules found.")

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
