import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"[MODIFIED] {event.src_path}")

    def on_created(self, event):
        print(f"[CREATED] {event.src_path}")

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
