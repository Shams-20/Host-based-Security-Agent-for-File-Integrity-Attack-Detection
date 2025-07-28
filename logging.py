import json
import datetime

def log_event(event_type, file_path, status, message):
    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "file_path": file_path,
        "status": status,
        "message": message
    }
    with open("event_log.jsonl", "a") as log_file:
        json.dump(log_data, log_file)
        log_file.write("\n")
