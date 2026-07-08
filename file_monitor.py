import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIRECTORY = "./secure_folder"
LOG_FILE = "file_audit_log.txt"

SENSITIVE_KEYWORDS = ["secret", "password", "financial", "confidential", "salary"]

BANNED_EXTENSIONS = [".exe", ".bat", ".sh", ".cmd"]

def calculate_sha256(file_path):
    if os.path.isdir(file_path):
        return None

    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return "N/A"

def process_security_event(event_type, file_path, file_hash="N/A"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    file_name = os.path.basename(file_path).lower()

    is_sensitive = any(keyword in file_name for keyword in SENSITIVE_KEYWORDS)
    classification = "SENSITIVE" if is_sensitive else "NORMAL"

    is_alert = False
    alert_reason = ""

    if any(file_name.endswith(ext) for ext in BANNED_EXTENSIONS):
        is_alert = True
        alert_reason = "UNAUTHORIZED FILE TYPE DETECTED"

    elif is_sensitive and event_type in ["FILE_CREATED", "FILE_MODIFIED"]:
        is_alert = True
        alert_reason = "UNAUTHORIZED SENSITIVE FILE INTERACTION"

    log_entry = f"[{timestamp}] EVENT: {event_type} | CLASS: {classification} | PATH: {file_path} | HASH: {file_hash}"

    if is_alert:
        final_output = f"🚨 [ALERT: {alert_reason}] 🚨\n{log_entry}\n"
    else:
        final_output = f"{log_entry}\n"

    print(final_output.strip())

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(final_output)

class SecurityMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.2)
            file_hash = calculate_sha256(event.src_path)
            process_security_event("FILE_CREATED", event.src_path, file_hash)

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)
            process_security_event("FILE_MODIFIED", event.src_path, file_hash)

    def on_deleted(self, event):
        if not event.is_directory:
            process_security_event("FILE_DELETED", event.src_path, "DELETED")

if __name__ == "__main__":
    if not os.path.exists(WATCH_DIRECTORY):
        os.makedirs(WATCH_DIRECTORY)

    event_handler = SecurityMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIRECTORY, recursive=False)

    print("=" * 60)
    print("🕵️‍♂️ SECURE FILE TRANSFER MONITORING SYSTEM INITIALIZED")
    print(f"📍 Target Path: {WATCH_DIRECTORY}")
    print("=" * 60)
    print("System active... Monitoring traffic events in real-time.")
    print("-> Press Ctrl+C (or stop the kernel) to stop execution and close the audit.")
    print("-" * 60)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Compiling final log reports...")
        observer.stop()

    observer.join()
    print("👋 System safely offline. See 'file_audit_log.txt' for data.")