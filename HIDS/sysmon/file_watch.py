from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import time

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, monitored_extensions=None, callback=None):
        super().__init__()
        self.monitored_extensions = monitored_extensions if monitored_extensions else []
        self.callback = callback

    def _process_event(self, event_type, event):
        if self.callback:
            self.callback(event_type, event.src_path, event.is_directory)

    def on_created(self, event):
        if event.is_directory:
            self._process_event("created", event)
        elif not event.is_directory:
            file_extension = os.path.splitext(event.src_path)[1]
            if not self.monitored_extensions or file_extension in self.monitored_extensions:
                self._process_event("created", event)

    def on_modified(self, event):
        if event.is_directory:
            self._process_event("modified", event)
        elif not event.is_directory:
            self._process_event("modified", event)

    def on_deleted(self, event):
        if event.is_directory:
            self._process_event("deleted", event)
        elif not event.is_directory:
            self._process_event("deleted", event)

class FileWatcher:
    def __init__(self, monitored_extensions=None, callback=None):
        self.observer = Observer()
        self.event_handler = FileEventHandler(monitored_extensions, callback)
        self.monitored_directories = {} # Stores {directory_path: watchdog_schedule_object}

    def start_monitoring(self, directory_to_watch: str, recursive: bool = True):
        if directory_to_watch in self.monitored_directories:
            print(f"[!] Already monitoring {directory_to_watch}")
            return

        if not os.path.isdir(directory_to_watch):
            print(f"[!] Directory not found: {directory_to_watch}")
            return

        schedule_object = self.observer.schedule(self.event_handler, directory_to_watch, recursive=recursive)
        self.monitored_directories[directory_to_watch] = schedule_object
        
        if not self.observer.is_alive():
            self.observer.start()
        print(f"[+] Started monitoring: {directory_to_watch}")

    def stop_monitoring(self, directory_to_stop: str):
        if directory_to_stop not in self.monitored_directories:
            print(f"[!] Not monitoring {directory_to_stop}")
            return

        schedule_object = self.monitored_directories.pop(directory_to_stop)
        self.observer.unschedule(schedule_object)
        print(f"[+] Stopped monitoring: {directory_to_stop}")

        if not self.monitored_directories and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            print("[+] All file monitoring stopped.")

    def list_monitored_directories(self):
        return list(self.monitored_directories.keys())

    def stop_all_monitoring(self):
        self.observer.stop()
        self.observer.join()
        self.monitored_directories.clear()
        print("[+] All file monitoring stopped.")

if __name__ == "__main__":
    # Example usage:
    def file_event_callback(event_type, path, is_directory):
        print(f"Event: {event_type}, Path: {path}, Is Directory: {is_directory}")

    watcher = FileWatcher(callback=file_event_callback)
    test_dir = "test_monitor_dir"
    os.makedirs(test_dir, exist_ok=True)

    watcher.start_monitoring(test_dir)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop_all_monitoring()
