from watchdog.observers import Observer
import time
import re  # Import the re module
from HIDS.sysmon.file_watch import FileCreationHandler
import hashlib
from HIDS.database.database import Database
import os
import uuid
from HIDS.log_analysis.alert import logger
from HIDS.util import hash_file

#HELPER
# Regex to find the filename part of a path
_FILENAME_RE = re.compile(r'[^/\\:]+$')

def get_filename(path: str) -> str:
    """
    Return the file name part of *path*.

    Raises
    ------
    NoFilenameError
        If the path ends with a directory separator and therefore
        contains no file name.
    """
    match = _FILENAME_RE.search(path)
    if not match:
        # Raise a clear, descriptive error as per the docstring
        raise NoFilenameError(
            f"Path '{path}' does not contain a file name; "
            "it appears to end with a directory separator."
        )

    return match.group(0)

# Placeholder for NoFilenameError, as it's raised by get_filename
class NoFilenameError(Exception):
    pass


class FileMonitoringSystem:

    def __init__(self, db, handler: FileCreationHandler):
        self.db = db
        self.observer = Observer()
        self.handler = handler
        self.watch_list = []
        self.observer.start()


    def check_integrity(self,file_name):
        try:
            query = self.db.get_cursor()
            query.execute("SELECT * FROM file_monitoring WHERE name = ?", (file_name,))
            result = query.fetchall()
            if len(result) > 0 and os.path.isfile(result[3]):
                new_hash = hash_file(result[3])
                baseline = result[2]
                confirmation_bool = baseline == new_hash
                return confirmation_bool
        except FileNotFoundError:
            print("this file does not exist in the database.")


    def monitor_file(self, file_path):
        try:
            # Schedule the file/directory to be monitored
            # Note: recursive=True is assumed; adjust if only specific files are needed.
            schedule_entry = self.observer.schedule(
                self.handler,
                path=file_path,
                recursive=True 
            )
            
            # Store information about the monitored path
            mon_dict = {
                "obj_path": file_path,
                "schedule_entry": schedule_entry # Store the schedule entry for potential future use (e.g., unscheduling)
            }
            self.watch_list.append(mon_dict)

            # If the observer is not running, start it.
            # The observer instance should only be started once.
            if not self.observer.is_running():
                self.observer.start()

            # Verify if the file_path exists in the database and add if not
            # get_filename is now fixed to raise NoFilenameError if path is invalid
            valid_file_name = get_filename(file_path) 
            
            query = self.db.get_cursor()
            query.execute("SELECT file_path FROM file_monitoring WHERE file_path = ? LIMIT 1", (file_path,))
            result = query.fetchall()
            
            if len(result) == 0:
                # File not in database, add it
                id = str(uuid.uuid4())
                # Use corrected create_baseline call with filename and path
                baseline = hash_file(file_path)
                self.db.write(
                    "file_monitoring",
                    {
                        "ID": id,
                        "file_name": valid_file_name,
                        "hash": baseline,
                        "file_path": file_path
                    }
                )
            # If file is already in DB, we don't need to do anything here for monitoring setup.
            # The observer is already started and will monitor changes.

        except NoFilenameError as e: # Catch the specific error from get_filename
            print(f"[!] Error processing path '{file_path}': {e}")
        except ValueError:
            # This might still be relevant if schedule raises it for invalid paths
            print("[!] Directory passed instead of file ") 
        except FileNotFoundError:
            print(f"[!] The specified file or directory in {file_path} does not exist ")
        except Exception as e: # Catch any other unexpected errors
            print(f"[!] An unexpected error occurred while monitoring '{file_path}': {e}")


    def monitor_dir(self, dir_path):
        try:
            # Schedule the directory to be monitored
            # Assuming recursive=True is desired for directories
            schedule_entry = self.observer.schedule(
                self.handler, # Using the same handler, assuming it can handle directory events
                path=dir_path,
                recursive=True 
            )
            
            # Store information about the monitored directory
            mon_dict = {
                "obj_path": dir_path,
                "schedule_entry": schedule_entry 
            }
            self.watch_list.append(mon_dict)

            # If the observer is not running, start it.
            if not self.observer.is_running():
                self.observer.start()

            # Optional: Add directory to database if needed, similar to file monitoring
            # For now, just setting up monitoring.

        except ValueError:
            print("[!] Invalid path provided for directory monitoring.") 
        except FileNotFoundError:
            print(f"[!] The specified directory '{dir_path}' does not exist.")
        except Exception as e: # Catch any other unexpected errors
            print(f"[!] An unexpected error occurred while monitoring directory '{dir_path}': {e}")


    def stop_monitoring(self):
        """
        Stops the observer and joins its thread.
        """
        if self.observer.is_running():
            self.observer.stop()
            self.observer.join()
            print("[+] File monitoring stopped.")
        else:
            print("[!] File observer is not running.")

    def all_file_status(self) -> str:
        """
        Checks the status of all monitored files and returns a formatted report.

        Returns:
            A formatted string detailing the status of each monitored file.
        """
        try:
            query = self.db.get_cursor()
            # Fetch all monitored files
            query.execute("SELECT name, file_path, baseline FROM file_monitoring")
            results = query.fetchall()

            if not results:
                return "No files are currently being monitored."

            status_report = ["--- File Status Report ---"]
            for row in results:
                file_name, file_path, _ = row # We don't need baseline here, file_status will recalculate
                status = self.file_status(file_name)
                status_report.append(status)
            
            status_report.append("--------------------------")
            return "\n".join(status_report)

        except Exception as e:
            return f"Error generating file status report: {e}"
    
    def file_status(self, file_name: str) -> str:
        """
        Checks the status of a monitored file.

        Args:
            file_name: The name of the file to check.

        Returns:
            A string indicating the status of the file (e.g., "Unmodified", "Modified", "Not Monitored", "File Not Found").
        """
        try:
            query = self.db.get_cursor()
            # Fetch file_path and baseline hash for the given file_name
            query.execute("SELECT file_path, baseline FROM file_monitoring WHERE name = ?", (file_name,))
            result = query.fetchone() # Use fetchone as we expect only one row for a given file name

            if not result:
                return f"File '{file_name}': Not Monitored"

            file_path, baseline_hash = result

            # Check if the file actually exists at the given path
            if not os.path.isfile(file_path):
                return f"File '{file_name}': File Not Found at '{file_path}'"

            # Calculate the new hash
            current_hash = hash_file(file_path)

            if baseline_hash == current_hash:
                return f"File '{file_name}': Unmodified"
            else:
                return f"File '{file_name}': Modified"

        except Exception as e:
            return f"File '{file_name}': Error checking status - {e}"