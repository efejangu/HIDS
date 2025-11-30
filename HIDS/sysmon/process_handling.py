
from ..log_analysis.alert import Alert
from ..log_analysis.alert_manager import AlertManager
from ..threat_detector.threat_detector import is_file_malicious
from ..util import hash_file
from datetime import datetime
import psutil
from time import sleep
from queue import Queue
from threading import Event, Thread



class ProcessHandling:
    """
    Handles process monitoring and examination for the HIDS system.
    """

    def __init__(self, alert_manager: AlertManager):
        """
        Initializes the ProcessHandling class.

        Args:
            alert_manager (AlertManager): The alert manager instance to use for reporting alerts.
        """
        self.alert_manager = alert_manager

    def load_new_processes(self, proc_queue: Queue, stop_event: Event, load_interval: int):
        """
        Loads new processes into the process queue.

        Args:
            proc_queue (Queue): The queue to add new processes to.
            stop_event (Event): An event to signal the thread to stop.
            load_interval (int): The interval (in seconds) to wait between loading new processes.

        Raises:
            ValueError: If load_interval is not a non-negative integer.
        """
        if not isinstance(load_interval, int) or load_interval < 0:
            raise ValueError("load_interval must be a non-negative integer")

        old_procs = set(psutil.pids())
        termination_signal = stop_event.is_set()
        proc_queue.put(old_procs) #The first set of PIDs that will be passed to the consumer function

        while not termination_signal:
            new_procs = set(psutil.pids())
            recently_added_procs = new_procs - old_procs #ammount of new processes added to new_procs
            if len(recently_added_procs) > 0:
                for procs in recently_added_procs:
                    proc_queue.put(procs)

                old_procs = new_procs
                sleep(load_interval)
        else:
            print("load_new_processes")

    def get_process(self, pid):
        """
        Gets a process by its PID.

        Args:
            pid (int): The PID of the process to get.

        Returns:
            psutil.Process: The process object, or None if the process does not exist or could not be obtained.
        """
        try:
            existing_proc = psutil.pid_exists(pid)
            if existing_proc:
                return psutil.Process(pid)
        except psutil.Error as e:
            print("unfortunately process could not be obtained")

    def examine_process(self, proc_queue: Queue, stop_event: Event):
        """
        Examines processes from the process queue for malicious activity.

        Args:
            proc_queue (Queue): The queue containing PIDs of processes to examine.
            stop_event (Event): An event to signal the thread to stop.
        """
        termination_signal = stop_event.is_set()
        while not termination_signal:
            if proc_queue.empty():
                continue

            pids_from_queue = proc_queue.get()
            potential_processes = list(map(self.get_process, pids_from_queue))
            
            active_processes = [
                proc for proc in potential_processes
                if proc is not None and proc.is_running()
            ]
                #TODO convert file_hash to a dictionary, and include process_id
            file_hashes = [hash_file(proc.exe()) for proc in active_processes]
            for proc, proc_hash in zip(active_processes, file_hashes):
                try:
                    if is_file_malicious(proc_hash):
                        alert = Alert(
                            timestamp=datetime.now(datetime.timezone.utc),
                            alertLevel="ALERT III",
                            message=f"A malicious process with PID {proc.pid} has been found in {proc.exe()}",
                            detected_by="sysmon_proc_manager",
                        )
                        self.alert_manager.add_alert(alert)
                    
                except psutil.NoSuchProcess as e:
                    print(f"Process {proc.pid} does not exist: {e}")
                except psutil.AccessDenied as e:
                    print(f"Access Denied for process {proc.pid}: {e}")
        else:
            print("examine_process_function ended")