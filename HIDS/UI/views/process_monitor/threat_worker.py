"""
Threat Detection Worker Module - Background threat detection using ProcessHandling

Handles:
- Background thread for threat analysis
- Queue-based PID processing
- Integration with HIDS threat detection
- Thread-safe UI callbacks
"""
import psutil
from pathlib import Path
from queue import Queue
from threading import Event, Thread
from typing import Optional, Callable

from HIDS.sysmon.process_handling import ProcessHandling
from HIDS.util import hash_file
from HIDS.threat_detector.threat_detector import is_file_malicious

from .cache import ProcessCache


class ThreatDetectionWorker:
    """Background worker for threat detection using ProcessHandling"""
    
    def __init__(self, process_handler: ProcessHandling, cache: ProcessCache, 
                 update_callback: Callable):
        """
        Initialize the threat detection worker
        
        Args:
            process_handler: ProcessHandling instance for threat analysis
            cache: ProcessCache for storing results
            update_callback: Function to call when threat status changes
        """
        self.process_handler = process_handler
        self.cache = cache
        self.update_callback = update_callback
        
        # Queues and events for thread management
        self.pid_queue = Queue()
        self.stop_event = Event()
        
        # Worker thread
        self.worker_thread: Optional[Thread] = None
        self.is_running = False
    
    def start(self) -> None:
        """Start the background threat detection worker"""
        if self.is_running:
            return
        
        self.stop_event.clear()
        self.worker_thread = Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        self.is_running = True
    
    def stop(self) -> None:
        """Stop the background threat detection worker"""
        if not self.is_running:
            return
        
        self.stop_event.set()
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
        self.is_running = False
    
    def queue_process(self, pid: int) -> None:
        """Queue a process for threat analysis"""
        if not self.pid_queue.full():
            self.pid_queue.put(pid)
    
    def _worker_loop(self) -> None:
        """Main worker loop - runs in background thread"""
        while not self.stop_event.is_set():
            try:
                # Get PIDs from queue with timeout
                if not self.pid_queue.empty():
                    pid = self.pid_queue.get(timeout=1.0)
                    
                    # Check if already analyzed recently
                    cached_status = self.cache.get_threat_status(pid)
                    if cached_status is not None:
                        continue
                    
                    # Mark as scanning
                    self.update_callback(pid, 'scanning', None)
                    
                    # Perform threat analysis
                    try:
                        proc = self.process_handler.get_process(pid)
                        if proc and proc.is_running():
                            exe_path = proc.exe()
                            if exe_path and Path(exe_path).exists():
                                # Get or compute hash
                                file_hash = self.cache.get_hash(exe_path)
                                if file_hash is None:
                                    file_hash = hash_file(exe_path)
                                    self.cache.set_hash(exe_path, file_hash)
                                
                                # Check if malicious
                                if is_file_malicious(file_hash):
                                    status = 'malicious'
                                    risk_score = 100
                                else:
                                    status = 'safe'
                                    risk_score = 10
                                
                                # Cache and update
                                self.cache.set_threat_status(pid, status)
                                self.update_callback(pid, status, risk_score)
                            else:
                                # No executable, mark as safe but low confidence
                                self.cache.set_threat_status(pid, 'safe')
                                self.update_callback(pid, 'safe', None)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process no longer exists or inaccessible
                        pass
                    except Exception:
                        # Error during analysis
                        pass
                    
                    self.pid_queue.task_done()
                else:
                    # No work, sleep briefly
                    self.stop_event.wait(0.5)
                    
            except Exception:
                # Catch any unexpected errors to keep worker alive
                continue