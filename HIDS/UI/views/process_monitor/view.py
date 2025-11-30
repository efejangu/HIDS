"""
Process Monitor View Module - Main UI orchestration

Handles:
- Main view composition and layout
- Process refresh logic
- Event handlers for UI interactions
- Integration with background threat worker
- Risk score calculation
- Audit logging
"""
import json
import psutil
from datetime import datetime
from typing import Optional, List, Dict, Any, Set

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Label
from textual import on, work
from textual.timer import Timer
from textual.widgets import DataTable, Button, Input, Checkbox

from HIDS.sysmon.process_handling import ProcessHandling
from HIDS.log_analysis.alert_manager import AlertManager

from .cache import ProcessCache
from .threat_worker import ThreatDetectionWorker
from .components import ProcessSearchPanel, ProcessControlPanel, ProcessDetailsPanel
from .process_table import ProcessMonitorTable


class ProcessMonitorView(Vertical):
    """
    Process Monitor view with optimized performance and background threat detection
    
    Performance optimizations:
    - Caching layer for static data (hashes, modules, threat status)
    - Lazy loading for expensive operations 
    - Differential updates (only changed values)
    - Background threading for threat detection
    - Integration with ProcessHandling for deep analysis
    """
    
    process_handler: Optional[ProcessHandling] = None
    alert_manager: Optional[AlertManager] = None
    refresh_timer: Optional[Timer] = None
    refresh_interval: int = 10  # Increased to 10 seconds to reduce layout pressure
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.alert_manager = AlertManager()
        self.process_handler = ProcessHandling(self.alert_manager)
        self.selected_processes: set = set()
        self.audit_log: List[Dict[str, Any]] = []
        
        # Performance optimization: caching layer
        self.cache = ProcessCache(ttl_seconds=300)  # 5-minute cache TTL
        
        # Track previous state for differential updates
        self.previous_pids: Set[int] = set()
        
        # Background threat detection worker
        self.threat_worker: Optional[ThreatDetectionWorker] = None
    
    def on_mount(self) -> None:
        """Called when the widget is mounted"""
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        table.clear()
        
        # Start background threat detection worker
        self.threat_worker = ThreatDetectionWorker(
            self.process_handler,
            self.cache,
            self._update_threat_status
        )
        self.threat_worker.start()
        
        # Start auto-refresh
        self.start_auto_refresh()
        
        # Load initial processes
        self.refresh_processes()
    
    def compose(self) -> ComposeResult:
        """Compose the process monitor view"""
        yield ProcessSearchPanel(id="process-search-panel")
        yield ProcessControlPanel(id="process-control-panel")
        
        with Horizontal(id="process-monitor-content"):
            with Vertical(classes="main-panel"):
                yield Label("[bold]System Processes[/bold]", classes="section-title")
                yield ProcessMonitorTable(id="process-monitor-table")
            
            yield ProcessDetailsPanel(id="process-details-panel")
    
    def start_auto_refresh(self) -> None:
        """Start the auto-refresh timer"""
        if self.refresh_timer:
            self.refresh_timer.stop()
        
        self.refresh_timer = self.set_interval(
            self.refresh_interval,
            self.refresh_processes
        )
    
    def stop_auto_refresh(self) -> None:
        """Stop the auto-refresh timer"""
        if self.refresh_timer:
            self.refresh_timer.stop()
            self.refresh_timer = None
    
    @work(exclusive=True, thread=True)
    async def refresh_processes(self) -> None:
        """
        Refresh the process list - optimized for performance
        
        Optimizations:
        - Exclusive worker prevents concurrent refresh operations
        - Only fetches essential process data
        - No expensive operations (hashing, modules, connections)
        - Differential updates (only changed values)
        - Tracks added/removed processes efficiently
        - Queues new processes for background threat analysis
        """
        try:
            # Fetch essential process data only
            processes = []
            current_pids = set()
            
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 
                                           'memory_info', 'username', 'status', 
                                           'exe', 'cmdline', 'create_time', 'num_threads']):
                try:
                    process_info = proc.info
                    pid = process_info['pid']
                    current_pids.add(pid)
                    
                    # Calculate memory in MB
                    if process_info.get('memory_info'):
                        process_info['memory_mb'] = process_info['memory_info'].rss / 1024 / 1024
                    else:
                        process_info['memory_mb'] = 0
                    
                    # Format start time
                    if process_info.get('create_time'):
                        process_info['start_time'] = datetime.fromtimestamp(
                            process_info['create_time']
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        process_info['start_time'] = 'N/A'
                    
                    # Calculate initial risk score (lightweight)
                    process_info['risk_score'] = self.calculate_risk_score(process_info)
                    
                    # Check cached threat status
                    cached_status = self.cache.get_threat_status(pid)
                    if cached_status:
                        process_info['status'] = cached_status
                        if cached_status == 'malicious':
                            process_info['risk_score'] = 100
                    else:
                        process_info['status'] = 'running'
                    
                    # Format command line
                    if isinstance(process_info.get('cmdline'), list):
                        process_info['cmdline'] = ' '.join(process_info['cmdline'])
                    
                    processes.append(process_info)
                    
                    # Queue new processes for background threat analysis
                    if pid not in self.previous_pids:
                        if self.threat_worker:
                            self.threat_worker.queue_process(pid)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Schedule UI update on main thread after refresh completes
            self.call_after_refresh(self._update_process_table, processes, current_pids)
            
        except Exception as e:
            self.call_from_thread(self.notify, f"Error refreshing processes: {str(e)}", severity="error")
    
    def _update_process_table(self, processes: List[Dict], current_pids: Set[int]) -> None:
        """Update the process table on the main thread - thread-safe"""
        try:
            table = self.query_one("#process-monitor-table", ProcessMonitorTable)
            
            for process_info in processes:
                pid = process_info['pid']
                row_key = f"proc_{pid}"
                
                if row_key in table.rows:
                    # Existing process - differential update
                    table.update_process(process_info)
                else:
                    # New process - add to table
                    table.add_process(process_info)
            
            # Remove processes that no longer exist
            removed_pids = self.previous_pids - current_pids
            for pid in removed_pids:
                table.remove_process(pid)
            
            # Update previous PIDs for next differential
            self.previous_pids = current_pids
            
            # Sort by current sort column
            table.sort_by_column(table.sort_column, table.sort_reverse)
            
        except Exception as e:
            self.notify(f"Error updating process table: {str(e)}", severity="error")
    
    def _update_threat_status(self, pid: int, status: str, risk_score: Optional[int]) -> None:
        """
        Callback from background worker to update threat status
        Thread-safe update to UI
        """
        try:
            table = self.query_one("#process-monitor-table", ProcessMonitorTable)
            row_key = f"proc_{pid}"
            
            if row_key in table.process_data:
                process_info = table.process_data[row_key].copy()
                process_info['status'] = status
                
                if risk_score is not None:
                    process_info['risk_score'] = risk_score
                
                # Update table (thread-safe via Textual's message system)
                self.call_from_thread(table.update_process, process_info)
        except Exception:
            pass
    
    def calculate_risk_score(self, process_info: Dict[str, Any]) -> int:
        """
        Calculate a risk score for a process
        Lightweight calculation - no expensive operations
        """
        score = 0
        
        # Check for suspicious process names
        suspicious_names = ['keylogger', 'trojan', 'backdoor', 'rootkit', 'miner']
        name = process_info.get('name', '').lower()
        if any(suspicious in name for suspicious in suspicious_names):
            score += 50
        
        # Check for high CPU usage
        cpu_percent = process_info.get('cpu_percent', 0)
        if cpu_percent > 80:
            score += 20
        
        # Check for high memory usage
        memory_mb = process_info.get('memory_mb', 0)
        if memory_mb > 1024:  # 1GB
            score += 15
        
        # Check for suspicious user (root/admin processes are higher risk)
        username = process_info.get('username', '').lower()
        if username in ['root', 'administrator', 'system']:
            score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def log_audit_action(self, action: str, details: str) -> None:
        """Log user actions for audit"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'user': 'current_user'
        }
        self.audit_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    @on(Button.Pressed, "#refresh-btn")
    def handle_refresh(self) -> None:
        """Handle manual refresh"""
        self.log_audit_action("manual_refresh", "User manually refreshed process list")
        self.notify("Refreshing process list...", severity="information")
        self.refresh_processes()
    
    @on(Button.Pressed, "#kill-process-btn")
    def handle_kill_process(self) -> None:
        """Handle kill single process"""
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        
        if table.cursor_coordinate:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            try:
                pid = int(row_key.split('_')[1])
                process_info = table.process_data.get(row_key, {})
                process_name = process_info.get('name', 'Unknown')
                
                # Direct kill without dialog for simplicity
                self._kill_process(pid, process_name)
                
            except Exception as e:
                self.notify(f"Error killing process: {str(e)}", severity="error")
    
    @on(Button.Pressed, "#kill-selected-btn")
    def handle_kill_selected(self) -> None:
        """Handle batch kill of selected processes"""
        self.handle_kill_process()
    
    def _kill_process(self, pid: int, process_name: str) -> None:
        """Kill a process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            
            self.log_audit_action("kill_process", f"Killed process {pid} ({process_name})")
            
            table = self.query_one("#process-monitor-table", ProcessMonitorTable)
            table.remove_process(pid)
            
            self.notify(f"Process {pid} terminated", severity="warning")
            
        except psutil.NoSuchProcess:
            self.notify(f"Process {pid} no longer exists", severity="error")
        except psutil.AccessDenied:
            self.notify(f"Access denied: Cannot terminate process {pid}", severity="error")
            self.log_audit_action("kill_process_denied", f"Access denied killing process {pid}")
        except Exception as e:
            self.notify(f"Error terminating process: {str(e)}", severity="error")
    
    @on(Button.Pressed, "#view-details-btn")
    def handle_view_details(self) -> None:
        """Handle view process details - lazy loads expensive data"""
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        
        if table.cursor_coordinate:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            process_info = table.process_data.get(row_key, {})
            
            if process_info:
                details_panel = self.query_one("#process-details-panel", ProcessDetailsPanel)
                # Pass cache for lazy loading
                details_panel.update_details(process_info, self.cache)
                self.log_audit_action("view_details", f"Viewed details for process {process_info.get('pid')}")
    
    @on(Button.Pressed, "#export-btn")
    def handle_export(self) -> None:
        """Handle export snapshot"""
        try:
            table = self.query_one("#process-monitor-table", ProcessMonitorTable)
            
            snapshot = {
                'timestamp': datetime.now().isoformat(),
                'processes': list(table.process_data.values()),
                'audit_log': self.audit_log[-100:]
            }
            
            filename = f"process_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(snapshot, f, indent=2, default=str)
            
            self.log_audit_action("export_snapshot", f"Exported process snapshot to {filename}")
            self.notify(f"Snapshot exported to {filename}", severity="information")
            
        except Exception as e:
            self.notify(f"Error exporting snapshot: {str(e)}", severity="error")
    
    @on(Button.Pressed, "#search-btn")
    def handle_search(self) -> None:
        """Handle search"""
        search_input = self.query_one("#process-search-input", Input)
        regex_checkbox = self.query_one("#regex-checkbox", Checkbox)
        fuzzy_checkbox = self.query_one("#fuzzy-checkbox", Checkbox)
        
        search_term = search_input.value.strip()
        use_regex = regex_checkbox.value
        use_fuzzy = fuzzy_checkbox.value
        
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        table.filter_processes(search_term, use_regex, use_fuzzy)
        
        if search_term:
            self.log_audit_action("search_processes", f"Searched for '{search_term}' (regex: {use_regex}, fuzzy: {use_fuzzy})")
    
    @on(Button.Pressed, "#clear-search-btn")
    def handle_clear_search(self) -> None:
        """Handle clear search"""
        search_input = self.query_one("#process-search-input", Input)
        search_input.value = ""
        
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        table.filter_processes("")
        
        self.log_audit_action("clear_search", "Cleared process search")
    
    @on(Input.Submitted, "#refresh-interval-input")
    def handle_refresh_interval_change(self) -> None:
        """Handle refresh interval change"""
        interval_input = self.query_one("#refresh-interval-input", Input)
        
        try:
            new_interval = int(interval_input.value)
            if 1 <= new_interval <= 60:
                self.refresh_interval = new_interval
                self.start_auto_refresh()
                self.log_audit_action("change_refresh_interval", f"Changed refresh interval to {new_interval} seconds")
                self.notify(f"Refresh interval set to {new_interval} seconds", severity="information")
            else:
                self.notify("Refresh interval must be between 1 and 60 seconds", severity="error")
        except ValueError:
            self.notify("Invalid refresh interval", severity="error")
    
    @on(DataTable.HeaderSelected, "#process-monitor-table")
    def handle_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """Handle column header click for sorting"""
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        
        # Toggle sort direction
        if table.sort_column == event.column_key.value:
            table.sort_reverse = not table.sort_reverse
        else:
            table.sort_reverse = False
        
        table.sort_by_column(event.column_key.value, table.sort_reverse)
        self.log_audit_action("sort_processes", f"Sorted processes by {event.column_key.value}")
    
    @on(DataTable.RowSelected, "#process-monitor-table")
    def handle_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection - lazy loads expensive details"""
        table = self.query_one("#process-monitor-table", ProcessMonitorTable)
        row_key = event.row_key.value
        
        process_info = table.process_data.get(row_key, {})
        if process_info:
            details_panel = self.query_one("#process-details-panel", ProcessDetailsPanel)
            # Pass cache for lazy loading
            details_panel.update_details(process_info, self.cache)
    
    def on_unmount(self) -> None:
        """Clean up when widget is unmounted"""
        self.stop_auto_refresh()
        
        # Stop background threat worker
        if self.threat_worker:
            self.threat_worker.stop()
        
        self.cache.clear()