"""
Process Monitor Table Module - DataTable for displaying processes

Handles:
- Process table display and formatting
- Row operations (add, update, remove)
- Filtering and sorting
- Risk score and status visualization
"""
import re
from typing import Dict, Any

from rich.text import Text
from textual.widgets import DataTable


class ProcessMonitorTable(DataTable):
    """DataTable showing system processes - optimized for performance"""
    
    COLUMN_KEYS = {
        "pid": "PID",
        "ppid": "PPID", 
        "name": "Process Name",
        "cpu": "CPU%",
        "memory": "Memory",
        "user": "User",
        "start_time": "Start Time",
        "risk_score": "Risk Score",
        "status": "Status"
    }
    
    def on_mount(self) -> None:
        """Initialize the process monitor table"""
        # Add columns
        for key, label in self.COLUMN_KEYS.items():
            if key == "name":
                self.add_column(label, width=30, key=key)
            elif key in ["pid", "ppid"]:
                self.add_column(label, width=10, key=key)
            elif key == "user":
                self.add_column(label, width=15, key=key)
            elif key == "start_time":
                self.add_column(label, width=20, key=key)
            elif key == "risk_score":
                self.add_column(label, width=12, key=key)
            elif key == "status":
                self.add_column(label, width=10, key=key)
            else:
                self.add_column(label, width=12, key=key)
        
        # Table configuration
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.show_cursor = True
        
        # Store process data for sorting and filtering
        self.process_data: Dict[str, Dict[str, Any]] = {}
        
        # Set initial sort column
        self.sort_column = "pid"
        self.sort_reverse = False
    
    def _format_risk_text(self, risk_score: int) -> Text:
        """Format risk score with appropriate color"""
        if risk_score >= 80:
            return Text(str(risk_score), style="red bold")
        elif risk_score >= 50:
            return Text(str(risk_score), style="yellow bold")
        elif risk_score >= 20:
            return Text(str(risk_score), style="orange bold")
        else:
            return Text(str(risk_score), style="green")
    
    def _format_status_text(self, status: str) -> Text:
        """Format status with appropriate icon and color"""
        status_map = {
            'running': Text("●", style="green bold"),
            'suspended': Text("⏸", style="yellow bold"),
            'suspicious': Text("⚠", style="yellow bold"),
            'malicious': Text("✗", style="red bold"),
            'scanning': Text("◐", style="blue bold"),
            'safe': Text("✓", style="green bold"),
            'unknown': Text("?", style="gray")
        }
        return status_map.get(status, Text(status, style="gray"))
    
    def _format_memory_text(self, memory_mb: float) -> str:
        """Format memory display"""
        if memory_mb >= 1024:
            return f"{memory_mb/1024:.1f}GB"
        else:
            return f"{memory_mb:.1f}MB"
    
    def add_process(self, process_info: Dict[str, Any]) -> None:
        """Add a process to the table"""
        pid = str(process_info['pid'])
        row_key = f"proc_{pid}"
        
        # Store process data
        self.process_data[row_key] = process_info
        
        # Add row with formatted values
        self.add_row(
            str(process_info['pid']),
            str(process_info.get('ppid', 'N/A')),
            process_info.get('name', 'N/A'),
            f"{process_info.get('cpu_percent', 0):.1f}",
            self._format_memory_text(process_info.get('memory_mb', 0)),
            process_info.get('username', 'N/A'),
            process_info.get('start_time', 'N/A'),
            self._format_risk_text(process_info.get('risk_score', 0)),
            self._format_status_text(process_info.get('status', 'unknown')),
            key=row_key
        )
    
    def update_process(self, process_info: Dict[str, Any]) -> None:
        """
        Update an existing process in the table
        Uses differential updates - only changes dynamic values
        """
        pid = str(process_info['pid'])
        row_key = f"proc_{pid}"
        
        if row_key not in self.rows:
            self.add_process(process_info)
            return
        
        # Get previous data for comparison
        old_data = self.process_data.get(row_key, {})
        
        # Update stored data
        self.process_data[row_key] = process_info
        
        # Only update cells that changed (differential update)
        try:
            if old_data.get('cpu_percent') != process_info.get('cpu_percent'):
                self.update_cell(row_key, "cpu", f"{process_info.get('cpu_percent', 0):.1f}")
            
            if old_data.get('memory_mb') != process_info.get('memory_mb'):
                self.update_cell(row_key, "memory", self._format_memory_text(process_info.get('memory_mb', 0)))
            
            if old_data.get('risk_score') != process_info.get('risk_score'):
                self.update_cell(row_key, "risk_score", self._format_risk_text(process_info.get('risk_score', 0)))
            
            if old_data.get('status') != process_info.get('status'):
                self.update_cell(row_key, "status", self._format_status_text(process_info.get('status', 'unknown')))
        except Exception:
            # Handle update errors gracefully
            pass
    
    def remove_process(self, pid: int) -> None:
        """Remove a process from the table"""
        row_key = f"proc_{pid}"
        if row_key in self.rows:
            try:
                self.remove_row(row_key)
                if row_key in self.process_data:
                    del self.process_data[row_key]
            except Exception:
                pass
    
    def filter_processes(self, search_term: str, use_regex: bool = False, use_fuzzy: bool = False) -> None:
        """Filter processes based on search term"""
        if not search_term:
            for row_key in self.process_data.keys():
                try:
                    self.rows[row_key].visible = True
                except Exception:
                    pass
            return
        
        search_term = search_term.lower()
        
        for row_key, process_info in self.process_data.items():
            match = False
            
            if use_regex:
                try:
                    pattern = re.compile(search_term, re.IGNORECASE)
                    if pattern.search(process_info.get('name', '').lower()):
                        match = True
                    elif pattern.search(str(process_info.get('pid', ''))):
                        match = True
                    elif pattern.search(process_info.get('username', '').lower()):
                        match = True
                except re.error:
                    use_regex = False
            
            if not use_regex:
                search_fields = [
                    process_info.get('name', '').lower(),
                    str(process_info.get('pid', '')),
                    process_info.get('username', '').lower()
                ]
                
                if use_fuzzy:
                    for field in search_fields:
                        if any(term in field for term in search_term.split()):
                            match = True
                            break
                else:
                    for field in search_fields:
                        if search_term in field:
                            match = True
                            break
            
            try:
                self.rows[row_key].visible = match
            except Exception:
                pass
    
    def sort_by_column(self, column_key: str, reverse: bool = False) -> None:
        """Sort processes by column"""
        if column_key not in self.COLUMN_KEYS:
            return
        
        self.sort_column = column_key
        self.sort_reverse = reverse
        
        # Get sorted row keys
        sorted_rows = sorted(
            self.process_data.items(),
            key=lambda x: x[1].get(column_key, 0),
            reverse=reverse
        )
        
        # Reorder rows
        try:
            for i, (row_key, _) in enumerate(sorted_rows):
                self.move_row(row_key, i)
        except Exception:
            pass