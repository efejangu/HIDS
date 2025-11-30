"""
UI Components Module - Reusable UI panels and controls

Handles:
- Search panel
- Control panel  
- Process details panel
"""
from typing import Dict, Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, Button, Input, Label, Checkbox
from textual.reactive import reactive

from .cache import ProcessCache
from .process_analyzer import ProcessAnalyzer


class ProcessSearchPanel(Horizontal):
    """Search panel for process filtering"""
    
    def compose(self) -> ComposeResult:
        """Compose the search panel"""
        yield Input(
            placeholder="Search processes (regex supported)...",
            id="process-search-input",
            classes="control-input"
        )
        yield Button("Search", variant="primary", id="search-btn")
        yield Button("Clear", variant="warning", id="clear-search-btn")
        yield Checkbox("Regex", id="regex-checkbox")
        yield Checkbox("Fuzzy", id="fuzzy-checkbox")


class ProcessControlPanel(Horizontal):
    """Control panel for process operations"""
    
    def compose(self) -> ComposeResult:
        """Compose the control panel"""
        yield Button("Kill Process", variant="error", id="kill-process-btn")
        yield Button("Kill Selected", variant="error", id="kill-selected-btn")
        yield Button("View Details", variant="primary", id="view-details-btn")
        yield Button("Export Snapshot", variant="success", id="export-btn")
        yield Button("Refresh", variant="primary", id="refresh-btn")
        
        yield Label("Refresh:", classes="control-label")
        yield Input(
            placeholder="5",
            value="5",
            id="refresh-interval-input",
            classes="interval-input"
        )
        yield Label("sec", classes="control-label")


class ProcessDetailsPanel(Vertical):
    """Right panel showing process details - lazy loads expensive data"""
    
    selected_pid = reactive(None)
    
    def compose(self) -> ComposeResult:
        """Compose the details panel"""
        yield Label("[bold]Process Details[/bold]", classes="panel-title")
        yield Static(
            "Select a process from the table to view details...",
            id="process-details-content",
            classes="details-display"
        )
    
    def update_details(self, process_info: Dict[str, Any], cache: ProcessCache) -> None:
        """
        Update the details display
        Lazy loads expensive data (connections, modules, hash) on-demand
        
        Args:
            process_info: Process information dictionary
            cache: ProcessCache instance for lazy loading
        """
        if not process_info:
            return
        
        self.selected_pid = process_info.get('pid')
        
        # Basic details (already available)
        details = f"""
[bold]Process Information:[/bold]
  PID: {process_info.get('pid', 'N/A')}
  PPID: {process_info.get('ppid', 'N/A')}
  Name: {process_info.get('name', 'N/A')}
  User: {process_info.get('username', 'N/A')}
  Status: {process_info.get('status', 'N/A')}
  
[bold]Resource Usage:[/bold]
  CPU: {process_info.get('cpu_percent', 0):.1f}%
  Memory: {process_info.get('memory_mb', 0):.1f}MB
  Threads: {process_info.get('num_threads', 0)}
  
[bold]Paths:[/bold]
  Executable: {process_info.get('exe', 'N/A')}
  Command Line: {process_info.get('cmdline', 'N/A')}
  Current Directory: {process_info.get('cwd', 'N/A')}
"""
        
        # Lazy load hash and threat status
        exe_path = process_info.get('exe')
        hash_val = ProcessAnalyzer.get_process_hash(exe_path, cache)
        threat_status = ProcessAnalyzer.check_threat_status(hash_val)
        
        details += f"""
[bold]Security:[/bold]
  Risk Score: {process_info.get('risk_score', 0)}
  Hash: {hash_val}
  Threat Status: {threat_status}
"""
        
        # Lazy load network connections
        pid = process_info.get('pid')
        connections = cache.get_connections(pid)
        if connections is None:
            connections = ProcessAnalyzer.load_connections(pid)
            if connections:
                cache.set_connections(pid, connections)
        
        details += "\n[bold]Network Connections:[/bold]\n"
        if connections:
            for conn in connections:
                details += f"  {conn.get('type', 'N/A')}: {conn.get('laddr', 'N/A')} -> {conn.get('raddr', 'N/A')}\n"
        else:
            details += "  No network connections\n"
        
        # Lazy load modules
        modules = cache.get_modules(pid)
        if modules is None:
            modules = ProcessAnalyzer.load_modules(pid)
            if modules:
                cache.set_modules(pid, modules)
        
        details += "\n[bold]Loaded Modules:[/bold]\n"
        if modules:
            for module in modules[:5]:
                details += f"  {module}\n"
            if len(modules) > 5:
                details += f"  ... and {len(modules) - 5} more\n"
        else:
            details += "  No loaded modules\n"
        
        details_widget = self.query_one("#process-details-content", Static)
        details_widget.update(details.strip())