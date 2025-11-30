"""
Log Viewer Components Module - UI widgets and panels

Handles:
- File selector component
- Search and filter controls
- Log statistics panel
- Export controls
"""
from pathlib import Path
from typing import Optional, Callable, List
from datetime import datetime

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Select, Static, Label, Checkbox
from textual.reactive import reactive

from .log_parser import LogLevel


class LogFileSelector(Vertical):
    """File selector for choosing which log file to view"""
    
    selected_file: reactive[Optional[Path]] = reactive(None)
    
    def __init__(self, log_directory: Path, **kwargs):
        """
        Initialize file selector
        
        Args:
            log_directory: Directory containing log files
        """
        super().__init__(**kwargs)
        self.log_directory = log_directory
        self.file_options = []
    
    def compose(self) -> ComposeResult:
        """Compose the file selector"""
        yield Label("[bold]Log File:[/bold]", classes="control-label")
        yield Select(
            options=[("No log files found", None)],
            id="log-file-select",
            allow_blank=True
        )
        yield Static("No file selected", id="file-info-display")
    
    def on_mount(self) -> None:
        """Load available log files when mounted"""
        self.refresh_file_list()
    
    def refresh_file_list(self) -> None:
        """Refresh the list of available log files"""
        if not self.log_directory.exists():
            return
        
        # Get all .log files
        log_files = sorted(
            self.log_directory.glob('*.log'),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        
        # Create options
        self.file_options = [
            (file.name, str(file)) for file in log_files
        ]
        
        # Update select widget
        select = self.query_one("#log-file-select", Select)
        select.set_options(self.file_options)
        
        # Auto-select first file if available
        if self.file_options and not self.selected_file:
            select.value = self.file_options[0][1]
            self.selected_file = Path(self.file_options[0][1])
            self._update_file_info()
    
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle file selection change"""
        if event.select.id == "log-file-select" and event.value != Select.BLANK:
            self.selected_file = Path(event.value)
            self._update_file_info()
            # Don't stop propagation - let parent view handle it too
    
    def _update_file_info(self) -> None:
        """Update file information display"""
        if not self.selected_file or not self.selected_file.exists():
            return
        
        stat = self.selected_file.stat()
        size_mb = round(stat.st_size / 1024 / 1024, 2)
        modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        info_text = f"Size: {size_mb} MB | Modified: {modified}"
        
        try:
            info_display = self.query_one("#file-info-display", Static)
            self.call_after_refresh(info_display.update, info_text)
        except Exception:
            pass


class LogSearchPanel(Horizontal):
    """Search and filter controls for log viewer"""
    
    def compose(self) -> ComposeResult:
        """Compose the search panel"""
        yield Label("[bold]Search:[/bold]", classes="control-label")
        yield Input(
            placeholder="Search logs...",
            id="log-search-input"
        )
        yield Checkbox("Case sensitive", id="case-sensitive-checkbox")
        yield Checkbox("Regex", id="regex-checkbox")
        yield Button("Clear", id="clear-search-btn", variant="default")


class LogFilterPanel(Horizontal):
    """Log level and date filtering controls"""
    
    def compose(self) -> ComposeResult:
        """Compose the filter panel"""
        yield Label("[bold]Filter by Level:[/bold]", classes="control-label")
        
        # Log level checkboxes
        yield Checkbox("DEBUG", id="filter-debug", value=True)
        yield Checkbox("INFO", id="filter-info", value=True)
        yield Checkbox("WARNING", id="filter-warning", value=True)
        yield Checkbox("ERROR", id="filter-error", value=True)
        yield Checkbox("CRITICAL", id="filter-critical", value=True)
        
        yield Button("Reset Filters", id="reset-filters-btn", variant="default")


class LogControlPanel(Horizontal):
    """Main control panel with view options and actions"""
    
    auto_refresh: reactive[bool] = reactive(False)
    
    def compose(self) -> ComposeResult:
        """Compose the control panel"""
        yield Button("⟳ Refresh", id="refresh-logs-btn", variant="primary")
        yield Checkbox("Auto-refresh", id="auto-refresh-checkbox")
        yield Button("⇊ Tail (Last 100)", id="tail-logs-btn", variant="default")
        yield Button("⬆ Jump to Top", id="jump-top-btn", variant="default")
        yield Button("⬇ Jump to Bottom", id="jump-bottom-btn", variant="default")
        yield Button("💾 Export", id="export-logs-btn", variant="success")
    
    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox state changes"""
        if event.checkbox.id == "auto-refresh-checkbox":
            self.auto_refresh = event.value


class LogStatsPanel(Static):
    """Display log statistics"""
    
    total_entries: reactive[int] = reactive(0)
    visible_entries: reactive[int] = reactive(0)
    error_count: reactive[int] = reactive(0)
    warning_count: reactive[int] = reactive(0)
    
    def compose(self) -> ComposeResult:
        """Compose the stats panel"""
        yield Label("[bold]Log Statistics[/bold]", classes="panel-title")
        yield Static(
            self._format_stats(),
            id="stats-content"
        )
    
    def _format_stats(self) -> str:
        """Format statistics for display"""
        return (
            f"Total Entries: {self.total_entries}\n"
            f"Visible: {self.visible_entries}\n"
            f"[red]Errors: {self.error_count}[/red]\n"
            f"[yellow]Warnings: {self.warning_count}[/yellow]"
        )
    
    def watch_total_entries(self, value: int) -> None:
        """Update display when total entries changes"""
        self._update_display()
    
    def watch_visible_entries(self, value: int) -> None:
        """Update display when visible entries changes"""
        self._update_display()
    
    def watch_error_count(self, value: int) -> None:
        """Update display when error count changes"""
        self._update_display()
    
    def watch_warning_count(self, value: int) -> None:
        """Update display when warning count changes"""
        self._update_display()
    
    def _update_display(self) -> None:
        """Update the stats display"""
        try:
            stats_content = self.query_one("#stats-content", Static)
            self.call_after_refresh(stats_content.update, self._format_stats())
        except Exception:
            pass


class LogEntryDetailsPanel(Vertical):
    """Detailed view of selected log entry"""
    
    def compose(self) -> ComposeResult:
        """Compose the details panel"""
        yield Label("[bold]Entry Details[/bold]", classes="panel-title")
        yield Static(
            "Select a log entry to view details",
            id="entry-details-content"
        )
    
    def show_entry_details(self, entry) -> None:
        """
        Display details for a log entry
        
        Args:
            entry: LogEntry object to display
        """
        timestamp = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else 'N/A'
        level_color = entry.level.color
        
        details = (
            f"[bold]Line:[/bold] {entry.line_number}\n"
            f"[bold]Timestamp:[/bold] {timestamp}\n"
            f"[bold]Level:[/bold] [{level_color}]{entry.level.value}[/{level_color}]\n"
            f"[bold]Source:[/bold] {entry.source or 'N/A'}\n"
            f"[bold]Message:[/bold]\n{entry.message}\n\n"
            f"[bold]Raw Line:[/bold]\n{entry.raw_line}"
        )
        
        try:
            content = self.query_one("#entry-details-content", Static)
            self.call_after_refresh(content.update, details)
        except Exception:
            pass
    
    def clear_details(self) -> None:
        """Clear the details display"""
        try:
            content = self.query_one("#entry-details-content", Static)
            self.call_after_refresh(content.update, "Select a log entry to view details")
        except Exception:
            pass