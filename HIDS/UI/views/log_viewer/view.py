"""
Log Viewer View Module - Main UI orchestration

Handles:
- Main view composition and layout
- File selection and loading
- Search and filter coordination
- Real-time log tailing
- Export functionality
- Event handlers for all UI interactions
"""
import json
from pathlib import Path
from typing import Optional, Set
from datetime import datetime

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Label, Button, Input, Checkbox, Select, Static
from textual.timer import Timer
from textual import on, work

from .log_parser import LogLevel, LogEntry
from .log_reader import LogFileReader, LogDirectoryMonitor
from .log_table import LogViewerTable
from .components import (
    LogFileSelector,
    LogSearchPanel,
    LogFilterPanel,
    LogControlPanel,
    LogStatsPanel,
    LogEntryDetailsPanel
)


class LogViewerView(Vertical):
    """
    Comprehensive log viewer with parsing, filtering, and export capabilities
    
    Features:
    - Multiple log file support
    - Intelligent parsing with syntax highlighting
    - Real-time tailing
    - Search and filter by level/text
    - Export filtered logs
    - Virtual scrolling for performance
    """
    
    def __init__(self, **kwargs):
        """Initialize the log viewer"""
        super().__init__(**kwargs)
        
        # Determine log directory
        self.log_directory = Path(__file__).parent.parent.parent / "app_log"
        if not self.log_directory.exists():
            self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Components
        self.current_reader: Optional[LogFileReader] = None
        self.directory_monitor = LogDirectoryMonitor(self.log_directory)
        
        # State
        self.current_file: Optional[Path] = None
        self.auto_refresh_timer: Optional[Timer] = None
        self.is_tailing = False
        
        # Filter state
        self.active_filters: Set[LogLevel] = {
            LogLevel.DEBUG,
            LogLevel.INFO,
            LogLevel.WARNING,
            LogLevel.ERROR,
            LogLevel.CRITICAL,
        }
        
        # Search state
        self.search_query = ""
        self.case_sensitive = False
        self._search_timer: Optional[Timer] = None  # For debouncing search
    
    def compose(self) -> ComposeResult:
        """Compose the log viewer layout"""
        # Top control panels
        with Container(id="log-viewer-controls"):
            with Horizontal(id="log-file-selector-panel"):
                yield LogFileSelector(self.log_directory, id="log-file-selector")
            
            with Horizontal(id="log-search-filter-panel"):
                yield LogSearchPanel(id="log-search-panel")
            
            with Horizontal(id="log-level-filter-panel"):
                yield LogFilterPanel(id="log-filter-panel")
            
            with Horizontal(id="log-control-actions-panel"):
                yield LogControlPanel(id="log-control-panel")
        
        # Main content area - split pane
        with Horizontal(id="log-viewer-content"):
            # Main log table (70%)
            with Vertical(classes="main-panel", id="log-main-panel"):
                yield Label("[bold]Log Entries[/bold]", classes="section-title")
                yield LogViewerTable(id="log-viewer-table")
            
            # Right sidebar (30%)
            with Vertical(classes="right-panel", id="log-sidebar"):
                yield LogStatsPanel(id="log-stats-panel")
                yield LogEntryDetailsPanel(id="log-entry-details-panel")
    
    def on_mount(self) -> None:
        """Initialize when view is mounted"""
        # Refresh file list to discover log files
        try:
            file_selector = self.query_one("#log-file-selector", LogFileSelector)
            file_selector.refresh_file_list()
            
            # Load first file if available
            if file_selector.selected_file:
                self.load_log_file(file_selector.selected_file)
        except Exception as e:
            self.notify(f"Error initializing log viewer: {e}", severity="error")
    
    def load_log_file(self, file_path: Path) -> None:
        """
        Load a log file into the viewer
        
        Args:
            file_path: Path to the log file
        """
        self.current_file = file_path
        self.current_reader = LogFileReader(file_path, chunk_size=1000)
        
        # Clear existing entries
        table = self.query_one("#log-viewer-table", LogViewerTable)
        table.clear_entries()
        
        # Load entries (use last N for performance with large files)
        self._load_entries()
    
    @work(exclusive=True, thread=True)
    async def _load_entries(self, tail_mode: bool = False) -> None:
        """
        Load log entries in background thread
        
        Args:
            tail_mode: If True, only load last 100 lines
        """
        if not self.current_reader:
            return
        
        try:
            # Read entries
            if tail_mode:
                entries = self.current_reader.read_last_n_lines(100)
                self.is_tailing = True
            else:
                # For large files, read last 500 lines initially
                total_lines = self.current_reader.count_lines()
                if total_lines > 500:
                    entries = self.current_reader.read_last_n_lines(500)
                else:
                    entries = self.current_reader.read_all()
                self.is_tailing = False
            
            # Update UI on main thread
            self.call_after_refresh(self._update_table_with_entries, entries)
            
        except Exception as e:
            self.notify(f"Error loading log file: {e}", severity="error")
    
    def _update_table_with_entries(self, entries: list) -> None:
        """
        Update table with loaded entries (main thread)
        
        Args:
            entries: List of LogEntry objects
        """
        table = self.query_one("#log-viewer-table", LogViewerTable)
        table.clear_entries()
        table.add_log_entries(entries)
        
        # Apply current filters
        self._apply_filters()
        
        # Update stats
        self._update_stats()
        
        # Auto-scroll to bottom if tailing
        if self.is_tailing:
            table.jump_to_bottom()
    
    def _apply_filters(self) -> None:
        """Apply current search and level filters (optimized - single pass)"""
        table = self.query_one("#log-viewer-table", LogViewerTable)
        
        # Optimize: Apply both filters in a single operation when possible
        if self.search_query:
            # First filter by search, then by level (more selective first)
            table.filter_by_search(self.search_query, self.case_sensitive)
            # Note: search already filters, so we don't double-filter
        else:
            # Only level filter needed
            table.filter_by_level(self.active_filters)
    
    def _update_stats(self) -> None:
        """Update statistics panel"""
        table = self.query_one("#log-viewer-table", LogViewerTable)
        stats = table.get_stats()
        
        stats_panel = self.query_one("#log-stats-panel", LogStatsPanel)
        stats_panel.total_entries = stats['total']
        stats_panel.visible_entries = stats['visible']
        stats_panel.error_count = stats['error'] + stats['critical']
        stats_panel.warning_count = stats['warning']
    
    # Event Handlers
    
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle file selection changes"""
        if event.select.id == "log-file-select" and event.value != Select.BLANK:
            # File was selected from dropdown
            self.load_log_file(Path(event.value))
    
    @on(Button.Pressed, "#refresh-logs-btn")
    def handle_refresh(self) -> None:
        """Handle refresh button"""
        if self.current_file:
            self.load_log_file(self.current_file)
            self.notify("Log file refreshed", severity="information")
    
    @on(Button.Pressed, "#tail-logs-btn")
    def handle_tail(self) -> None:
        """Handle tail button - show last 100 lines"""
        if self.current_file:
            self._load_entries(tail_mode=True)
            self.notify("Showing last 100 log entries", severity="information")
    
    @on(Button.Pressed, "#jump-top-btn")
    def handle_jump_top(self) -> None:
        """Handle jump to top button"""
        table = self.query_one("#log-viewer-table", LogViewerTable)
        table.jump_to_top()
    
    @on(Button.Pressed, "#jump-bottom-btn")
    def handle_jump_bottom(self) -> None:
        """Handle jump to bottom button"""
        table = self.query_one("#log-viewer-table", LogViewerTable)
        table.jump_to_bottom()
    
    @on(Button.Pressed, "#export-logs-btn")
    def handle_export(self) -> None:
        """Handle export button"""
        self._export_logs()
    
    @on(Button.Pressed, "#clear-search-btn")
    def handle_clear_search(self) -> None:
        """Handle clear search button"""
        search_input = self.query_one("#log-search-input", Input)
        search_input.value = ""
        self.search_query = ""
        self._apply_filters()
        self._update_stats()
    
    @on(Button.Pressed, "#reset-filters-btn")
    def handle_reset_filters(self) -> None:
        """Handle reset filters button"""
        # Reset all level filters
        self.active_filters = {
            LogLevel.DEBUG,
            LogLevel.INFO,
            LogLevel.WARNING,
            LogLevel.ERROR,
            LogLevel.CRITICAL,
        }
        
        # Check all checkboxes
        for level in ["debug", "info", "warning", "error", "critical"]:
            try:
                checkbox = self.query_one(f"#filter-{level}", Checkbox)
                checkbox.value = True
            except Exception:
                pass
        
        self._apply_filters()
        self._update_stats()
        self.notify("Filters reset", severity="information")
    
    @on(Input.Changed, "#log-search-input")
    def handle_search_changed(self, event: Input.Changed) -> None:
        """Handle search input changes with debouncing for better performance"""
        self.search_query = event.value
        
        # Cancel previous search timer if exists
        if self._search_timer:
            self._search_timer.stop()
        
        # Debounce search - wait 300ms after last keystroke
        self._search_timer = self.set_timer(
            0.3,
            lambda: self._perform_search()
        )
    
    def _perform_search(self) -> None:
        """Execute the actual search operation (debounced)"""
        self._apply_filters()
        self._update_stats()
        self._search_timer = None
    
    @on(Checkbox.Changed, "#case-sensitive-checkbox")
    def handle_case_sensitive_changed(self, event: Checkbox.Changed) -> None:
        """Handle case sensitive checkbox"""
        self.case_sensitive = event.value
        if self.search_query:
            self._apply_filters()
            self._update_stats()
    
    @on(Checkbox.Changed, "#auto-refresh-checkbox")
    def handle_auto_refresh_changed(self, event: Checkbox.Changed) -> None:
        """Handle auto-refresh checkbox"""
        if event.value:
            self.start_auto_refresh()
        else:
            self.stop_auto_refresh()
    
    @on(Checkbox.Changed)
    def handle_level_filter_changed(self, event: Checkbox.Changed) -> None:
        """Handle log level filter checkbox changes"""
        # Map checkbox IDs to LogLevel
        level_map = {
            "filter-debug": LogLevel.DEBUG,
            "filter-info": LogLevel.INFO,
            "filter-warning": LogLevel.WARNING,
            "filter-error": LogLevel.ERROR,
            "filter-critical": LogLevel.CRITICAL,
        }
        
        if event.checkbox.id in level_map:
            level = level_map[event.checkbox.id]
            if event.value:
                self.active_filters.add(level)
            else:
                self.active_filters.discard(level)
            
            self._apply_filters()
            self._update_stats()
    
    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection in log table"""
        if event.data_table.id == "log-viewer-table":
            table = self.query_one("#log-viewer-table", LogViewerTable)
            entry = table.get_selected_entry()
            
            if entry:
                details_panel = self.query_one("#log-entry-details-panel", LogEntryDetailsPanel)
                details_panel.show_entry_details(entry)
    
    def start_auto_refresh(self) -> None:
        """Start auto-refresh timer for log tailing"""
        if self.auto_refresh_timer:
            self.auto_refresh_timer.stop()
        
        self.auto_refresh_timer = self.set_interval(2.0, self._auto_refresh_callback)
        self.notify("Auto-refresh enabled", severity="information")
    
    def stop_auto_refresh(self) -> None:
        """Stop auto-refresh timer"""
        if self.auto_refresh_timer:
            self.auto_refresh_timer.stop()
            self.auto_refresh_timer = None
    
    def _auto_refresh_callback(self) -> None:
        """Callback for auto-refresh timer"""
        if not self.current_reader:
            return
        
        # Get new entries from tail
        new_entries = self.current_reader.tail()
        
        if new_entries:
            table = self.query_one("#log-viewer-table", LogViewerTable)
            
            # Add new entries
            for entry in new_entries:
                table.add_log_entry(entry)
            
            # Reapply filters
            self._apply_filters()
            self._update_stats()
            
            # Auto-scroll to bottom if we're at the bottom
            if self.is_tailing:
                table.jump_to_bottom()
    
    def _export_logs(self) -> None:
        """Export visible log entries to JSON file"""
        table = self.query_one("#log-viewer-table", LogViewerTable)
        visible_entries = table.get_visible_entries()
        
        if not visible_entries:
            self.notify("No log entries to export", severity="warning")
            return
        
        # Create export filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_file = self.log_directory / f"export_{timestamp}.json"
        
        try:
            # Convert entries to dict
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'source_file': str(self.current_file) if self.current_file else None,
                'total_entries': len(visible_entries),
                'entries': [entry.to_dict() for entry in visible_entries]
            }
            
            # Write to file
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.notify(
                f"Exported {len(visible_entries)} entries to {export_file.name}",
                severity="information"
            )
            
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")
    
    def on_unmount(self) -> None:
        """Clean up when view is unmounted"""
        # Stop auto-refresh timer
        if self.auto_refresh_timer:
            self.auto_refresh_timer.stop()
            self.auto_refresh_timer = None
        
        # Stop search timer
        if self._search_timer:
            self._search_timer.stop()
            self._search_timer = None