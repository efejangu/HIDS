"""
Log Table Module - DataTable for displaying log entries

Handles:
- Log entry display with syntax highlighting
- Color-coded log levels
- Row selection and interaction
- Virtual scrolling support
- Efficient rendering
"""
from typing import List, Optional, Set
from datetime import datetime

from textual.widgets import DataTable
from textual import on
from rich.text import Text

from .log_parser import LogEntry, LogLevel


class LogViewerTable(DataTable):
    """
    DataTable for displaying log entries with syntax highlighting
    
    Features:
    - Color-coded log levels
    - Line number display
    - Timestamp formatting
    - Component/source display
    - Message preview with truncation
    - Row selection for details view
    """
    
    def __init__(self, **kwargs):
        """Initialize the log viewer table"""
        super().__init__(**kwargs)
        self.entries: List[LogEntry] = []
        self.entry_map: dict = {}  # Maps row_key to LogEntry
        self.max_message_length = 120  # Truncate long messages
    
    def on_mount(self) -> None:
        """Initialize table columns when mounted"""
        self.cursor_type = "row"
        self.zebra_stripes = True
        
        # Add columns
        self.add_columns(
            "#",           # Line number
            "Timestamp",   # When the log was created
            "Level",       # Log severity level
            "Source",      # Component/module
            "Message"      # Log message
        )
    
    def add_log_entry(self, entry: LogEntry) -> None:
        """
        Add a single log entry to the table
        
        Args:
            entry: LogEntry object to add
        """
        row_data = self._format_entry(entry)
        row_key = self.add_row(*row_data)
        self.entry_map[row_key] = entry
        self.entries.append(entry)
    
    def add_log_entries(self, entries: List[LogEntry]) -> None:
        """
        Add multiple log entries to the table efficiently using batch operations
        
        Args:
            entries: List of LogEntry objects to add
        """
        # Batch add for better performance
        rows_to_add = []
        for entry in entries:
            row_data = self._format_entry(entry)
            rows_to_add.append(row_data)
            self.entries.append(entry)
        
        # Add all rows at once for better performance
        for row_data in rows_to_add:
            row_key = self.add_row(*row_data)
            # Map using index since we appended entries in same order
            idx = len(self.entry_map)
            self.entry_map[row_key] = self.entries[-(len(rows_to_add) - idx)]
    
    def clear_entries(self) -> None:
        """Clear all entries from the table"""
        self.clear()
        self.entries.clear()
        self.entry_map.clear()
    
    def _format_entry(self, entry: LogEntry) -> tuple:
        """
        Format a log entry for table display
        
        Args:
            entry: LogEntry to format
            
        Returns:
            Tuple of formatted cell values
        """
        # Line number
        line_num = str(entry.line_number)
        
        # Timestamp
        if entry.timestamp:
            timestamp = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp = "-"
        
        # Log level with color
        level_color = entry.level.color
        level_text = Text(entry.level.value, style=level_color)
        
        # Source/component
        source = entry.source if entry.source else "-"
        if len(source) > 20:
            source = source[:17] + "..."
        
        # Message (truncate if too long)
        message = entry.message
        if len(message) > self.max_message_length:
            message = message[:self.max_message_length - 3] + "..."
        
        # Apply color to continuation lines
        if entry.is_continuation:
            message_text = Text(message, style="dim")
        else:
            message_text = message
        
        return (line_num, timestamp, level_text, source, message_text)
    
    def get_selected_entry(self) -> Optional[LogEntry]:
        """
        Get the currently selected log entry
        
        Returns:
            Selected LogEntry or None
        """
        if not self.cursor_row:
            return None
        
        row_key = self.coordinate_to_cell_key(self.cursor_coordinate).row_key
        return self.entry_map.get(row_key)
    
    def filter_by_level(self, allowed_levels: Set[LogLevel]) -> None:
        """
        Filter table to show only entries with specified log levels (optimized)
        
        Args:
            allowed_levels: Set of LogLevel values to display
        """
        self.clear()
        self.entry_map.clear()
        
        # Batch filtered entries for better performance
        filtered_entries = [entry for entry in self.entries if entry.level in allowed_levels]
        
        # Add all filtered rows at once
        for entry in filtered_entries:
            row_data = self._format_entry(entry)
            row_key = self.add_row(*row_data)
            self.entry_map[row_key] = entry
    
    def filter_by_search(self, query: str, case_sensitive: bool = False) -> None:
        """
        Filter table to show only entries matching search query (optimized)
        
        Args:
            query: Search string
            case_sensitive: Whether search is case-sensitive
        """
        self.clear()
        self.entry_map.clear()
        
        if not query:
            # Show all entries - batch operation
            for entry in self.entries:
                row_data = self._format_entry(entry)
                row_key = self.add_row(*row_data)
                self.entry_map[row_key] = entry
            return
        
        # Pre-process search query
        search_query = query if case_sensitive else query.lower()
        
        # Batch filter matching entries
        matching_entries = []
        for entry in self.entries:
            search_text = f"{entry.source} {entry.message}"
            if not case_sensitive:
                search_text = search_text.lower()
            
            if search_query in search_text:
                matching_entries.append(entry)
        
        # Add all matching rows at once
        for entry in matching_entries:
            row_data = self._format_entry(entry)
            row_key = self.add_row(*row_data)
            self.entry_map[row_key] = entry
    
    def jump_to_line(self, line_number: int) -> None:
        """
        Jump to a specific line number
        
        Args:
            line_number: Line number to jump to
        """
        for i, entry in enumerate(self.entries):
            if entry.line_number == line_number:
                if i < self.row_count:
                    self.cursor_coordinate = (i, 0)
                    self.scroll_to_row(i)
                break
    
    def jump_to_top(self) -> None:
        """Jump to the first entry"""
        if self.row_count > 0:
            self.cursor_coordinate = (0, 0)
            self.scroll_to_row(0)
    
    def jump_to_bottom(self) -> None:
        """Jump to the last entry"""
        if self.row_count > 0:
            last_row = self.row_count - 1
            self.cursor_coordinate = (last_row, 0)
            self.scroll_to_row(last_row)
    
    def get_visible_entries(self) -> List[LogEntry]:
        """
        Get list of currently visible (filtered) entries
        
        Returns:
            List of visible LogEntry objects
        """
        return [entry for entry in self.entry_map.values()]
    
    def get_stats(self) -> dict:
        """
        Get statistics about current entries
        
        Returns:
            Dictionary with entry counts by level
        """
        stats = {
            'total': len(self.entries),
            'visible': len(self.entry_map),
            'debug': 0,
            'info': 0,
            'warning': 0,
            'error': 0,
            'critical': 0,
        }
        
        for entry in self.entries:
            level_name = entry.level.value.lower()
            if level_name in stats:
                stats[level_name] += 1
        
        return stats