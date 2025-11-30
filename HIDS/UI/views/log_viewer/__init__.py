"""
Log Viewer Package - Modular log viewing and analysis system

This package provides a comprehensive log viewing interface with:
- Intelligent log parsing with timestamp and level extraction
- Real-time log tailing with auto-refresh
- Search and filtering capabilities (text, regex, level-based)
- Virtual scrolling for performance with large files
- Export functionality (JSON format)
- Background file reading with pagination

Package Structure:
- view: Main view orchestration (LogViewerView)
- components: UI panels and controls (LogFileSelector, LogSearchPanel, LogFilterPanel, etc.)
- log_table: Log entry table widget (LogViewerTable)
- log_reader: File reading and monitoring (LogFileReader, LogDirectoryMonitor)
- log_parser: Log parsing and analysis (LogParser, LogEntry, LogLevel)
"""

# Import main view for backward compatibility
from .view import LogViewerView

# Import components for external use
from .components import (
    LogFileSelector,
    LogSearchPanel,
    LogFilterPanel,
    LogControlPanel,
    LogStatsPanel,
    LogEntryDetailsPanel
)
from .log_table import LogViewerTable
from .log_reader import LogFileReader, LogDirectoryMonitor
from .log_parser import LogParser, LogEntry, LogLevel

__all__ = [
    # Main view
    'LogViewerView',
    
    # UI components
    'LogFileSelector',
    'LogSearchPanel',
    'LogFilterPanel',
    'LogControlPanel',
    'LogStatsPanel',
    'LogEntryDetailsPanel',
    'LogViewerTable',
    
    # Core components
    'LogFileReader',
    'LogDirectoryMonitor',
    'LogParser',
    
    # Data models
    'LogEntry',
    'LogLevel',
]