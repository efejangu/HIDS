"""
Log Parser Module - Intelligent log entry parsing

Handles:
- Timestamp extraction and parsing
- Log level identification (INFO, WARNING, ERROR, DEBUG, CRITICAL)
- Component/source extraction
- Message parsing
- Multi-line log entry handling (stack traces, JSON)
"""
import re
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"
    
    @property
    def color(self) -> str:
        """Get color representation for this log level"""
        colors = {
            LogLevel.DEBUG: "blue",
            LogLevel.INFO: "green",
            LogLevel.WARNING: "yellow",
            LogLevel.ERROR: "red",
            LogLevel.CRITICAL: "red bold",
            LogLevel.UNKNOWN: "white",
        }
        return colors.get(self, "white")


@dataclass
class LogEntry:
    """Parsed log entry with metadata"""
    line_number: int
    timestamp: Optional[datetime]
    level: LogLevel
    source: str
    message: str
    raw_line: str
    is_continuation: bool = False  # For multi-line entries
    
    def __str__(self) -> str:
        return self.raw_line
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return {
            'line_number': self.line_number,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'level': self.level.value,
            'source': self.source,
            'message': self.message,
            'raw_line': self.raw_line
        }


class LogParser:
    """
    Intelligent log parser supporting various log formats
    
    Supported formats:
    - Standard Python logging: "2025-11-22 01:18:23 - FileMonitor - INFO - Message"
    - Syslog: "Nov 22 01:18:23 hostname service[pid]: message"
    - Simple: "INFO: Message"
    - Generic timestamped: "2025-11-22 01:18:23 Message"
    """
    
    # Regex patterns for different log formats
    PATTERNS = [
        # Python logging format: "2025-11-22 01:18:23 - Source - LEVEL - Message"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
            r'\s+-\s+(?P<source>[^-]+?)'
            r'\s+-\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)'
            r'\s+-\s+(?P<message>.*)$'
        ),
        
        # Alternative Python format with milliseconds
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})'
            r'\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)'
            r'\s+(?P<source>\S+)'
            r'\s+(?P<message>.*)$'
        ),
        
        # Syslog format
        re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
            r'\s+(?P<source>\S+)'
            r'(?:\[\d+\])?:\s+(?P<message>.*)$'
        ),
        
        # Simple format with level: "INFO: Message" or "ERROR: Message"
        re.compile(
            r'^(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)'
            r':\s+(?P<message>.*)$'
        ),
        
        # Timestamp only format: "2025-11-22 01:18:23 Message"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
            r'\s+(?P<message>.*)$'
        ),
    ]
    
    # Timestamp formats to try
    TIMESTAMP_FORMATS = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S,%f',
        '%b %d %H:%M:%S',  # Syslog format
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
    ]
    
    def __init__(self):
        """Initialize the log parser"""
        self.current_year = datetime.now().year
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string into datetime object"""
        if not timestamp_str:
            return None
        
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str.strip(), fmt)
                # For syslog format without year, add current year
                if fmt == '%b %d %H:%M:%S':
                    dt = dt.replace(year=self.current_year)
                return dt
            except ValueError:
                continue
        
        return None
    
    def parse_level(self, level_str: Optional[str]) -> LogLevel:
        """Parse log level from string"""
        if not level_str:
            return LogLevel.UNKNOWN
        
        level_str = level_str.strip().upper()
        try:
            return LogLevel[level_str]
        except KeyError:
            # Check for partial matches
            if 'ERR' in level_str:
                return LogLevel.ERROR
            elif 'WARN' in level_str:
                return LogLevel.WARNING
            elif 'INFO' in level_str:
                return LogLevel.INFO
            elif 'DEBUG' in level_str or 'DIAG' in level_str:
                return LogLevel.DEBUG
            elif 'CRIT' in level_str or 'FATAL' in level_str:
                return LogLevel.CRITICAL
            
            return LogLevel.UNKNOWN
    
    def is_continuation_line(self, line: str) -> bool:
        """Check if line is a continuation of previous entry (traceback, JSON, etc.)"""
        if not line.strip():
            return True
        
        # Common continuation patterns
        continuation_patterns = [
            r'^\s+',  # Starts with whitespace
            r'^Traceback',
            r'^File\s+"',
            r'^\s+at\s+',
            r'^\s+\.\.\.',
            r'^\s*[\{\[\(]',  # JSON/dict continuation
        ]
        
        return any(re.match(pattern, line) for pattern in continuation_patterns)
    
    def parse_line(self, line: str, line_number: int) -> LogEntry:
        """
        Parse a single log line
        
        Args:
            line: The log line to parse
            line_number: Line number in the file
            
        Returns:
            LogEntry object with parsed information
        """
        # Check if it's a continuation line
        if self.is_continuation_line(line):
            return LogEntry(
                line_number=line_number,
                timestamp=None,
                level=LogLevel.UNKNOWN,
                source="",
                message=line.strip(),
                raw_line=line.rstrip('\n'),
                is_continuation=True
            )
        
        # Try each pattern
        for pattern in self.PATTERNS:
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                timestamp = self.parse_timestamp(groups.get('timestamp', ''))
                level = self.parse_level(groups.get('level'))
                source = groups.get('source', '').strip()
                message = groups.get('message', '').strip()
                
                return LogEntry(
                    line_number=line_number,
                    timestamp=timestamp,
                    level=level,
                    source=source,
                    message=message,
                    raw_line=line.rstrip('\n')
                )
        
        # If no pattern matched, create a generic entry
        return LogEntry(
            line_number=line_number,
            timestamp=None,
            level=LogLevel.UNKNOWN,
            source="",
            message=line.strip(),
            raw_line=line.rstrip('\n')
        )
    
    def parse_lines(self, lines: List[str], start_line: int = 1) -> List[LogEntry]:
        """
        Parse multiple log lines
        
        Args:
            lines: List of log lines
            start_line: Starting line number
            
        Returns:
            List of LogEntry objects
        """
        entries = []
        for i, line in enumerate(lines, start=start_line):
            entry = self.parse_line(line, i)
            entries.append(entry)
        
        return entries