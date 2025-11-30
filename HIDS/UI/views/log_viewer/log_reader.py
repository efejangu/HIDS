"""
Log File Reader Module - Efficient log file reading with pagination and streaming

Handles:
- Large file reading with memory-efficient chunking
- Pagination support for UI display
- Real-time file tailing for new entries
- File monitoring for changes
- Caching for performance
"""
import os
from pathlib import Path
from typing import List, Optional, Tuple, Generator
from collections import deque
from datetime import datetime

from .log_parser import LogParser, LogEntry


class LogFileReader:
    """
    Efficient log file reader with pagination and streaming support
    
    Features:
    - Memory-efficient chunked reading
    - Pagination for large files
    - Real-time tailing
    - File change detection
    - Line number indexing for quick access
    """
    
    def __init__(self, file_path: Path, chunk_size: int = 1000):
        """
        Initialize log file reader
        
        Args:
            file_path: Path to the log file
            chunk_size: Number of lines to read per chunk
        """
        self.file_path = Path(file_path)
        self.chunk_size = chunk_size
        self.parser = LogParser()
        
        # File state tracking
        self.file_size = 0
        self.last_modified = 0.0
        self.total_lines = 0
        
        # Caching
        self.cached_chunks: dict = {}  # {start_line: List[LogEntry]}
        self.max_cached_chunks = 10
        
        # Tailing state
        self.tail_position = 0
        
        self._update_file_stats()
    
    def _update_file_stats(self) -> None:
        """Update file statistics"""
        if self.file_path.exists():
            stat = self.file_path.stat()
            self.file_size = stat.st_size
            self.last_modified = stat.st_mtime
    
    def has_changed(self) -> bool:
        """
        Check if file has been modified since last read
        
        Returns:
            True if file has changed
        """
        if not self.file_path.exists():
            return False
        
        stat = self.file_path.stat()
        return stat.st_mtime > self.last_modified or stat.st_size != self.file_size
    
    def count_lines(self) -> int:
        """
        Count total lines in file efficiently
        
        Returns:
            Total number of lines
        """
        if not self.file_path.exists():
            return 0
        
        try:
            with open(self.file_path, 'rb') as f:
                count = sum(1 for _ in f)
            self.total_lines = count
            return count
        except Exception:
            return 0
    
    def read_chunk(self, start_line: int = 1, num_lines: Optional[int] = None) -> List[LogEntry]:
        """
        Read a chunk of log lines starting from specified line
        
        Args:
            start_line: Starting line number (1-based)
            num_lines: Number of lines to read (None = chunk_size)
            
        Returns:
            List of parsed LogEntry objects
        """
        if num_lines is None:
            num_lines = self.chunk_size
        
        # Check cache first
        cache_key = (start_line, num_lines)
        if cache_key in self.cached_chunks and not self.has_changed():
            return self.cached_chunks[cache_key]
        
        if not self.file_path.exists():
            return []
        
        try:
            entries = []
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip to start line
                for _ in range(start_line - 1):
                    next(f, None)
                
                # Read the chunk
                lines = []
                for i in range(num_lines):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                
                # Parse lines
                entries = self.parser.parse_lines(lines, start_line)
            
            # Cache the result
            self._add_to_cache(cache_key, entries)
            self._update_file_stats()
            
            return entries
            
        except Exception as e:
            print(f"Error reading log file {self.file_path}: {e}")
            return []
    
    def read_all(self) -> List[LogEntry]:
        """
        Read entire file (use with caution for large files)
        
        Returns:
            List of all LogEntry objects
        """
        if not self.file_path.exists():
            return []
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            entries = self.parser.parse_lines(lines, 1)
            self._update_file_stats()
            return entries
            
        except Exception as e:
            print(f"Error reading log file {self.file_path}: {e}")
            return []
    
    def read_last_n_lines(self, n: int = 100) -> List[LogEntry]:
        """
        Read last N lines efficiently (for tailing)
        
        Args:
            n: Number of lines to read from end
            
        Returns:
            List of last N LogEntry objects
        """
        if not self.file_path.exists():
            return []
        
        try:
            # Use deque to efficiently keep only last N lines
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = deque(f, maxlen=n)
            
            # Calculate starting line number
            total = self.count_lines()
            start_line = max(1, total - n + 1)
            
            entries = self.parser.parse_lines(list(lines), start_line)
            self._update_file_stats()
            self.tail_position = self.file_size
            
            return entries
            
        except Exception as e:
            print(f"Error reading last lines from {self.file_path}: {e}")
            return []
    
    def tail(self) -> List[LogEntry]:
        """
        Read new lines added since last tail operation
        
        Returns:
            List of new LogEntry objects
        """
        if not self.file_path.exists():
            return []
        
        try:
            current_size = self.file_path.stat().st_size
            
            # No new content
            if current_size <= self.tail_position:
                return []
            
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to last position
                f.seek(self.tail_position)
                new_lines = f.readlines()
                self.tail_position = f.tell()
            
            if not new_lines:
                return []
            
            # Calculate starting line number
            total = self.count_lines()
            start_line = total - len(new_lines) + 1
            
            entries = self.parser.parse_lines(new_lines, start_line)
            self._update_file_stats()
            
            return entries
            
        except Exception as e:
            print(f"Error tailing log file {self.file_path}: {e}")
            return []
    
    def search(self, query: str, case_sensitive: bool = False, max_results: int = 1000) -> List[LogEntry]:
        """
        Search for entries containing query string (optimized with early exit)
        
        Args:
            query: Search string
            case_sensitive: Whether search is case-sensitive
            max_results: Maximum number of results to return (for performance)
            
        Returns:
            List of matching LogEntry objects
        """
        if not query:
            return []
        
        search_query = query if case_sensitive else query.lower()
        matching_entries = []
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, start=1):
                    # Early exit if we have enough results
                    if len(matching_entries) >= max_results:
                        break
                    
                    search_line = line if case_sensitive else line.lower()
                    if search_query in search_line:
                        entry = self.parser.parse_line(line, line_num)
                        matching_entries.append(entry)
            
            return matching_entries
            
        except Exception as e:
            print(f"Error searching log file {self.file_path}: {e}")
            return []
    
    def _add_to_cache(self, key: Tuple, entries: List[LogEntry]) -> None:
        """Add entries to cache with LRU eviction (optimized)"""
        # Move to end if already exists (LRU behavior)
        if key in self.cached_chunks:
            del self.cached_chunks[key]
        
        self.cached_chunks[key] = entries
        
        # Evict oldest if cache is full
        if len(self.cached_chunks) > self.max_cached_chunks:
            # Remove first item (oldest)
            oldest_key = next(iter(self.cached_chunks))
            del self.cached_chunks[oldest_key]
    
    def clear_cache(self) -> None:
        """Clear all cached data"""
        self.cached_chunks.clear()


class LogDirectoryMonitor:
    """
    Monitor a directory for log files
    
    Features:
    - Auto-discovery of log files
    - File filtering by extension
    - Sorted file listing
    """
    
    def __init__(self, log_directory: Path, extensions: Optional[List[str]] = None):
        """
        Initialize directory monitor
        
        Args:
            log_directory: Path to log directory
            extensions: List of file extensions to monitor (default: ['.log'])
        """
        self.log_directory = Path(log_directory)
        self.extensions = extensions or ['.log']
    
    def get_log_files(self) -> List[Path]:
        """
        Get all log files in directory
        
        Returns:
            Sorted list of log file paths
        """
        if not self.log_directory.exists():
            return []
        
        log_files = []
        for ext in self.extensions:
            log_files.extend(self.log_directory.glob(f'*{ext}'))
        
        # Sort by modification time (newest first)
        log_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        return log_files
    
    def get_file_info(self, file_path: Path) -> dict:
        """
        Get information about a log file
        
        Returns:
            Dictionary with file metadata
        """
        if not file_path.exists():
            return {}
        
        stat = file_path.stat()
        return {
            'name': file_path.name,
            'size': stat.st_size,
            'size_mb': round(stat.st_size / 1024 / 1024, 2),
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'lines': sum(1 for _ in open(file_path, 'rb'))
        }