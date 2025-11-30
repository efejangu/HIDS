"""
Process Cache Module - Caching layer for expensive process operations

Provides thread-safe caching for:
- File hashes
- Network connections
- Loaded modules
- Threat detection status
"""
import threading
from datetime import datetime
from typing import Optional, List, Dict


class ProcessCache:
    """Thread-safe cache for expensive process operations"""
    
    def __init__(self, ttl_seconds: int = 300):
        """
        Initialize cache with TTL (time-to-live)
        
        Args:
            ttl_seconds: Cache entry lifetime in seconds (default: 5 minutes)
        """
        self.ttl = ttl_seconds
        self._hash_cache: Dict[str, tuple] = {}  # {exe_path: (hash, timestamp)}
        self._module_cache: Dict[int, tuple] = {}  # {pid: (modules, timestamp)}
        self._connection_cache: Dict[int, tuple] = {}  # {pid: (connections, timestamp)}
        self._threat_status_cache: Dict[int, tuple] = {}  # {pid: (status, timestamp)}
        self._lock = threading.Lock()
    
    def get_hash(self, exe_path: str) -> Optional[str]:
        """Get cached hash or None if expired/missing"""
        with self._lock:
            if exe_path in self._hash_cache:
                hash_val, timestamp = self._hash_cache[exe_path]
                if (datetime.now().timestamp() - timestamp) < self.ttl:
                    return hash_val
                else:
                    del self._hash_cache[exe_path]
        return None
    
    def set_hash(self, exe_path: str, hash_val: str) -> None:
        """Cache a hash value"""
        with self._lock:
            self._hash_cache[exe_path] = (hash_val, datetime.now().timestamp())
    
    def get_modules(self, pid: int) -> Optional[List[str]]:
        """Get cached modules or None if expired/missing"""
        with self._lock:
            if pid in self._module_cache:
                modules, timestamp = self._module_cache[pid]
                if (datetime.now().timestamp() - timestamp) < self.ttl:
                    return modules
                else:
                    del self._module_cache[pid]
        return None
    
    def set_modules(self, pid: int, modules: List[str]) -> None:
        """Cache modules for a process"""
        with self._lock:
            self._module_cache[pid] = (modules, datetime.now().timestamp())
    
    def get_connections(self, pid: int) -> Optional[List[Dict]]:
        """Get cached connections or None if expired/missing"""
        with self._lock:
            if pid in self._connection_cache:
                connections, timestamp = self._connection_cache[pid]
                if (datetime.now().timestamp() - timestamp) < self.ttl:
                    return connections
                else:
                    del self._connection_cache[pid]
        return None
    
    def set_connections(self, pid: int, connections: List[Dict]) -> None:
        """Cache connections for a process"""
        with self._lock:
            self._connection_cache[pid] = (connections, datetime.now().timestamp())
    
    def get_threat_status(self, pid: int) -> Optional[str]:
        """Get cached threat status or None if expired/missing"""
        with self._lock:
            if pid in self._threat_status_cache:
                status, timestamp = self._threat_status_cache[pid]
                if (datetime.now().timestamp() - timestamp) < self.ttl:
                    return status
                else:
                    del self._threat_status_cache[pid]
        return None
    
    def set_threat_status(self, pid: int, status: str) -> None:
        """Cache threat status for a process"""
        with self._lock:
            self._threat_status_cache[pid] = (status, datetime.now().timestamp())
    
    def clear(self) -> None:
        """Clear all caches"""
        with self._lock:
            self._hash_cache.clear()
            self._module_cache.clear()
            self._connection_cache.clear()
            self._threat_status_cache.clear()