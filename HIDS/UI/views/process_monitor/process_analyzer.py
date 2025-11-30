"""
Process Analyzer Module - Lazy loading of expensive process data

Handles:
- Network connections loading
- Memory maps/modules loading
- Process details extraction
"""
import psutil
from typing import List, Dict
from pathlib import Path

from HIDS.util import hash_file
from HIDS.threat_detector.threat_detector import is_file_malicious

from .cache import ProcessCache


class ProcessAnalyzer:
    """Handles lazy loading of expensive process analysis operations"""
    
    @staticmethod
    def load_connections(pid: int) -> List[Dict]:
        """
        Lazy load network connections for a process
        
        Args:
            pid: Process ID
            
        Returns:
            List of connection dictionaries
        """
        try:
            proc = psutil.Process(pid)
            connections = []
            for conn in proc.connections():
                if conn.status != 'NONE':
                    conn_info = {
                        'type': conn.type.name if hasattr(conn, 'type') else 'N/A',
                        'status': conn.status,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'
                    }
                    connections.append(conn_info)
            return connections
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    @staticmethod
    def load_modules(pid: int, max_modules: int = 10) -> List[str]:
        """
        Lazy load memory maps/modules for a process
        
        Args:
            pid: Process ID
            max_modules: Maximum number of modules to return
            
        Returns:
            List of module paths
        """
        try:
            proc = psutil.Process(pid)
            if hasattr(proc, 'memory_maps'):
                modules = []
                for mmap in proc.memory_maps():
                    if mmap.path and mmap.path not in modules:
                        modules.append(mmap.path)
                        if len(modules) >= max_modules:
                            break
                return modules
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return []
    
    @staticmethod
    def get_process_hash(exe_path: str, cache: ProcessCache) -> str:
        """
        Get or compute file hash with caching
        
        Args:
            exe_path: Path to executable
            cache: ProcessCache instance
            
        Returns:
            File hash or error message
        """
        if not exe_path or not Path(exe_path).exists():
            return 'N/A'
        
        # Check cache first
        hash_val = cache.get_hash(exe_path)
        if hash_val is not None:
            return hash_val
        
        # Compute and cache
        try:
            hash_val = hash_file(exe_path)
            cache.set_hash(exe_path, hash_val)
            return hash_val
        except Exception:
            return 'Error computing hash'
    
    @staticmethod
    def check_threat_status(file_hash: str) -> str:
        """
        Check if file hash is malicious
        
        Args:
            file_hash: File hash to check
            
        Returns:
            Threat status string
        """
        if file_hash in ['N/A', 'Error computing hash']:
            return 'Not scanned'
        
        try:
            if is_file_malicious(file_hash):
                return '[red]MALICIOUS[/red]'
            else:
                return '[green]Safe[/green]'
        except Exception:
            return 'Check failed'