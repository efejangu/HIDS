"""
HIDS UI Views Package
"""

from .file_monitor import FileMonitorView
from .network_monitor import NetworkMonitorView
from .process_monitor import ProcessMonitorView

__all__ = [
    'FileMonitorView',
    'NetworkMonitorView',
    'ProcessMonitorView'
]