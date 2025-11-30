"""
Process Monitor View - Backward Compatibility Wrapper

This module maintains backward compatibility by re-exporting from the new
modular process_monitor package structure.

For new code, import directly from the package:
    from HIDS.UI.views.process_monitor import ProcessMonitorView
"""

# Re-export all components from the new modular structure
from .process_monitor import (
    ProcessMonitorView,
    ProcessCache,
    ThreatDetectionWorker,
    ProcessAnalyzer,
    ProcessSearchPanel,
    ProcessControlPanel,
    ProcessDetailsPanel,
    ProcessMonitorTable,
)

__all__ = [
    'ProcessMonitorView',
    'ProcessCache',
    'ThreatDetectionWorker',
    'ProcessAnalyzer',
    'ProcessSearchPanel',
    'ProcessControlPanel',
    'ProcessDetailsPanel',
    'ProcessMonitorTable',
]