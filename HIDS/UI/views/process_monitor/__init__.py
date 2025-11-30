"""
Process Monitor Package - Modular process monitoring system

This package provides a high-performance, modular process monitoring interface with:
- Background threat detection
- Caching layer for expensive operations
- Lazy loading and differential updates
- Thread-safe UI updates

Package Structure:
- cache: Process data caching (ProcessCache)
- threat_worker: Background threat detection (ThreatDetectionWorker)
- process_analyzer: Lazy loading operations (ProcessAnalyzer)
- components: UI panels and controls (ProcessSearchPanel, ProcessControlPanel, ProcessDetailsPanel)
- process_table: Process table widget (ProcessMonitorTable)
- view: Main view orchestration (ProcessMonitorView)
"""

# Import main view for backward compatibility
from .view import ProcessMonitorView

# Import components for external use
from .cache import ProcessCache
from .threat_worker import ThreatDetectionWorker
from .process_analyzer import ProcessAnalyzer
from .components import ProcessSearchPanel, ProcessControlPanel, ProcessDetailsPanel
from .process_table import ProcessMonitorTable

__all__ = [
    # Main view
    'ProcessMonitorView',
    
    # Core components
    'ProcessCache',
    'ThreatDetectionWorker',
    'ProcessAnalyzer',
    
    # UI components
    'ProcessSearchPanel',
    'ProcessControlPanel',
    'ProcessDetailsPanel',
    'ProcessMonitorTable',
]