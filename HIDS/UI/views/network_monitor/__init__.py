"""
Network Monitor Package - Modular network monitoring system

This package provides a high-performance, modular network monitoring interface with:
- Background packet capture and IP reporting
- VirusTotal threat intelligence integration
- Real-time traffic analysis
- Thread-safe UI updates

Package Structure:
- components: UI panels and controls (NetworkStatsPanel, NetworkControlPanel, ThreatDetailsPanel)
- network_table: Network traffic table widget (NetworkTrafficTable)
- capture_worker: Background packet capture (CaptureWorker)
- view: Main view orchestration (NetworkMonitorView)
"""

# Import main view for backward compatibility
from .view import NetworkMonitorView

# Import components for external use
from .components import NetworkStatsPanel, NetworkControlPanel, ThreatDetailsPanel
from .network_table import NetworkTrafficTable
from .capture_worker import CaptureWorker

__all__ = [
    # Main view
    'NetworkMonitorView',
    
    # UI components
    'NetworkStatsPanel',
    'NetworkControlPanel',
    'ThreatDetailsPanel',
    'NetworkTrafficTable',
    
    # Core components
    'CaptureWorker',
]