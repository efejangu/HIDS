"""
Network Monitor View Module - Main UI orchestration

Handles:
- Main view composition and layout
- Network capture control
- Event handlers for UI interactions
- Integration with background capture worker
- Periodic UI updates
"""
import logging
from pathlib import Path
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Label, DataTable, Button
from textual.timer import Timer
from textual import on

from HIDS.log_analysis.alert_manager import AlertManager
from HIDS.log_analysis.alert import alert_queue

from .components import NetworkStatsPanel, NetworkControlPanel, ThreatDetailsPanel
from .network_table import NetworkTrafficTable
from .capture_worker import CaptureWorker


class NetworkMonitorView(Vertical):
    """Network monitor view showing network activity"""
    
    def __init__(self, *args, **kwargs):
        """Initialize the network monitor view"""
        super().__init__(*args, **kwargs)
        
        # Set up logging with file handler
        self.logger = logging.getLogger('NetworkMonitor')
        self.logger.setLevel(logging.DEBUG)
        
        # Create file handler if not already exists
        if not self.logger.handlers:
            ui_dir = Path(__file__).parent.parent.parent
            log_dir = ui_dir / "app_log"
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "network_monitor.log"
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        self.logger.info("NetworkMonitorView initialized")
        
        # Initialize components
        self.alert_manager: AlertManager = None
        self.capture_worker: CaptureWorker = None
        self.update_timer: Timer = None
    
    def compose(self) -> ComposeResult:
        """Compose the network monitor view"""
        # Top controls
        with Horizontal(id="network-controls"):
            yield NetworkControlPanel(id="network-control-panel")
            yield NetworkStatsPanel(id="network-stats-panel")
        
        # Main content - split pane
        with Horizontal(id="network-monitor-content"):
            # Main table (70%)
            with Vertical(classes="main-panel"):
                yield Label("[bold]Network Traffic Log[/bold]", classes="section-title")
                yield NetworkTrafficTable(id="network-traffic-table")
            
            # Right details panel (30%)
            yield ThreatDetailsPanel(classes="right-panel", id="threat-details-panel")
    
    def on_mount(self) -> None:
        """Initialize components when view is mounted"""
        # Initialize AlertManager with shared queue
        self.alert_manager = AlertManager(queue=alert_queue)
        
        # Initialize capture worker
        self.capture_worker = CaptureWorker(self.alert_manager, self.logger)
        
        # Set up periodic UI update (every 2 seconds)
        self.update_timer = self.set_interval(2.0, self.update_ui_from_capture_worker)
    
    def update_ui_from_capture_worker(self) -> None:
        """Periodically update UI with data from CaptureWorker"""
        if not self.capture_worker:
            return
        
        self.logger.debug(f"update_ui_from_capture_worker called - is_capturing: {self.capture_worker.is_capturing}")
        
        if not self.capture_worker.is_capturing:
            self.logger.debug("Skipping UI update - not capturing")
            return
        
        try:
            # Get table reference
            table = self.query_one("#network-traffic-table", NetworkTrafficTable)
            
            # Define callback for adding new IPs to table
            def add_to_table(ip: str, is_malicious: bool, details: str) -> None:
                table.add_ip_entry(ip, is_malicious, details)
            
            # Get new IPs from capture worker
            new_count = self.capture_worker.get_new_ips(add_to_table)
            
            # Update stats panel
            stats_panel = self.query_one("#network-stats-panel", NetworkStatsPanel)
            packets_captured, threats_detected = self.capture_worker.get_stats()
            stats_panel.packets_captured = packets_captured
            stats_panel.threats_detected = threats_detected
            
        except Exception as e:
            self.logger.error(f"Error updating UI from CaptureWorker: {e}", exc_info=True)
    
    @on(Button.Pressed, "#start-capture-btn")
    def handle_start_capture(self) -> None:
        """Handle start capture button"""
        success, message = self.capture_worker.start_capture()
        
        if success:
            # Update button states
            self.query_one("#start-capture-btn", Button).disabled = True
            self.query_one("#stop-capture-btn", Button).disabled = False
            self.notify(message, severity="information")
        else:
            self.notify(message, severity="error")
    
    @on(Button.Pressed, "#stop-capture-btn")
    def handle_stop_capture(self) -> None:
        """Handle stop capture button"""
        success, message = self.capture_worker.stop_capture()
        
        if success:
            # Update button states
            self.query_one("#start-capture-btn", Button).disabled = False
            self.query_one("#stop-capture-btn", Button).disabled = True
            self.notify(message, severity="warning")
        else:
            self.notify(message, severity="error")
    
    @on(Button.Pressed, "#clear-history-btn")
    def handle_clear_history(self) -> None:
        """Handle clear history button"""
        table = self.query_one("#network-traffic-table", NetworkTrafficTable)
        table.clear()
        
        # Clear displayed IPs in capture worker
        self.capture_worker.clear_displayed_ips()
        
        # Update stats
        stats_panel = self.query_one("#network-stats-panel", NetworkStatsPanel)
        stats_panel.packets_captured = 0
        
        self.notify("Traffic history cleared", severity="information")
    
    @on(DataTable.RowSelected, "#network-traffic-table")
    def handle_traffic_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in traffic table"""
        row_data = event.data_table.get_row(event.row_key)
        
        # Update details panel
        details_panel = self.query_one("#threat-details-panel", ThreatDetailsPanel)
        details_panel.update_details(row_data)
    
    def on_unmount(self) -> None:
        """Cleanup when view is unmounted"""
        if self.capture_worker:
            self.capture_worker.cleanup()