"""
UI Components Module - Reusable UI panels and controls for network monitoring

Handles:
- Network statistics panel
- Threat details panel
- Network control panel (buttons)
"""
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, Label, Button
from textual.reactive import reactive


class NetworkStatsPanel(Static):
    """Panel showing network statistics"""
    
    packets_captured = reactive(0)
    threats_detected = reactive(0)
    connections_active = reactive(0)
    
    def compose(self) -> ComposeResult:
        yield Label("[bold]Network Statistics[/bold]", classes="panel-title")
        yield Static(
            f"Packets Captured: {self.packets_captured}\n"
            f"Threats Detected: {self.threats_detected}\n"
            f"Active Connections: {self.connections_active}",
            id="network-stats"
        )
    
    def watch_packets_captured(self, new_value: int) -> None:
        """Update display when packets_captured changes"""
        self._update_stats_display()
    
    def watch_threats_detected(self, new_value: int) -> None:
        """Update display when threats_detected changes"""
        self._update_stats_display()
    
    def watch_connections_active(self, new_value: int) -> None:
        """Update display when connections_active changes"""
        self._update_stats_display()
    
    def _update_stats_display(self) -> None:
        """Update the stats display widget"""
        try:
            stats_widget = self.query_one("#network-stats", Static)
            stats_widget.update(
                f"Packets Captured: {self.packets_captured}\n"
                f"Threats Detected: {self.threats_detected}\n"
                f"Active Connections: {self.connections_active}"
            )
        except Exception:
            # Widget might not be mounted yet
            pass


class NetworkControlPanel(Horizontal):
    """Control panel for network capture operations"""
    
    def compose(self) -> ComposeResult:
        """Compose the control panel"""
        yield Button("Start Capture", variant="success", id="start-capture-btn")
        yield Button("Stop Capture", variant="error", id="stop-capture-btn", disabled=True)
        yield Button("Clear History", variant="warning", id="clear-history-btn")


class ThreatDetailsPanel(Vertical):
    """Panel showing details of selected threat"""
    
    def compose(self) -> ComposeResult:
        """Compose the threat details panel"""
        yield Label("[bold]Threat Details[/bold]", classes="panel-title")
        yield Static(
            "Select a connection from the table to view details...",
            id="threat-details-content",
            classes="details-display"
        )
    
    def update_details(self, row_data: tuple) -> None:
        """
        Update the threat details display
        
        Args:
            row_data: Tuple of (time, ip_address, status, threat_level, details)
        """
        details = f"""
[bold]Time:[/bold] {row_data[0]}
[bold]IP Address:[/bold] {row_data[1]}
[bold]Status:[/bold] {row_data[2]}
[bold]Threat Level:[/bold] {row_data[3]}
[bold]Details:[/bold] {row_data[4]}

[dim]IP analyzed using VirusTotal threat intelligence[/dim]
        """
        
        try:
            details_widget = self.query_one("#threat-details-content", Static)
            details_widget.update(details.strip())
        except Exception:
            # Widget might not be mounted yet
            pass