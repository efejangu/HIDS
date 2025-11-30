"""
Network Traffic Table Module - DataTable for displaying network traffic and threats

Handles:
- Network traffic table display and formatting
- IP entry management
- Threat level visualization
"""
from datetime import datetime
from rich.text import Text
from textual.widgets import DataTable


class NetworkTrafficTable(DataTable):
    """Table showing network traffic and threats"""
    
    def on_mount(self) -> None:
        """Initialize the network traffic table"""
        self.add_columns(
            "Time",
            "IP Address",
            "Status",
            "Threat Level",
            "Details"
        )
        
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.show_cursor = True
    
    def add_ip_entry(
        self,
        ip_address: str,
        is_malicious: bool,
        details: str = ""
    ) -> None:
        """
        Add a new IP entry to the table
        
        Args:
            ip_address: IP address to add
            is_malicious: Whether the IP is malicious
            details: Additional details about the IP
        """
        if is_malicious:
            status = Text("⚠ Malicious", style="red bold")
            threat_level = Text("High", style="red bold")
        else:
            status = Text("✓ Clean", style="green")
            threat_level = Text("Low", style="green")
        
        self.add_row(
            datetime.now().strftime("%H:%M:%S"),
            ip_address,
            status,
            threat_level,
            details[:50] if details else "Processing...",
            key=f"ip_{datetime.now().timestamp()}"
        )