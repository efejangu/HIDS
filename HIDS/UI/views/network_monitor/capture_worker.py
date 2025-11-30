"""
Capture Worker Module - Background packet capture and IP reporting

Handles:
- Background thread for packet capture
- IP collection and processing
- Integration with ScappyIPCollector and IPReporter
- Thread-safe state management
"""
import logging
from threading import Event, Thread
from typing import Optional, Callable, Set
from scapy.all import AsyncSniffer

from HIDS.netmon.net_packet import ScappyIPCollector, get_active_interfaces
from HIDS.netmon.ip_reporter import IPReporter
from HIDS.log_analysis.alert_manager import AlertManager


class CaptureWorker:
    """Background worker for network packet capture and IP reporting"""
    
    def __init__(self, alert_manager: AlertManager, logger: logging.Logger):
        """
        Initialize the capture worker
        
        Args:
            alert_manager: AlertManager instance for threat alerting
            logger: Logger for debug and info messages
        """
        self.alert_manager = alert_manager
        self.logger = logger
        
        # Network monitoring components
        self.sniffer: Optional[AsyncSniffer] = None
        self.ip_collector: Optional[ScappyIPCollector] = None
        self.ip_reporter: Optional[IPReporter] = None
        
        # Thread management
        self.stop_event = Event()
        self.sniffer_thread: Optional[Thread] = None
        self.is_capturing = False
        
        # Track displayed IPs
        self.displayed_ips: Set[str] = set()
    
    def start_capture(self) -> tuple[bool, str]:
        """
        Start network packet capture
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if self.is_capturing:
            return False, "Capture already running"
        
        try:
            self.logger.info("Starting network capture process...")
            
            # Initialize Scapy components
            self.sniffer = AsyncSniffer()
            self.ip_collector = ScappyIPCollector(self.sniffer)
            self.logger.info("ScappyIPCollector initialized")
            
            # Initialize IPReporter with AlertManager
            self.ip_reporter = IPReporter(
                ip_collector=self.ip_collector,
                alert_manager=self.alert_manager
            )
            self.logger.info("IPReporter initialized")
            
            # Get active network interfaces (excluding loopback)
            active_interfaces = get_active_interfaces()
            self.logger.info(f"Found {len(active_interfaces)} active interfaces: {active_interfaces}")
            
            if not active_interfaces:
                self.logger.error("No active network interfaces available for capture")
                return False, "No active network interfaces found"
            
            self.logger.info(f"Starting capture on interfaces: {active_interfaces}")
            
            # Start packet capture in background thread
            self.stop_event.clear()
            self.sniffer_thread = Thread(
                target=self.ip_collector.start_sniffer,
                args=(self.stop_event, active_interfaces),
                daemon=True
            )
            self.sniffer_thread.start()
            self.logger.info("Sniffer thread started")
            
            # Start IP processing
            self.ip_reporter.start()
            self.logger.info("IPReporter started")
            
            self.is_capturing = True
            self.logger.info(f"Capture status set to: {self.is_capturing}")
            
            message = f"Network capture started on {len(active_interfaces)} interface(s): {', '.join(active_interfaces)}"
            self.logger.info(f"Network capture fully initialized on interfaces: {active_interfaces}")
            
            return True, message
            
        except Exception as e:
            self.logger.error(f"Error starting capture: {e}", exc_info=True)
            return False, f"Failed to start capture: {str(e)}"
    
    def stop_capture(self) -> tuple[bool, str]:
        """
        Stop network packet capture
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_capturing:
            return False, "No capture running"
        
        try:
            # Stop IP reporter first
            if self.ip_reporter:
                self.ip_reporter.stop()
            
            # Signal sniffer to stop
            self.stop_event.set()
            
            # Wait for sniffer thread to finish (with timeout)
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=3)
            
            self.is_capturing = False
            
            self.logger.info("Network capture stopped")
            return True, "Network capture stopped"
            
        except Exception as e:
            self.logger.error(f"Error stopping capture: {e}", exc_info=True)
            return False, f"Failed to stop capture: {str(e)}"
    
    def get_new_ips(self, update_callback: Callable[[str, bool, str], None]) -> int:
        """
        Get newly processed IPs from IPReporter and update UI
        
        Args:
            update_callback: Function to call for each new IP (ip, is_malicious, details)
            
        Returns:
            Number of new IPs added
        """
        if not self.is_capturing or not self.ip_reporter:
            return 0
        
        try:
            # Get processed IPs from IPReporter
            processed_ips = self.ip_reporter.processed_ips.copy()
            self.logger.debug(f"Processed IPs from IPReporter: {len(processed_ips)} total, displayed: {len(self.displayed_ips)}")
            
            # Add new IPs
            new_ips_count = 0
            for ip in processed_ips:
                if ip not in self.displayed_ips:
                    new_ips_count += 1
                    self.displayed_ips.add(ip)
                    
                    # For now, mark all as non-malicious (VirusTotal checking happens in IPReporter)
                    # In production, you might want to cross-reference with alert_manager
                    is_malicious = False
                    details = "Checked with VirusTotal"
                    
                    # Call the update callback
                    update_callback(ip, is_malicious, details)
                    self.logger.info(f"Added new IP to UI table: {ip}")
            
            if new_ips_count > 0:
                self.logger.info(f"Added {new_ips_count} new IPs to display")
            
            return new_ips_count
            
        except Exception as e:
            self.logger.error(f"Error getting new IPs: {e}", exc_info=True)
            return 0
    
    def get_stats(self) -> tuple[int, int]:
        """
        Get current capture statistics
        
        Returns:
            Tuple of (packets_captured, threats_detected)
        """
        packets_captured = len(self.displayed_ips)
        threats_detected = self.alert_manager.number_of_alerts if self.alert_manager else 0
        
        return packets_captured, threats_detected
    
    def clear_displayed_ips(self) -> None:
        """Clear the set of displayed IPs"""
        self.displayed_ips.clear()
    
    def cleanup(self) -> None:
        """Cleanup resources when worker is destroyed"""
        if self.is_capturing:
            try:
                if self.ip_reporter:
                    self.ip_reporter.stop()
                self.stop_event.set()
            except Exception as e:
                self.logger.error(f"Error during cleanup: {e}", exc_info=True)