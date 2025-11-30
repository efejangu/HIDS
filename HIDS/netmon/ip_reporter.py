
import logging
from queue import Queue
from threading import Thread, Event
import time
from typing import Set

from HIDS.netmon.net_packet import ScappyIPCollector
from HIDS.threat_detector.threat_detector import GatherThreatData, is_ipv4_malicious, display_ipv4_info
from HIDS.log_analysis.alert_manager import AlertManager
from HIDS.log_analysis.alert import Alert
from datetime import datetime

class IPReporter:
    def __init__(self, ip_collector: ScappyIPCollector, alert_manager: AlertManager = None):
        self.ip_collector = ip_collector
        self.threat_data_gatherer = GatherThreatData()
        self.processed_ips: Set[str] = set()
        self.stop_event = Event()
        self.processor_thread = None
        self.logger = logging.getLogger(__name__)
        self.alert_manager = alert_manager

    def _process_ips(self):
        self.logger.info("IPReporter processor thread started.")
        while not self.stop_event.is_set():
            if not self.ip_collector.get_queue().empty():
                ip = self.ip_collector.get_queue().get()
                if ip not in self.processed_ips:
                    self.processed_ips.add(ip)
                    self.logger.info(f"Processing new IP: {ip}")
                    
                    try:
                        # Gather threat data for the IP
                        vt_response = self.threat_data_gatherer.gather_ipv4_info(ip)
                        
                        if "error" in vt_response:
                            self.logger.error(f"Error checking IP {ip} with VirusTotal: {vt_response['error']}")
                            continue

                        # Determine if malicious
                        # TODO: Refactor is_ipv4_malicious to accept the already fetched `vt_response` data for efficiency.
                        malicious = is_ipv4_malicious(ip) 

                        if malicious:
                            self.logger.warning(f"Malicious IP detected: {ip}. Details: {vt_response}")
                            if self.alert_manager:
                                # Create Alert object with proper structure
                                alert = Alert(
                                    timestamp=datetime.now(),
                                    alertLevel="High",
                                    message=f"Malicious IP detected: {ip}. VT Data: {str(vt_response)}",
                                    detected_by="NetworkMonitor/VirusTotal"
                                )
                                self.alert_manager.add_alert(alert)
                            # Optionally display detailed info
                            display_ipv4_info(vt_response)
                        else:
                            self.logger.info(f"IP {ip} seems clean.")
                            # Optionally display info for clean IPs too, or just log
                            # display_ipv4_info(vt_response)

                    except Exception as e:
                        self.logger.error(f"Unhandled error processing IP {ip}: {e}", exc_info=True)
            else:
                time.sleep(1) # Wait a bit if the queue is empty to avoid busy-waiting
        self.logger.info("IPReporter processor thread stopped.")

    def start(self):
        if self.processor_thread is None or not self.processor_thread.is_alive():
            self.stop_event.clear()
            self.processor_thread = Thread(target=self._process_ips, daemon=True)
            self.processor_thread.start()
            self.logger.info("IPReporter started.")

    def stop(self):
        if self.processor_thread and self.processor_thread.is_alive():
            self.stop_event.set()
            self.processor_thread.join(timeout=5)
            if self.processor_thread.is_alive():
                self.logger.warning("IPReporter thread did not terminate gracefully.")
            self.logger.info("IPReporter stopped.")
