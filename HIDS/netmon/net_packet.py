from queue import Queue
from threading import Event
from scapy.all import AsyncSniffer, get_if_list, conf
from scapy.layers.inet import IP
from typing import Union
import logging

class ScappyIPCollector:
    def __init__(self, scappy_sniffer: AsyncSniffer):
        self.scappy_sniiffer = scappy_sniffer
        self.queue = Queue()
        self._prev_ip = None
        self.logger = logging.getLogger(__name__)
        self.logger.info("ScappyIPCollector initialized")

    def get_queue(self):
        """Always return the queue object, regardless of empty status"""
        return self.queue
    
    def add_ip(self, pkt:str):
        self.logger.debug(f"Packet received in add_ip callback")
        if pkt.haslayer(IP):
            destination_address = pkt[IP].dst
            self.logger.debug(f"IP packet detected: {destination_address}")
            
            if destination_address != self._prev_ip:
                #prevents duplicate Ips from being added to the queue
                self.queue.put(destination_address)
                self.logger.info(f"IP added to queue: {destination_address}")
                self._prev_ip = destination_address
        else:
            self.logger.debug("Packet has no IP layer")


    def start_sniffer(self, event: Event, interface: Union[str, list[str], None]):
        """
        Start packet sniffer on specified interface(s).
        
        Args:
            event: Event to signal when to stop sniffing
            interface: Network interface name, list of interfaces, or None for default
        """
        self.logger.info(f"Starting sniffer on interface(s): {interface}")
        self.sniffer = AsyncSniffer(
            prn=self.add_ip,
            iface=interface  # Scapy supports: None, 'eth0', or ['eth0', 'wlan0']
        )
        self.sniffer.start()
        self.logger.info(f"Sniffer started successfully on {interface}")
        event.wait()
        self.logger.info("Stop event received, stopping sniffer")
        self.sniffer.stop()
        self.logger.info("Sniffer stopped")


def get_available_interfaces() -> list[str]:
    """
    Get list of available network interfaces, excluding loopback.
    
    Returns:
        List of interface names (e.g., ['eth0', 'wlan0'])
    """
    return [iface for iface in get_if_list() if iface != 'lo']


def get_default_interface() -> str:
    """
    Get the default network interface used by Scapy.
    
    Returns:
        Default interface name
    """
    return conf.iface


def get_active_interfaces() -> list[str]:
    """
    Get network interfaces that are likely active (non-loopback).
    For most use cases, this provides interfaces to monitor.
    
    Returns:
        List of active interface names
    """
    return get_available_interfaces()