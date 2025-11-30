import pytest
from unittest.mock import MagicMock, patch
from queue import Queue
from threading import Event
from HIDS.netmon.net_packet import ScappyIPCollector
from scapy.layers.inet import IP

# Mock Scapy's AsyncSniffer and IP layer for testing
class MockIP:
    def __init__(self, dst):
        self.dst = dst

class MockPacket:
    def __init__(self, dst_ip=None):
        self._dst_ip = dst_ip

    def haslayer(self, layer):
        # Check for both the real IP class from scapy and MockIP
        return (layer == IP or layer == MockIP) and self._dst_ip is not None

    def __getitem__(self, layer):
        if layer == IP or layer == MockIP:
            return MockIP(self._dst_ip)
        raise KeyError(f"Layer {layer} not found")

@pytest.fixture
def mock_async_sniffer():
    return MagicMock()

@pytest.fixture
def ip_collector(mock_async_sniffer):
    return ScappyIPCollector(mock_async_sniffer)

def test_scappy_ip_collector_initialization(mock_async_sniffer):
    """
    Test that ScappyIPCollector initializes correctly.
    """
    collector = ScappyIPCollector(mock_async_sniffer)
    assert collector.scappy_sniiffer == mock_async_sniffer
    assert isinstance(collector.queue, Queue)
    assert collector.queue.empty()
    assert collector._prev_ip is None

def test_get_queue_empty(ip_collector):
    """
    Test get_queue always returns the queue object, even when empty.
    """
    queue = ip_collector.get_queue()
    assert queue is not None
    assert queue == ip_collector.queue
    assert queue.empty()

def test_get_queue_with_items(ip_collector):
    """
    Test get_queue always returns the same queue object.
    """
    ip_collector.queue.put("192.168.1.1")
    queue = ip_collector.get_queue()
    assert queue is not None
    assert queue == ip_collector.queue
    assert not queue.empty()

@pytest.mark.parametrize("ip_address", ["192.168.1.1", "192.168.1.2", "10.0.0.1"])
def test_add_ip_unique_addresses(ip_collector, ip_address):
    """
    Test add_ip with unique IP addresses.
    """
    packet = MockPacket(dst_ip=ip_address)
    ip_collector.add_ip(packet)
    assert ip_collector.queue.get() == ip_address
    assert ip_collector._prev_ip == ip_address
    assert ip_collector.queue.empty()

def test_add_ip_duplicate_addresses(ip_collector):
    """
    Test add_ip to ensure duplicate consecutive IP addresses are not added.
    """
    packet1 = MockPacket(dst_ip="192.168.1.1")
    packet2 = MockPacket(dst_ip="192.168.1.1") # Duplicate
    packet3 = MockPacket(dst_ip="192.168.1.2")

    ip_collector.add_ip(packet1)
    assert ip_collector.queue.get() == "192.168.1.1"
    assert ip_collector._prev_ip == "192.168.1.1"
    assert ip_collector.queue.empty()

    ip_collector.add_ip(packet2) # Should not be added
    assert ip_collector.queue.empty()
    assert ip_collector._prev_ip == "192.168.1.1"

    ip_collector.add_ip(packet3)
    assert ip_collector.queue.get() == "192.168.1.2"
    assert ip_collector._prev_ip == "192.168.1.2"
    assert ip_collector.queue.empty()

def test_add_ip_no_ip_layer(ip_collector):
    """
    Test add_ip with a packet that does not have an IP layer.
    """
    mock_pkt_no_ip = MagicMock()
    mock_pkt_no_ip.haslayer.return_value = False

    ip_collector.add_ip(mock_pkt_no_ip)
    assert ip_collector.queue.empty()
    assert ip_collector._prev_ip is None

@patch('HIDS.netmon.net_packet.AsyncSniffer')
def test_start_sniffer(mock_async_sniffer_class, ip_collector):
    """
    Test start_sniffer method, ensuring AsyncSniffer is started and stopped correctly.
    """
    mock_event = MagicMock(spec=Event)
    mock_interface = "eth0"

    # Mock an instance of AsyncSniffer
    mock_sniffer_instance = MagicMock()
    mock_async_sniffer_class.return_value = mock_sniffer_instance
    
    # Configure mock_event.wait to return immediately (must be before start_sniffer call)
    mock_event.wait.return_value = True

    ip_collector.start_sniffer(mock_event, mock_interface)

    # Assert AsyncSniffer was initialized with correct parameters
    mock_async_sniffer_class.assert_called_once_with(
        prn=ip_collector.add_ip,
        iface=mock_interface
    )
    # Assert sniffer was started
    mock_sniffer_instance.start.assert_called_once()
    # Assert event.wait() was called
    mock_event.wait.assert_called_once()
    # Assert sniffer was stopped after event.wait()
    mock_sniffer_instance.stop.assert_called_once()
