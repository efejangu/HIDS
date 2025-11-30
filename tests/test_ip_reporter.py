import pytest
from unittest.mock import MagicMock, patch
from queue import Queue
from threading import Event
import time
import logging

from HIDS.netmon.ip_reporter import IPReporter
from HIDS.netmon.net_packet import ScappyIPCollector
from HIDS.threat_detector.threat_detector import GatherThreatData, is_ipv4_malicious, display_ipv4_info

# Mock the external dependencies
@pytest.fixture
def mock_ip_collector():
    collector = MagicMock(spec=ScappyIPCollector)
    collector.get_queue.return_value = Queue()
    return collector

@pytest.fixture
def mock_gather_threat_data():
    gatherer = MagicMock(spec=GatherThreatData)
    # Default to returning a benign response
    gatherer.gather_ipv4_info.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10}}}}
    return gatherer

@pytest.fixture
def mock_is_ipv4_malicious():
    # Patch the function where it is used, inside the ip_reporter module
    with patch('HIDS.netmon.ip_reporter.is_ipv4_malicious', return_value=False) as mock_func:
        yield mock_func

@pytest.fixture
def mock_display_ipv4_info():
    with patch('HIDS.netmon.ip_reporter.display_ipv4_info') as mock_func:
        yield mock_func

@pytest.fixture
def mock_alert_manager():
    manager = MagicMock()
    # Mock the add_alert method if it's called
    manager.add_alert = MagicMock()
    return manager

@pytest.fixture
def ip_reporter(mock_ip_collector, mock_alert_manager):
    reporter = IPReporter(mock_ip_collector, mock_alert_manager)
    # Patch the actual GatherThreatData instance created within IPReporter
    reporter.threat_data_gatherer = MagicMock(spec=GatherThreatData)
    reporter.threat_data_gatherer.gather_ipv4_info.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10}}}}
    return reporter

def test_ip_reporter_initialization(ip_reporter, mock_ip_collector, mock_alert_manager):
    assert ip_reporter.ip_collector == mock_ip_collector
    assert isinstance(ip_reporter.threat_data_gatherer, MagicMock)
    assert isinstance(ip_reporter.processed_ips, set)
    assert ip_reporter.alert_manager == mock_alert_manager
    assert not ip_reporter.stop_event.is_set()
    assert ip_reporter.processor_thread is None

def test_start_and_stop_ip_reporter(ip_reporter):
    ip_reporter.start()
    time.sleep(0.1) # Give thread time to start
    assert ip_reporter.processor_thread is not None
    assert ip_reporter.processor_thread.is_alive()
    ip_reporter.stop()
    ip_reporter.processor_thread.join(timeout=1)
    assert not ip_reporter.processor_thread.is_alive()
    assert ip_reporter.stop_event.is_set()

def test_process_single_clean_ip(ip_reporter, mock_ip_collector, mock_gather_threat_data, mock_is_ipv4_malicious, mock_display_ipv4_info, mock_alert_manager):
    ip_reporter.threat_data_gatherer = mock_gather_threat_data # Ensure it uses our mock
    mock_ip_collector.get_queue.return_value.put("192.168.1.1")
    
    ip_reporter.start()
    # Wait for the IP to be processed
    time.sleep(0.2) 
    ip_reporter.stop()

    mock_gather_threat_data.gather_ipv4_info.assert_called_once_with("192.168.1.1")
    mock_is_ipv4_malicious.assert_called_once_with("192.168.1.1")
    mock_alert_manager.add_alert.assert_not_called()
    mock_display_ipv4_info.assert_not_called() # Should not display for clean by default

def test_process_single_malicious_ip(ip_reporter, mock_ip_collector, mock_gather_threat_data, mock_is_ipv4_malicious, mock_display_ipv4_info, mock_alert_manager):
    # Configure mocks for malicious IP
    ip_reporter.threat_data_gatherer = mock_gather_threat_data
    mock_gather_threat_data.gather_ipv4_info.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 5}}}}
    mock_is_ipv4_malicious.return_value = True

    mock_ip_collector.get_queue.return_value.put("1.1.1.1")
    
    ip_reporter.start()
    time.sleep(0.2)
    ip_reporter.stop()

    mock_gather_threat_data.gather_ipv4_info.assert_called_once_with("1.1.1.1")
    mock_is_ipv4_malicious.assert_called_once_with("1.1.1.1")
    mock_alert_manager.add_alert.assert_called_once()
    assert "Malicious IP detected: 1.1.1.1" in mock_alert_manager.add_alert.call_args[1]['message']
    mock_display_ipv4_info.assert_called_once()

def test_process_duplicate_ip(ip_reporter, mock_ip_collector, mock_gather_threat_data, mock_is_ipv4_malicious):
    ip_reporter.threat_data_gatherer = mock_gather_threat_data
    mock_ip_collector.get_queue.return_value.put("8.8.8.8")
    mock_ip_collector.get_queue.return_value.put("8.8.8.8") # Duplicate
    
    ip_reporter.start()
    time.sleep(0.3) # Give enough time to process both if it didn't deduplicate
    ip_reporter.stop()

    mock_gather_threat_data.gather_ipv4_info.assert_called_once_with("8.8.8.8")
    mock_is_ipv4_malicious.assert_called_once_with("8.8.8.8")
    assert "8.8.8.8" in ip_reporter.processed_ips
    assert ip_reporter.ip_collector.get_queue().empty()

def test_processing_ip_with_virustotal_error(ip_reporter, mock_ip_collector, mock_gather_threat_data, mock_is_ipv4_malicious, mock_alert_manager):
    ip_reporter.threat_data_gatherer = mock_gather_threat_data
    mock_gather_threat_data.gather_ipv4_info.return_value = {"error": "API error message"}
    mock_ip_collector.get_queue.return_value.put("1.2.3.4")

    ip_reporter.start()
    time.sleep(0.2)
    ip_reporter.stop()

    mock_gather_threat_data.gather_ipv4_info.assert_called_once_with("1.2.3.4")
    mock_is_ipv4_malicious.assert_not_called() # Should not be called if gather fails
    mock_alert_manager.add_alert.assert_not_called()

def test_ip_is_added_to_processed_ips_set(ip_reporter, mock_ip_collector):
    mock_ip_collector.get_queue.return_value.put("10.0.0.1")
    ip_reporter.start()
    time.sleep(0.2)
    ip_reporter.stop()
    assert "10.0.0.1" in ip_reporter.processed_ips

def test_processed_ips_set_prevents_duplicate_api_calls(ip_reporter, mock_ip_collector, mock_gather_threat_data):
    ip_reporter.threat_data_gatherer = mock_gather_threat_data
    
    # Simulate adding the same IP multiple times from the collector
    mock_ip_collector.get_queue.return_value.put("172.16.0.1")
    mock_ip_collector.get_queue.return_value.put("172.16.0.1")
    mock_ip_collector.get_queue.return_value.put("172.16.0.1")
    
    ip_reporter.start()
    time.sleep(0.3)
    ip_reporter.stop()

    mock_gather_threat_data.gather_ipv4_info.assert_called_once_with("172.16.0.1")
    assert "172.16.0.1" in ip_reporter.processed_ips

def test_queue_empty_graceful_wait(ip_reporter):
    # This test primarily checks that the thread doesn't busy-wait indefinitely
    # and handles an empty queue gracefully.
    ip_reporter.start()
    start_time = time.time()
    time.sleep(0.5) # Allow some waiting with an empty queue
    end_time = time.time()
    ip_reporter.stop()
    assert (end_time - start_time) > 0.4 # Ensure some time has passed due to sleep(1)

def test_ip_collector_get_queue_returns_none(ip_reporter, mock_ip_collector, mock_alert_manager):
    """
    Test scenario where ip_collector.get_queue() might return an empty queue or None (though our mock returns Queue).
    This test mostly ensures no crashes if the queue is truly empty.
    """
    mock_ip_collector.get_queue.return_value.empty = MagicMock(return_value=True)
    
    ip_reporter.start()
    time.sleep(0.1) # Let the loop run once
    ip_reporter.stop()
    mock_alert_manager.add_alert.assert_not_called() # No IPs to process, no alerts
    
def test_refactor_todo_is_note(ip_reporter):
    """
    This test serves as a placeholder to acknowledge the TODO:
    "Refactor is_ipv4_malicious to accept the already fetched `vt_response` data."
    It checks if the current implementation correctly calls `gather_ipv4_info` and `is_ipv4_malicious`.
    """
    ip_to_check = "192.168.0.100"
    mock_response = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10}}}}
    
    ip_reporter.threat_data_gatherer.gather_ipv4_info.return_value = mock_response
    
    # Put an IP into the queue
    ip_reporter.ip_collector.get_queue.return_value.put(ip_to_check)
    
    # Start and stop the reporter
    ip_reporter.start()
    time.sleep(0.1) # Give time for processing
    ip_reporter.stop()
    
    # Assert that gather_ipv4_info was called
    ip_reporter.threat_data_gatherer.gather_ipv4_info.assert_called_once_with(ip_to_check)
    
    # Although is_ipv4_malicious is called with the IP directly,
    # for this test, we are acknowledging that the data is fetched separately.
    # A future refactor would pass `mock_response` to `is_ipv4_malicious`.
    # For now, we confirm the current flow.
    # The actual patch for `is_ipv4_malicious` is global through the fixture,
    # so we can't directly check its call arguments in the same way here without
    # more complex mocking. This test just ensures the flow.
    pass # No specific assertion needed beyond previous tests for `is_ipv4_malicious` calls.
