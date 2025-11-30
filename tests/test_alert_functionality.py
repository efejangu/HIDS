import pytest
import queue
from unittest.mock import patch
from HIDS.log_analysis.alert_manager import AlertManager
from HIDS.log_analysis import alert

@pytest.fixture
def alert_manager():
    alert.alert_queue = queue.Queue()  # Reset the queue for each test
    return AlertManager()

def test_view_current_alert_empty_queue(alert_manager, capsys):
    alert_manager.view_current_alert()
    captured = capsys.readouterr()
    assert captured.out.strip() == "No Alerts currently"

def test_view_current_alert_with_alert(alert_manager, capsys):
    test_alert = alert.Alert(
        timestamp="2023-11-07 10:00:00",
        alertLevel="High",
        message="Suspicious activity detected",
        detected_by="ProcessMonitor",
        id="123"
    )
    alert.alert_queue.put(test_alert)
    alert_manager.view_current_alert()
    captured = capsys.readouterr()
    expected_output = "2023-11-07 10:00:00 \n alert_level:High \n Suspicious activity detected \n\n ProcessMonitor"
    assert captured.out.strip() == expected_output

def test_view_current_alert_missing_attributes(alert_manager, capsys):
    test_alert = alert.Alert(
        timestamp="2023-11-07 10:00:00",
        alertLevel="High",
        message="Suspicious activity detected",
        detected_by="Unknown",
        id="123"
    )
    alert.alert_queue.put(test_alert)
    alert_manager.view_current_alert()
    captured = capsys.readouterr()
    expected_output = "2023-11-07 10:00:00 \n alert_level:High \n Suspicious activity detected \n\n Unknown"
    assert captured.out.strip() == expected_output

def test_empty_queue_with_alerts(alert_manager):
    test_alert = alert.Alert(
        timestamp="2023-11-07 10:00:00",
        alertLevel="High",
        message="Suspicious activity detected",
        detected_by="ProcessMonitor",
        id="123"
    )
    alert.alert_queue.put(test_alert)
    alert_manager.empty_queue()
    assert alert.alert_queue.empty()

def test_empty_queue_empty_queue(alert_manager):
    alert_manager.empty_queue()
    assert alert.alert_queue.empty()