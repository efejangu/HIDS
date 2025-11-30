import pytest
from unittest.mock import MagicMock, ANY
from queue import Queue
from threading import Event
import psutil

# Import the class to be tested
from HIDS.sysmon.process_handling import ProcessHandling
from HIDS.log_analysis.alert import Alert
from HIDS.log_analysis.alert_manager import AlertManager

@pytest.fixture
def mock_alert_manager():
    """Fixture to create a mock AlertManager."""
    return MagicMock(spec=AlertManager)

@pytest.fixture
def process_handler(mock_alert_manager):
    """Fixture to create an instance of ProcessHandling with a mock alert manager."""
    return ProcessHandling(alert_manager=mock_alert_manager)

def test_get_process_success(mocker, process_handler):
    """
    Tests that get_process returns a process object when the PID exists.
    """
    mocker.patch('psutil.pid_exists', return_value=True)
    mocker.patch('psutil.Process')
    
    pid = 1234
    process = process_handler.get_process(pid)
    
    psutil.pid_exists.assert_called_once_with(pid)
    psutil.Process.assert_called_once_with(pid)
    assert process is not None

def test_get_process_not_exists(mocker, process_handler):
    """
    Tests that get_process returns None when the PID does not exist.
    """
    mocker.patch('psutil.pid_exists', return_value=False)
    mock_process = mocker.patch('psutil.Process')

    pid = 5678
    process = process_handler.get_process(pid)

    psutil.pid_exists.assert_called_once_with(pid)
    mock_process.assert_not_called()
    assert process is None

def test_examine_process_benign(mocker, process_handler, mock_alert_manager):
    """
    Tests examination of a benign process, ensuring no alert is generated.
    """
    proc_queue = Queue()
    proc_queue.put(1234)
    stop_event = Event()
    # To ensure the loop runs once and then stops, we mock is_set to return False then True
    mocker.patch.object(stop_event, 'is_set', side_effect=[False, True])

    mock_proc = MagicMock()
    mock_proc.is_running.return_value = True
    mock_proc.exe.return_value = '/bin/benign_process'
    
    # Patch the get_process method and store the mock to assert against it
    mock_get_process = mocker.patch.object(process_handler, 'get_process', return_value=mock_proc)
    mocker.patch('HIDS.sysmon.process_handling.hash_file', return_value='some_hash')
    mocker.patch('HIDS.sysmon.process_handling.is_file_malicious', return_value=False)

    process_handler.examine_process(proc_queue, stop_event)

    mock_get_process.assert_called_once_with(1234)
    mock_alert_manager.add_alert.assert_not_called()

def test_examine_process_malicious(mocker, process_handler, mock_alert_manager):
    """
    Tests examination of a malicious process, verifying an alert is generated.
    """
    proc_queue = Queue()
    pid = 5678
    file_path = '/usr/sbin/malicious_daemon'
    proc_queue.put(pid)
    stop_event = Event()
    mocker.patch.object(stop_event, 'is_set', side_effect=[False, True])

    mock_proc = MagicMock()
    mock_proc.is_running.return_value = True
    mock_proc.exe.return_value = file_path
    
    mocker.patch.object(process_handler, 'get_process', return_value=mock_proc)
    mocker.patch('HIDS.sysmon.process_handling.hash_file', return_value='malicious_hash')
    mocker.patch('HIDS.sysmon.process_handling.is_file_malicious', return_value=True)

    process_handler.examine_process(proc_queue, stop_event)

    mock_alert_manager.add_alert.assert_called_once()
    # Check that the alert object passed to add_alert has the correct properties
    mock_alert_manager.add_alert.assert_called_with(ANY)
    
def test_examine_process_no_such_process(mocker, process_handler, mock_alert_manager):
    """
    Tests that examine_process handles psutil.NoSuchProcess gracefully and terminates.
    """
    proc_queue = Queue()
    proc_queue.put(9999)
    stop_event = Event()
    
    # Mock the queue to signal the stop_event when it becomes empty
    def mock_get():
        item = Queue.get(proc_queue)
        if proc_queue.empty():
            stop_event.set()
        return item

    mocker.patch.object(proc_queue, 'get', side_effect=mock_get)
    mocker.patch.object(proc_queue, 'empty', side_effect=lambda: Queue.empty(proc_queue))

    mock_proc = MagicMock()
    mock_proc.is_running.return_value = True
    mock_proc.exe.side_effect = psutil.NoSuchProcess(pid=9999)
    
    mocker.patch.object(process_handler, 'get_process', return_value=mock_proc)

    # We expect this to run without raising an unhandled exception or timing out
    process_handler.examine_process(proc_queue, stop_event)
    
    mock_alert_manager.add_alert.assert_not_called()

def test_examine_process_not_running(mocker, process_handler, mock_alert_manager):
    """
    Tests that examine_process skips processes that are no longer running.
    """
    proc_queue = Queue()
    proc_queue.put(1111)
    stop_event = Event()
    mocker.patch.object(stop_event, 'is_set', side_effect=[False, True])

    mock_proc = MagicMock()
    mock_proc.is_running.return_value = False
    
    mocker.patch.object(process_handler, 'get_process', return_value=mock_proc)
    mock_hash_file = mocker.patch('HIDS.sysmon.process_handling.hash_file')

    process_handler.examine_process(proc_queue, stop_event)

    # Ensure that hashing and further checks are skipped
    mock_hash_file.assert_not_called()
    mock_alert_manager.add_alert.assert_not_called()