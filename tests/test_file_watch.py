import pytest
import os
import time
import tempfile
import shutil # For directory cleanup
from unittest.mock import patch, MagicMock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from HIDS.sysmon.file_watch import FileCreationHandler

# Fixture for temporary directory management
@pytest.fixture
def temp_dir_manager(request):
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="watch_test_")
    
    # Function to clean up the directory
    def cleanup_dir():
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            
    # Register the cleanup function to be called after the test
    request.addfinalizer(cleanup_dir)
    
    # Yield the temporary directory path
    return temp_dir

# Fixtures for handlers
@pytest.fixture
def handler_no_filter():
    return FileCreationHandler()

@pytest.fixture
def handler_with_filter():
    return FileCreationHandler(monitored_extensions=['.txt', '.log'])

class TestFileCreationHandlerWithObserver:

    @patch('builtins.print')
    def test_on_created_directory(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1) # Give observer time to start

        dir_path = os.path.join(base_dir, "new_dir_created")
        os.makedirs(dir_path)
        time.sleep(0.5) # Give observer time to detect

        mock_print.assert_any_call(f"Directory created: {dir_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_created_file_no_filter(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        file_path = os.path.join(base_dir, "test_file_no_filter.dat")
        with open(file_path, "w") as f:
            f.write("some data")
        time.sleep(0.5)

        mock_print.assert_any_call(f"File created with extension .dat: {file_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_created_file_with_filter_match(self, mock_print, handler_with_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_with_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        file_path = os.path.join(base_dir, "test_file_match.txt")
        with open(file_path, "w") as f:
            f.write("some data")
        time.sleep(0.5)

        mock_print.assert_any_call(f"File created with extension .txt: {file_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_created_file_with_filter_no_match(self, mock_print, handler_with_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_with_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        file_path = os.path.join(base_dir, "test_file_no_match.py")
        with open(file_path, "w") as f:
            f.write("some data")
        time.sleep(0.5)

        # Assert that no print call was made for this file
        all_calls = mock_print.call_args_list
        # The original assertion failed because 'any' returned True, meaning a print call happened.
        # We need to assert that NO such call happened.
        assert not any(f"File created with extension .py: {file_path}" in str(call) for call in all_calls)
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_modified_directory(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        dir_path = os.path.join(base_dir, "dir_to_modify")
        os.makedirs(dir_path)
        time.sleep(0.2) # Ensure directory exists before modifying
        
        # Modify the directory (e.g., by touching it again)
        os.utime(dir_path, None) 
        time.sleep(0.5)

        mock_print.assert_any_call(f"Directory modified: {dir_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_modified_file(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        file_path = os.path.join(base_dir, "file_to_modify.txt")
        with open(file_path, "w") as f:
            f.write("initial content")
        time.sleep(0.2) # Ensure file exists

        with open(file_path, "w") as f:
            f.write("modified content")
        time.sleep(0.5)

        mock_print.assert_any_call(f"File modified: {file_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_deleted_directory(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        dir_path = os.path.join(base_dir, "dir_to_delete")
        os.makedirs(dir_path)
        time.sleep(0.2) # Ensure directory exists

        os.rmdir(dir_path)
        time.sleep(0.5)

        mock_print.assert_any_call(f"Directory deleted: {dir_path}")
        
        obs.stop()
        obs.join()

    @patch('builtins.print')
    def test_on_deleted_file(self, mock_print, handler_no_filter, temp_dir_manager):
        base_dir = temp_dir_manager
        handler = handler_no_filter
        
        obs = Observer()
        obs.schedule(handler, base_dir, recursive=True)
        obs.start()
        time.sleep(0.1)

        file_path = os.path.join(base_dir, "file_to_delete.txt")
        with open(file_path, "w") as f:
            f.write("content to delete")
        time.sleep(0.2) # Ensure file exists

        os.remove(file_path)
        time.sleep(0.5)

        mock_print.assert_any_call(f"File deleted: {file_path}")
        
        obs.stop()
        obs.join()
