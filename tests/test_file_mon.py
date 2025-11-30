import uuid
import pytest
import os
import time
import tempfile
import shutil
import hashlib
import sqlite3
from unittest.mock import patch, MagicMock

# Import from the actual project structure
from HIDS.database.database import Database
from HIDS.sysmon.file_mon import FileMonitoringSystem, NoFilenameError

# --- Fixtures ---

@pytest.fixture
def temp_dir_manager(request):
    """Fixture to manage temporary directories for tests."""
    temp_dir = tempfile.mkdtemp(prefix="fms_test_")
    
    def cleanup_dir():
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            
    request.addfinalizer(cleanup_dir)
    return temp_dir

@pytest.fixture
def mock_db_instance(temp_dir_manager):
    """
    Provides a mock Database instance that uses a temporary DB file.
    This avoids interfering with the actual HIDS.db.
    """
    db_path = os.path.join(temp_dir_manager, "test_HIDS.db")
    
    class MockDatabase:
        def __init__(self, db_path):
            self.db_path = db_path
            self.conn = None
            self.cursor = None
            self.create_tables()

        def get(self):
            if self.conn is None:
                self.conn = sqlite3.connect(self.db_path)
                self.cursor = self.conn.cursor()
            return self

        def get_cursor(self):
            if self.cursor is None:
                self.conn = sqlite3.connect(self.db_path)
                self.cursor = self.conn.cursor()
            return self.cursor

        def write(self, table, data):
            if self.conn is None:
                self.conn = sqlite3.connect(self.db_path)
                self.cursor = self.conn.cursor()
            
            if table == "file_monitoring":
                # Assuming data is a tuple: (id, name, baseline, file_path)
                self.cursor.execute(
                    "INSERT INTO file_monitoring (ID, name, baseline, file_path) VALUES (?, ?, ?, ?)",
                    data
                )
                self.conn.commit()
            else:
                raise NotImplementedError(f"Mock write only supports 'file_monitoring', not '{table}'")

        def create_tables(self):
            if self.conn is None:
                self.conn = sqlite3.connect(self.db_path)
                self.cursor = self.conn.cursor()
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_monitoring (
                    ID TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    baseline BLOB,
                    file_path TEXT NOT NULL
                )
            """)
            self.conn.commit()

        def close(self):
            if self.conn:
                self.conn.close()
                self.conn = None
                self.cursor = None

        def __del__(self):
            self.close()

    mock_db = MockDatabase(db_path)
    mock_db.create_tables()
    return mock_db

@pytest.fixture
def file_monitoring_system(mock_db_instance, temp_dir_manager):
    """
    Fixture to provide a FileMonitoringSystem instance,
    patched to use the mock database.
    """
    # Create a subclass that injects the mock DB
    class TestFileMonitoringSystem(FileMonitoringSystem):
        def __init__(self, mock_db_instance):
            self.db = mock_db_instance
            self.observer = MagicMock()
            self.handler = MagicMock()
            self.watch_list = []
            
    fms_instance = TestFileMonitoringSystem(mock_db_instance)
    return fms_instance

# --- Test Cases ---

# Test for file_status method

def test_file_status_unmodified(file_monitoring_system, temp_dir_manager, mock_db_instance):
    file_name = "test_unmodified.txt"
    file_dir = temp_dir_manager # This is the temporary directory path
    file_path_full = os.path.join(file_dir, file_name)
    
    content = "This is a test file."
    with open(file_path_full, "w") as f:
        f.write(content)
    
    hasher = hashlib.sha256()
    hasher.update(content.encode('utf-8'))
    baseline_hash = hasher.digest()

    file_id = str(uuid.uuid4())
    mock_db_instance.write("file_monitoring", (file_id, file_name, baseline_hash, file_path_full))

    status = file_monitoring_system.file_status(file_name)
    assert status == f"File '{file_name}': Unmodified"

def test_file_status_modified(file_monitoring_system, temp_dir_manager, mock_db_instance):
    file_name = "test_modified.txt"
    file_dir = temp_dir_manager
    file_path_full = os.path.join(file_dir, file_name)
    
    initial_content = "Initial content."
    with open(file_path_full, "w") as f:
        f.write(initial_content)
    
    hasher = hashlib.sha256()
    hasher.update(initial_content.encode('utf-8'))
    baseline_hash = hasher.digest()

    file_id = str(uuid.uuid4())
    mock_db_instance.write("file_monitoring", (file_id, file_name, baseline_hash, file_path_full))

    modified_content = "Modified content."
    with open(file_path_full, "w") as f:
        f.write(modified_content)
    
    status = file_monitoring_system.file_status(file_name)
    assert status == f"File '{file_name}': Modified"

def test_file_status_not_monitored(file_monitoring_system):
    file_name = "non_existent_file.txt"
    status = file_monitoring_system.file_status(file_name)
    assert status == f"File '{file_name}': Not Monitored"

def test_file_status_file_not_found(file_monitoring_system, temp_dir_manager, mock_db_instance):
    file_name = "missing_file.txt"
    file_dir = temp_dir_manager
    file_path_full = os.path.join(file_dir, file_name) # This file will not be created

    file_id = str(uuid.uuid4())
    dummy_hash = hashlib.sha256(b"dummy").digest() 
    mock_db_instance.write("file_monitoring", (file_id, file_name, dummy_hash, file_path_full))

    status = file_monitoring_system.file_status(file_name)
    assert status == f"File '{file_name}': File Not Found at '{file_path_full}'"

# Test for all_file_status method

def test_all_file_status(file_monitoring_system, temp_dir_manager, mock_db_instance):
    file_name_unmodified = "unmodified.log"
    file_dir = temp_dir_manager
    file_path_unmodified = os.path.join(file_dir, file_name_unmodified)
    content_unmodified = "This is unmodified."
    with open(file_path_unmodified, "w") as f:
        f.write(content_unmodified)
    hasher_unmodified = hashlib.sha256()
    hasher_unmodified.update(content_unmodified.encode('utf-8'))
    hash_unmodified = hasher_unmodified.digest()
    mock_db_instance.write("file_monitoring", (str(uuid.uuid4()), file_name_unmodified, hash_unmodified, file_path_unmodified))

    file_name_modified = "modified.conf"
    file_path_modified = os.path.join(file_dir, file_name_modified)
    content_modified_initial = "Initial config."
    with open(file_path_modified, "w") as f:
        f.write(content_modified_initial)
    hasher_modified = hashlib.sha256()
    hasher_modified.update(content_modified_initial.encode('utf-8'))
    hash_modified = hasher_modified.digest()
    mock_db_instance.write("file_monitoring", (str(uuid.uuid4()), file_name_modified, hash_modified, file_path_modified))
    content_modified_new = "Modified config."
    with open(file_path_modified, "w") as f:
        f.write(content_modified_new)

    file_name_not_found = "missing_config.cfg"
    file_path_not_found = os.path.join(file_dir, file_name_not_found)
    dummy_hash_not_found = hashlib.sha256(b"dummy_not_found").digest()
    mock_db_instance.write("file_monitoring", (str(uuid.uuid4()), file_name_not_found, dummy_hash_not_found, file_path_not_found))

    report = file_monitoring_system.all_file_status()
    
    assert "--- File Status Report ---" in report
    assert f"File '{file_name_unmodified}': Unmodified" in report
    assert f"File '{file_name_modified}': Modified" in report
    assert f"File '{file_name_not_found}': File Not Found at '{file_path_not_found}'" in report
    assert "--------------------------" in report

def test_all_file_status_no_files(file_monitoring_system):
    report = file_monitoring_system.all_file_status()
    assert report == "No files are currently being monitored."