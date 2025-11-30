"""
Test file monitor event tracking functionality
"""
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from HIDS.database.database import Database


def test_database_schema():
    """Test that the database schema includes event count fields"""
    print("Testing database schema...")
    
    # Create a temporary database
    with tempfile.TemporaryDirectory() as tmpdir:
        original_dir = os.getcwd()
        os.chdir(tmpdir)
        
        try:
            with Database() as db:
                db.create_tables()
                
                # Add a test directory
                test_path = "/tmp/test_monitor"
                success = db.add_monitored_directory(test_path)
                assert success, "Failed to add directory"
                print("✓ Directory added successfully")
                
                # Verify the directory was added with default counts
                dirs = db.get_all_monitored_directories()
                assert len(dirs) > 0, "No directories found"
                
                # Check that we have the event count fields (8 fields total)
                dir_data = dirs[0]
                assert len(dir_data) >= 8, f"Expected at least 8 fields, got {len(dir_data)}"
                print(f"✓ Database schema correct: {len(dir_data)} fields")
                
                # Test increment functionality
                db.increment_directory_event_count(test_path, 'modified')
                db.increment_directory_event_count(test_path, 'created')
                db.increment_directory_event_count(test_path, 'deleted')
                print("✓ Event counts incremented")
                
                # Verify counts
                counts = db.get_directory_event_counts(test_path)
                assert counts is not None, "Failed to get event counts"
                assert counts['modified'] == 1, f"Expected 1 modified, got {counts['modified']}"
                assert counts['added'] == 1, f"Expected 1 added, got {counts['added']}"
                assert counts['deleted'] == 1, f"Expected 1 deleted, got {counts['deleted']}"
                print("✓ Event counts verified correctly")
                
                print("\n✅ All database tests passed!")
                
        finally:
            os.chdir(original_dir)


def test_logging_setup():
    """Test that logging is properly configured"""
    print("\nTesting logging setup...")
    
    try:
        # Import the FileMonitorView
        from HIDS.UI.views.file_monitor import FileMonitorView
        
        # Create an instance (this will set up logging)
        view = FileMonitorView()
        
        # Check that logger exists and is configured
        assert view.logger is not None, "Logger not initialized"
        assert view.logger.name == 'FileMonitor', f"Wrong logger name: {view.logger.name}"
        assert len(view.logger.handlers) > 0, "No handlers attached to logger"
        print("✓ Logger initialized correctly")
        
        # Check event_counts dictionary exists
        assert hasattr(view, 'event_counts'), "event_counts not initialized"
        assert isinstance(view.event_counts, dict), "event_counts is not a dict"
        print("✓ Event counts dictionary initialized")
        
        print("\n✅ All logging tests passed!")
    except ImportError as e:
        print(f"⚠ Skipping UI tests (missing dependencies): {e}")
        print("  Run with venv activated to test UI components")


if __name__ == "__main__":
    try:
        test_database_schema()
        test_logging_setup()
        print("\n" + "="*50)
        print("ALL TESTS PASSED SUCCESSFULLY! ✨")
        print("="*50)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)