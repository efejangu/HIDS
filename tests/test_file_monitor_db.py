"""
Test file monitor database integration
"""
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from HIDS.database.database import Database


def test_monitored_directories():
    """Test monitored directories database operations"""
    
    # Create a temporary database for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        # Change to temp directory for database
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            print("Testing database operations for monitored directories...")
            
            # Test 1: Create database and tables
            print("\n1. Creating database and tables...")
            with Database() as db:
                db.create_tables()
            print("✓ Tables created successfully")
            
            # Test 2: Add monitored directory
            print("\n2. Adding monitored directory...")
            test_path = "/tmp/test_monitoring"
            with Database() as db:
                result = db.add_monitored_directory(test_path)
                assert result == True, "Failed to add directory"
            print(f"✓ Added directory: {test_path}")
            
            # Test 3: Try adding duplicate (should fail)
            print("\n3. Testing duplicate prevention...")
            with Database() as db:
                result = db.add_monitored_directory(test_path)
                assert result == False, "Duplicate should be prevented"
            print("✓ Duplicate prevention works")
            
            # Test 4: Retrieve all monitored directories
            print("\n4. Retrieving all monitored directories...")
            with Database() as db:
                dirs = db.get_all_monitored_directories()
                assert len(dirs) == 1, f"Expected 1 directory, got {len(dirs)}"
                assert dirs[0][2] == test_path, "Path mismatch"
                print(f"✓ Retrieved {len(dirs)} directory")
                print(f"  Data: {dirs[0]}")
            
            # Test 5: Update directory status
            print("\n5. Updating directory status...")
            with Database() as db:
                result = db.update_directory_status(test_path, "paused")
                assert result == True, "Failed to update status"
                
                # Verify update
                dirs = db.get_all_monitored_directories()
                assert dirs[0][4] == "paused", "Status not updated"
            print("✓ Status updated to 'paused'")
            
            # Test 6: Add another directory
            print("\n6. Adding second directory...")
            test_path2 = "/tmp/test_monitoring2"
            with Database() as db:
                result = db.add_monitored_directory(test_path2)
                assert result == True, "Failed to add second directory"
                
                dirs = db.get_all_monitored_directories()
                assert len(dirs) == 2, f"Expected 2 directories, got {len(dirs)}"
            print(f"✓ Added second directory: {test_path2}")
            
            # Test 7: Delete monitored directory
            print("\n7. Deleting monitored directory...")
            with Database() as db:
                result = db.delete_monitored_directory(test_path)
                assert result == True, "Failed to delete directory"
                
                # Verify deletion
                dirs = db.get_all_monitored_directories()
                assert len(dirs) == 1, f"Expected 1 directory after deletion, got {len(dirs)}"
                assert dirs[0][2] == test_path2, "Wrong directory remaining"
            print(f"✓ Deleted directory: {test_path}")
            print(f"  Remaining: {dirs[0][2]}")
            
            # Test 8: Clean up - delete remaining directory
            print("\n8. Cleaning up...")
            with Database() as db:
                result = db.delete_monitored_directory(test_path2)
                assert result == True, "Failed to delete second directory"
                
                dirs = db.get_all_monitored_directories()
                assert len(dirs) == 0, f"Expected 0 directories, got {len(dirs)}"
            print("✓ All directories deleted")
            
            print("\n" + "="*50)
            print("All tests passed successfully! ✓")
            print("="*50)
            
        finally:
            # Restore original directory
            os.chdir(original_dir)


if __name__ == "__main__":
    test_monitored_directories()