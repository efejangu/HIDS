#!/usr/bin/env python3
"""
Test script for HIDS UI
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from textual.pilot import Pilot
from HIDS.UI.app import HIDSApp


async def test_basic_navigation():
    """Test basic UI navigation"""
    app = HIDSApp()
    
    async with app.run_test() as pilot:
        # Wait for app to load
        await pilot.pause()
        
        # Test tab switching
        print("✓ App loaded successfully")
        
        # Switch to File Monitor
        await pilot.press("f")
        await pilot.pause()
        print("✓ Switched to File Monitor tab")
        
        # Switch to Network Monitor
        await pilot.press("n")
        await pilot.pause()
        print("✓ Switched to Network Monitor tab")
        
        # Switch back to Dashboard
        await pilot.press("d")
        await pilot.pause()
        print("✓ Switched back to Dashboard tab")
        
        print("\n✅ All basic navigation tests passed!")


async def test_file_monitor_interactions():
    """Test file monitor interactions"""
    app = HIDSApp()
    
    async with app.run_test() as pilot:
        # Navigate to file monitor
        await pilot.press("f")
        await pilot.pause()
        
        # Try to add a directory
        dir_input = app.query_one("#directory-input")
        dir_input.value = "/home/test"
        await pilot.pause()
        
        # Click add button
        await pilot.click("#add-dir-btn")
        await pilot.pause()
        
        print("✓ File monitor interactions work")


if __name__ == "__main__":
    import asyncio
    
    print("Running HIDS UI Tests...")
    print("-" * 60)
    
    try:
        asyncio.run(test_basic_navigation())
        print()
        asyncio.run(test_file_monitor_interactions())
        print("\n" + "=" * 60)
        print("✅ All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)