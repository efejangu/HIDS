#!/usr/bin/env python3
"""
HIDS - Main Entry Point
Run the Host Intrusion Detection System terminal UI
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from HIDS.UI import run_app

if __name__ == "__main__":
    print("Starting HIDS Terminal UI...")
    print("Press 'q' to quit, 'f' for File Monitor, 'n' for Network, 'p' for Process Monitor, 'l' for Log Viewer")
    print("-" * 80)
    
    try:
        run_app()
    except KeyboardInterrupt:
        print("\nHIDS terminated by user")
    except Exception as e:
        print(f"\nError running HIDS: {e}")
        import traceback
        traceback.print_exc()
        import sys
        sys.exit(1)