#!/usr/bin/env python3
"""
Security Toolsmith TUI - Standalone Runner

This script runs the Security Toolsmith Terminal User Interface.

Usage:
    python run_tui.py

Requirements:
    - Python 3.8+
    - textual>=0.40.0
    - rich>=13.0.0
"""

import sys
import os

# Add the python directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []

    try:
        import textual
        print(f"[OK] textual {textual.__version__}")
    except ImportError:
        missing.append("textual")
        print("[MISSING] textual")

    try:
        import rich
        print(f"[OK] rich {rich.__version__}")
    except ImportError:
        missing.append("rich")
        print("[MISSING] rich")

    if missing:
        print("\n" + "=" * 50)
        print("Missing dependencies detected!")
        print("Install with: pip install " + " ".join(missing))
        print("=" * 50)
        return False

    return True


def main():
    """Main entry point."""
    print("Security Toolsmith TUI")
    print("=" * 50)
    print("Checking dependencies...")
    print()

    if not check_dependencies():
        print("\nPlease install missing dependencies and try again.")
        sys.exit(1)

    print()
    print("Starting TUI application...")
    print("Press Ctrl+Q to quit, 'h' for help")
    print("=" * 50)
    print()

    try:
        from tui import ToolsmithApp
        app = ToolsmithApp()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
    except Exception as e:
        print(f"\nError running TUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
