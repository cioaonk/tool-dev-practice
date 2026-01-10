#!/usr/bin/env python3
"""
Penetration Testing Toolkit - Environment Setup
================================================

This script verifies the Python environment and provides information
about the available tools in the toolkit.

Author: Offensive Security Toolsmith
Version: 1.0.0
"""

import sys
import os
import importlib.util
from pathlib import Path


def check_python_version():
    """Verify Python version meets requirements."""
    required = (3, 6)
    current = sys.version_info[:2]

    if current >= required:
        print(f"[+] Python version: {sys.version.split()[0]} (OK)")
        return True
    else:
        print(f"[-] Python version: {sys.version.split()[0]} (Requires 3.6+)")
        return False


def check_tool(tool_path: Path) -> bool:
    """Check if a tool is properly configured."""
    tool_file = tool_path / "tool.py"
    readme_file = tool_path / "README.md"

    if not tool_file.exists():
        return False

    # Try to import and check for required functions
    try:
        spec = importlib.util.spec_from_file_location("tool", tool_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Check for documentation hook
        has_docs = hasattr(module, 'get_documentation')
        has_plan = hasattr(module, 'print_plan')

        return has_docs and has_plan

    except Exception as e:
        return False


def list_tools():
    """List all available tools."""
    tools_dir = Path(__file__).parent.parent

    tools = []
    for item in tools_dir.iterdir():
        if item.is_dir() and not item.name.startswith('_'):
            tool_file = item / "tool.py"
            if tool_file.exists():
                tools.append(item.name)

    return sorted(tools)


def main():
    """Main entry point."""
    print("""
================================================================================
  Penetration Testing Toolkit - Environment Setup
================================================================================
""")

    # Check Python version
    if not check_python_version():
        print("\n[!] Please upgrade Python to version 3.6 or higher")
        return 1

    # List tools
    print("\n[*] Available Tools:")
    print("-" * 40)

    tools = list_tools()
    for tool_name in tools:
        tool_path = Path(__file__).parent.parent / tool_name

        if check_tool(tool_path):
            status = "Ready"
            symbol = "+"
        else:
            status = "Check failed"
            symbol = "!"

        print(f"  [{symbol}] {tool_name:<30} {status}")

    print(f"\n[*] Total: {len(tools)} tools available")

    # Usage hints
    print("""
================================================================================
  Quick Start
================================================================================

Each tool supports:
  --plan, -p    Preview operation without executing
  --help, -h    Show detailed usage information
  --verbose, -v Enable verbose output

Example:
  python3 tools/network-scanner/tool.py 192.168.1.0/24 --plan
  python3 tools/port-scanner/tool.py target.com --ports top100 --plan

WARNING: These tools are for AUTHORIZED security testing only.
================================================================================
""")

    return 0


if __name__ == "__main__":
    sys.exit(main())
