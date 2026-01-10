#!/usr/bin/env python3
"""
Test script for TUI tool discovery functionality.
Verifies that all 15 expected tools can be discovered and loaded.
"""

import sys
sys.path.insert(0, '/Users/ic/cptc11/python')

from pathlib import Path
from tui.utils.tool_discovery import discover_all_tools, get_tools_by_category

def main():
    # Set the tools directory
    tools_dir = Path('/Users/ic/cptc11/python/tools')

    print("=" * 70)
    print("TOOL DISCOVERY TEST REPORT")
    print("=" * 70)
    print()

    # Discover all tools
    print("Discovering tools...")
    tools = discover_all_tools(tools_dir)

    print(f"\nTotal tools discovered: {len(tools)}")
    print()

    # Expected tools based on directory listing (excluding environment and __pycache__)
    expected_tools = [
        'amsi-bypass',
        'credential-validator',
        'dns-enumerator',
        'edr-evasion-toolkit',
        'hash-cracker',
        'http-request-tool',
        'network-scanner',
        'payload-generator',
        'port-scanner',
        'process-hollowing',
        'reverse-shell-handler',
        'service-fingerprinter',
        'shellcode-encoder',
        'smb-enumerator',
        'web-directory-enumerator'
    ]

    discovered_names = [tool.name for tool in tools]

    print("-" * 70)
    print("DISCOVERY RESULTS")
    print("-" * 70)

    # Check for any failures (expected but not found)
    missing = []
    for expected in expected_tools:
        if expected not in discovered_names:
            missing.append(expected)

    if missing:
        print(f"\nFAILED TO LOAD ({len(missing)} tools):")
        for name in missing:
            print(f"  - {name}")
    else:
        print("\nAll expected tools loaded successfully!")

    # Check for unexpected tools
    unexpected = []
    for name in discovered_names:
        if name not in expected_tools:
            unexpected.append(name)

    if unexpected:
        print(f"\nUNEXPECTED TOOLS FOUND ({len(unexpected)}):")
        for name in unexpected:
            print(f"  - {name}")

    print()
    print("-" * 70)
    print("PARAMETER COUNTS PER TOOL")
    print("-" * 70)
    print()
    print(f"{'Tool Name':<30} {'Category':<20} {'Params':<8} {'Version'}")
    print("-" * 70)

    for tool in sorted(tools, key=lambda t: t.name):
        param_count = len(tool.parameters)
        print(f"{tool.name:<30} {tool.category:<20} {param_count:<8} {tool.version}")

    print()
    print("-" * 70)
    print("TOOLS BY CATEGORY")
    print("-" * 70)
    categories = get_tools_by_category(tools)
    for category, cat_tools in sorted(categories.items()):
        print(f"\n{category}:")
        for tool in cat_tools:
            print(f"  - {tool.name}")

    print()
    print("-" * 70)
    print("DETAILED PARAMETER INFO")
    print("-" * 70)

    for tool in sorted(tools, key=lambda t: t.name):
        print(f"\n{tool.name} ({len(tool.parameters)} parameters):")
        if tool.parameters:
            for param in tool.parameters:
                req_str = "required" if param.required else "optional"
                print(f"  --{param.name} ({param.param_type}, {req_str})")
        else:
            print("  No parameters defined")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Expected tools: {len(expected_tools)}")
    print(f"Discovered tools: {len(tools)}")
    print(f"Missing tools: {len(missing)}")
    print(f"Discovery success rate: {(len(tools)/len(expected_tools))*100:.1f}%")

    # Check if we hit the expected 15 tools
    if len(tools) == 15:
        print("\n[PASS] All 15 tools discovered successfully!")
        return 0
    else:
        print(f"\n[FAIL] Expected 15 tools, found {len(tools)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
