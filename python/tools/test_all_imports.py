#!/usr/bin/env python3
"""
Import Validation Test Script
==============================

Tests that all 15 Python tools can be imported without errors
and validates that get_documentation() is callable.
"""

import sys
import os
import importlib.util
from pathlib import Path

# Add tools directory to path
TOOLS_DIR = Path(__file__).parent
sys.path.insert(0, str(TOOLS_DIR))

# Define all 15 tools with their module paths
TOOLS = {
    # Tools using tool.py pattern (import from tool.py directly)
    "network-scanner": ("network-scanner/tool.py", "tool"),
    "port-scanner": ("port-scanner/tool.py", "tool"),
    "service-fingerprinter": ("service-fingerprinter/tool.py", "tool"),
    "web-directory-enumerator": ("web-directory-enumerator/tool.py", "tool"),
    "credential-validator": ("credential-validator/tool.py", "tool"),
    "dns-enumerator": ("dns-enumerator/tool.py", "tool"),
    "smb-enumerator": ("smb-enumerator/tool.py", "tool"),
    "http-request-tool": ("http-request-tool/tool.py", "tool"),
    "hash-cracker": ("hash-cracker/tool.py", "tool"),
    "reverse-shell-handler": ("reverse-shell-handler/tool.py", "tool"),
    # Tools using package pattern (have __init__.py)
    "payload-generator": ("payload-generator/payload_generator.py", "payload_generator"),
    "process-hollowing": ("process-hollowing/process_hollowing.py", "process_hollowing"),
    "amsi-bypass": ("amsi-bypass/amsi_bypass.py", "amsi_bypass"),
    "shellcode-encoder": ("shellcode-encoder/shellcode_encoder.py", "shellcode_encoder"),
    "edr-evasion-toolkit": ("edr-evasion-toolkit/edr_evasion.py", "edr_evasion"),
}


def load_module_from_file(file_path: str, module_name: str):
    """Load a Python module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {file_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_tool_import(tool_name: str, rel_path: str, module_name: str) -> dict:
    """
    Test importing a single tool and calling get_documentation().

    Returns a dict with:
        - tool_name: Name of the tool
        - import_success: bool
        - get_documentation_success: bool
        - error: error message if any
        - documentation_keys: keys returned by get_documentation() if successful
    """
    result = {
        "tool_name": tool_name,
        "import_success": False,
        "get_documentation_success": False,
        "error": None,
        "documentation_keys": None
    }

    file_path = TOOLS_DIR / rel_path

    try:
        # Attempt to import the module
        module = load_module_from_file(str(file_path), f"test_{module_name}_{tool_name.replace('-', '_')}")
        result["import_success"] = True

        # Check if get_documentation exists and is callable
        if hasattr(module, "get_documentation"):
            doc_func = getattr(module, "get_documentation")
            if callable(doc_func):
                doc = doc_func()
                result["get_documentation_success"] = True
                if isinstance(doc, dict):
                    result["documentation_keys"] = list(doc.keys())
            else:
                result["error"] = "get_documentation is not callable"
        else:
            result["error"] = "get_documentation function not found"

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)}"

    return result


def main():
    """Run import validation for all 15 tools."""
    print("=" * 70)
    print("PYTHON TOOLS IMPORT VALIDATION TEST")
    print("=" * 70)
    print()

    results = []
    successful_imports = 0
    successful_docs = 0
    failed_tools = []

    for tool_name, (rel_path, module_name) in TOOLS.items():
        print(f"Testing: {tool_name}...")
        result = test_tool_import(tool_name, rel_path, module_name)
        results.append(result)

        if result["import_success"]:
            successful_imports += 1
            status = "[IMPORT OK]"
        else:
            status = "[IMPORT FAILED]"
            failed_tools.append(tool_name)

        if result["get_documentation_success"]:
            successful_docs += 1
            status += " [get_documentation OK]"
        else:
            status += " [get_documentation FAILED]"
            if tool_name not in failed_tools:
                failed_tools.append(tool_name)

        print(f"  {status}")
        if result["error"]:
            print(f"  Error: {result['error']}")
        if result["documentation_keys"]:
            print(f"  Documentation keys: {result['documentation_keys']}")
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total tools tested: {len(TOOLS)}")
    print(f"Successful imports: {successful_imports}/{len(TOOLS)}")
    print(f"Successful get_documentation() calls: {successful_docs}/{len(TOOLS)}")
    print()

    if failed_tools:
        print("FAILED TOOLS:")
        for tool in failed_tools:
            for r in results:
                if r["tool_name"] == tool:
                    print(f"  - {tool}: {r['error']}")
        print()

    # Detailed results
    print("\nDETAILED RESULTS:")
    print("-" * 70)
    print(f"{'Tool Name':<30} {'Import':<10} {'get_documentation':<15}")
    print("-" * 70)
    for r in results:
        import_status = "PASS" if r["import_success"] else "FAIL"
        doc_status = "PASS" if r["get_documentation_success"] else "FAIL"
        print(f"{r['tool_name']:<30} {import_status:<10} {doc_status:<15}")
    print("-" * 70)

    # Exit code
    if successful_imports == len(TOOLS) and successful_docs == len(TOOLS):
        print("\nALL TESTS PASSED!")
        return 0
    else:
        print(f"\nTESTS FAILED: {len(failed_tools)} tool(s) have issues")
        return 1


if __name__ == "__main__":
    sys.exit(main())
