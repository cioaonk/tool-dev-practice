"""
Tool Discovery Module

Discovers and registers security tools from the tools directory.
Uses each tool's get_documentation() function to build the registry.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolParameter:
    """Represents a tool parameter/argument."""

    name: str
    param_type: str
    required: bool
    description: str
    default: Any = None
    choices: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.param_type,
            "required": self.required,
            "description": self.description,
            "default": self.default,
            "choices": self.choices,
        }


@dataclass
class DiscoveredTool:
    """Represents a discovered security tool with full metadata."""

    name: str
    display_name: str
    description: str
    category: str
    version: str
    tool_path: Path
    parameters: List[ToolParameter] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    examples: List[Dict[str, str]] = field(default_factory=list)
    opsec_notes: List[str] = field(default_factory=list)
    author: str = "Unknown"

    def __hash__(self) -> int:
        return hash(self.name)

    def get_command_base(self) -> List[str]:
        """Get the base command to run this tool."""
        return [sys.executable, str(self.tool_path)]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category,
            "version": self.version,
            "tool_path": str(self.tool_path),
            "parameters": [p.to_dict() for p in self.parameters],
            "features": self.features,
            "examples": self.examples,
            "opsec_notes": self.opsec_notes,
            "author": self.author,
        }


# Category mappings for better display
CATEGORY_DISPLAY_NAMES = {
    "reconnaissance": "Reconnaissance",
    "recon": "Reconnaissance",
    "web": "Web Testing",
    "credential": "Credential Testing",
    "network": "Network Services",
    "evasion": "Evasion/Payload",
    "payload": "Evasion/Payload",
    "exploitation": "Exploitation",
}


def _normalize_category(category: str) -> str:
    """Normalize category name for display."""
    cat_lower = category.lower()
    return CATEGORY_DISPLAY_NAMES.get(cat_lower, category.title())


def _parse_arguments(args_data: Any) -> List[ToolParameter]:
    """
    Parse arguments from get_documentation() into ToolParameter list.

    Supports both dictionary format (name -> info) and list format (list of dicts).
    """
    parameters = []

    # Handle list format: [{"name": "--flag", "description": "...", ...}, ...]
    if isinstance(args_data, list):
        for arg_info in args_data:
            if not isinstance(arg_info, dict):
                continue

            arg_name = arg_info.get("name", "")
            clean_name = arg_name.lstrip("-")
            if not clean_name:
                continue

            required = arg_info.get("required", False)
            param_type = arg_info.get("type", "string")
            description = arg_info.get("description", "")
            default = arg_info.get("default", None)
            choices = arg_info.get("choices", None)

            # Convert type names
            type_mapping = {
                "bool": "bool",
                "boolean": "bool",
                "int": "int",
                "integer": "int",
                "float": "float",
                "string": "str",
                "str": "str",
                "list": "list",
                "file": "file",
            }
            param_type = type_mapping.get(str(param_type).lower(), "str")

            parameters.append(ToolParameter(
                name=clean_name,
                param_type=param_type,
                required=required,
                description=description,
                default=default,
                choices=choices,
            ))

    # Handle dictionary format: {"--flag": {"description": "...", ...}, ...}
    elif isinstance(args_data, dict):
        for arg_name, arg_info in args_data.items():
            # Handle both positional args and flag args
            clean_name = arg_name.lstrip("-")

            # Determine if required
            if isinstance(arg_info, dict):
                required = arg_info.get("required", False)
                param_type = arg_info.get("type", "string")
                description = arg_info.get("description", "")
                default = arg_info.get("default", None)
                choices = arg_info.get("choices", None)
            else:
                # Simple string description
                required = False
                param_type = "string"
                description = str(arg_info)
                default = None
                choices = None

            # Convert type names
            type_mapping = {
                "bool": "bool",
                "boolean": "bool",
                "int": "int",
                "integer": "int",
                "float": "float",
                "string": "str",
                "str": "str",
                "list": "list",
                "file": "file",
            }
            param_type = type_mapping.get(str(param_type).lower(), "str")

            parameters.append(ToolParameter(
                name=clean_name,
                param_type=param_type,
                required=required,
                description=description,
                default=default,
                choices=choices,
            ))

    return parameters


def _load_tool_documentation(tool_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load a tool's get_documentation() function and call it.

    Args:
        tool_path: Path to the tool.py file

    Returns:
        Documentation dictionary or None if loading fails
    """
    try:
        # Create a module spec and load the module
        spec = importlib.util.spec_from_file_location(
            f"tool_{tool_path.parent.name}",
            tool_path
        )
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)

        # Don't add to sys.modules to avoid conflicts
        # Just execute the module to get the function
        spec.loader.exec_module(module)

        # Call get_documentation if it exists
        if hasattr(module, "get_documentation"):
            return module.get_documentation()

        return None

    except Exception as e:
        # Log but don't fail - tool might still be runnable
        print(f"Warning: Could not load documentation from {tool_path}: {e}")
        return None


def _find_tool_file(tool_dir: Path) -> Optional[Path]:
    """
    Find the main tool file in a directory.

    Looks for tool.py first, then falls back to <dirname>.py or
    <dirname_with_underscores>.py patterns.

    Args:
        tool_dir: Path to the tool directory

    Returns:
        Path to the tool file or None if not found
    """
    # Primary: tool.py
    tool_path = tool_dir / "tool.py"
    if tool_path.exists():
        return tool_path

    # Secondary: <dirname>.py (e.g., amsi-bypass -> amsi_bypass.py)
    alt_name = tool_dir.name.replace("-", "_") + ".py"
    alt_path = tool_dir / alt_name
    if alt_path.exists():
        return alt_path

    # Tertiary: Look for any Python file with get_documentation
    for py_file in tool_dir.glob("*.py"):
        if py_file.name.startswith("__"):
            continue
        if py_file.name == "test_" or py_file.name.startswith("test_"):
            continue

        # Quick check if file contains get_documentation
        try:
            content = py_file.read_text(encoding="utf-8")
            if "def get_documentation" in content:
                return py_file
        except Exception:
            continue

    return None


def discover_tool(tool_dir: Path) -> Optional[DiscoveredTool]:
    """
    Discover a single tool from its directory.

    Args:
        tool_dir: Path to the tool directory

    Returns:
        DiscoveredTool or None if discovery fails
    """
    tool_path = _find_tool_file(tool_dir)

    if not tool_path:
        return None

    # Try to get documentation
    docs = _load_tool_documentation(tool_path)

    if docs:
        # Build from documentation
        name = docs.get("name", tool_dir.name)
        display_name = name.replace("-", " ").title()
        description = docs.get("description", "No description available")
        category = _normalize_category(docs.get("category", "Other"))
        version = docs.get("version", "1.0.0")
        features = docs.get("features", [])
        examples = docs.get("examples", [])
        opsec_notes = docs.get("opsec_notes", [])
        author = docs.get("author", "Unknown")

        # Parse arguments
        args_dict = docs.get("arguments", {})
        parameters = _parse_arguments(args_dict)
    else:
        # Fallback to basic info from directory name
        name = tool_dir.name
        display_name = name.replace("-", " ").title()
        description = f"{display_name} security tool"
        category = "Other"
        version = "1.0.0"
        features = []
        examples = []
        opsec_notes = []
        author = "Unknown"
        parameters = []

    return DiscoveredTool(
        name=name,
        display_name=display_name,
        description=description,
        category=category,
        version=version,
        tool_path=tool_path,
        parameters=parameters,
        features=features,
        examples=examples,
        opsec_notes=opsec_notes,
        author=author,
    )


def discover_all_tools(tools_dir: Optional[Path] = None) -> List[DiscoveredTool]:
    """
    Discover all tools in the tools directory.

    Args:
        tools_dir: Path to the tools directory. If None, uses default location.

    Returns:
        List of discovered tools
    """
    if tools_dir is None:
        # Default to ../../tools relative to this file
        tools_dir = Path(__file__).parent.parent.parent / "tools"

    if not tools_dir.exists():
        print(f"Warning: Tools directory not found: {tools_dir}")
        return []

    discovered = []

    for item in sorted(tools_dir.iterdir()):
        if item.is_dir() and not item.name.startswith("."):
            # Skip non-tool directories
            if item.name in ("environment", "__pycache__"):
                continue

            tool = discover_tool(item)
            if tool:
                discovered.append(tool)

    return discovered


def get_tools_by_category(tools: List[DiscoveredTool]) -> Dict[str, List[DiscoveredTool]]:
    """
    Group tools by category.

    Args:
        tools: List of discovered tools

    Returns:
        Dictionary mapping category names to tool lists
    """
    categories: Dict[str, List[DiscoveredTool]] = {}

    for tool in tools:
        if tool.category not in categories:
            categories[tool.category] = []
        categories[tool.category].append(tool)

    return categories


class ToolRegistry:
    """
    Registry of discovered security tools.

    Provides methods for discovering, accessing, and filtering tools.
    """

    def __init__(self, tools_dir: Optional[Path] = None):
        """
        Initialize the registry.

        Args:
            tools_dir: Path to the tools directory
        """
        self.tools_dir = tools_dir or Path(__file__).parent.parent.parent / "tools"
        self._tools: List[DiscoveredTool] = []
        self._tools_by_name: Dict[str, DiscoveredTool] = {}
        self._loaded = False

    def discover(self) -> None:
        """Discover all tools and populate the registry."""
        self._tools = discover_all_tools(self.tools_dir)
        self._tools_by_name = {tool.name: tool for tool in self._tools}
        self._loaded = True

    def ensure_loaded(self) -> None:
        """Ensure tools have been discovered."""
        if not self._loaded:
            self.discover()

    @property
    def tools(self) -> List[DiscoveredTool]:
        """Get all discovered tools."""
        self.ensure_loaded()
        return self._tools

    def get_tool(self, name: str) -> Optional[DiscoveredTool]:
        """Get a tool by name."""
        self.ensure_loaded()
        return self._tools_by_name.get(name)

    def get_tools_by_category(self) -> Dict[str, List[DiscoveredTool]]:
        """Get tools grouped by category."""
        self.ensure_loaded()
        return get_tools_by_category(self._tools)

    def get_categories(self) -> List[str]:
        """Get list of all categories."""
        self.ensure_loaded()
        return sorted(set(tool.category for tool in self._tools))

    def filter_by_category(self, category: str) -> List[DiscoveredTool]:
        """Get tools in a specific category."""
        self.ensure_loaded()
        return [tool for tool in self._tools if tool.category == category]

    def search(self, query: str) -> List[DiscoveredTool]:
        """Search tools by name or description."""
        self.ensure_loaded()
        query_lower = query.lower()
        results = []

        for tool in self._tools:
            if (query_lower in tool.name.lower() or
                query_lower in tool.display_name.lower() or
                query_lower in tool.description.lower()):
                results.append(tool)

        return results

    def __len__(self) -> int:
        self.ensure_loaded()
        return len(self._tools)

    def __iter__(self):
        self.ensure_loaded()
        return iter(self._tools)


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_registry(tools_dir: Optional[Path] = None) -> ToolRegistry:
    """
    Get the global tool registry instance.

    Args:
        tools_dir: Optional tools directory path

    Returns:
        ToolRegistry instance
    """
    global _global_registry

    if _global_registry is None:
        _global_registry = ToolRegistry(tools_dir)

    return _global_registry
