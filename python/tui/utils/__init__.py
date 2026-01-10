"""TUI Utilities Package - Helper functions and utilities."""

from .network_targets import (
    CoreTargetManager,
    NetworkTarget,
    NetworkSegment,
    parse_imn_targets,
    get_active_session_targets,
    get_network_ranges,
)

from .tool_discovery import (
    DiscoveredTool,
    ToolParameter,
    ToolRegistry,
    discover_all_tools,
    get_registry,
)

from .tool_executor import (
    ToolExecutor,
    ExecutionResult,
    ExecutionStatus,
    ExecutionConfig,
    get_executor,
    execute_tool,
    build_command,
)

from .docker_targets import (
    DockerTargetManager,
    DockerTarget,
    TargetService,
    get_docker_target_manager,
)

__all__ = [
    # Network targets
    "CoreTargetManager",
    "NetworkTarget",
    "NetworkSegment",
    "parse_imn_targets",
    "get_active_session_targets",
    "get_network_ranges",
    # Tool discovery
    "DiscoveredTool",
    "ToolParameter",
    "ToolRegistry",
    "discover_all_tools",
    "get_registry",
    # Tool executor
    "ToolExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "ExecutionConfig",
    "get_executor",
    "execute_tool",
    "build_command",
    # Docker targets
    "DockerTargetManager",
    "DockerTarget",
    "TargetService",
    "get_docker_target_manager",
]
