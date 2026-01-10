"""
Tool Executor Module

Executes security tools via subprocess with real-time output streaming.
Supports both plan mode and actual execution with proper error handling.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)

from .tool_discovery import DiscoveredTool, ToolParameter


class ExecutionStatus(Enum):
    """Status of tool execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    tool_name: str
    status: ExecutionStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    json_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    @property
    def duration(self) -> Optional[float]:
        """Get execution duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ExecutionStatus.COMPLETED and self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "json_output": self.json_output,
            "error_message": self.error_message,
            "success": self.success,
        }


@dataclass
class ExecutionConfig:
    """Configuration for tool execution."""
    plan_mode: bool = False
    json_output: bool = False
    verbose: bool = False
    timeout: Optional[float] = None  # Timeout in seconds
    working_dir: Optional[Path] = None
    env_vars: Dict[str, str] = field(default_factory=dict)


def build_command(
    tool: DiscoveredTool,
    params: Dict[str, Any],
    config: ExecutionConfig
) -> List[str]:
    """
    Build the command line arguments for a tool.

    Args:
        tool: The tool to execute
        params: Parameter values from the user
        config: Execution configuration

    Returns:
        List of command line arguments
    """
    cmd = [sys.executable, str(tool.tool_path)]

    # Build parameter lookup for easy access
    param_lookup = {p.name: p for p in tool.parameters}

    # Process parameters
    for param_name, value in params.items():
        if value is None or value == "":
            continue

        param_info = param_lookup.get(param_name)

        # Determine if this is a positional or flag argument
        # Positional args typically don't start with dashes in the original
        is_positional = param_info and param_info.required and not param_name.startswith("-")

        if is_positional:
            # Positional arguments - add value directly
            if isinstance(value, list):
                cmd.extend(str(v) for v in value)
            else:
                cmd.append(str(value))
        else:
            # Flag arguments
            flag_name = f"--{param_name}" if not param_name.startswith("-") else param_name

            if param_info and param_info.param_type == "bool":
                # Boolean flags - only add if True
                if value is True or str(value).lower() in ("true", "yes", "1"):
                    cmd.append(flag_name)
            elif isinstance(value, list):
                # List values - add flag once with multiple values
                cmd.append(flag_name)
                cmd.extend(str(v) for v in value)
            else:
                # Regular flag with value
                cmd.append(flag_name)
                cmd.append(str(value))

    # Add execution config flags
    if config.plan_mode:
        cmd.append("--plan")

    if config.json_output:
        # Only add if tool supports it (most do)
        cmd.append("--json")

    if config.verbose:
        cmd.append("--verbose")

    return cmd


class ToolExecutor:
    """
    Executor for running security tools via subprocess.

    Provides async execution with real-time output streaming,
    cancellation support, and proper error handling.
    """

    def __init__(self):
        """Initialize the executor."""
        self._running_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set = set()

    async def execute(
        self,
        tool: DiscoveredTool,
        params: Dict[str, Any],
        config: Optional[ExecutionConfig] = None,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> ExecutionResult:
        """
        Execute a tool and collect the complete result.

        Args:
            tool: The tool to execute
            params: Parameter values
            config: Execution configuration
            on_stdout: Callback for stdout lines
            on_stderr: Callback for stderr lines

        Returns:
            ExecutionResult with complete output
        """
        if config is None:
            config = ExecutionConfig()

        result = ExecutionResult(
            tool_name=tool.name,
            status=ExecutionStatus.PENDING,
            start_time=datetime.now(),
        )

        cmd = build_command(tool, params, config)
        execution_id = f"{tool.name}_{result.start_time.timestamp()}"

        stdout_lines = []
        stderr_lines = []

        try:
            result.status = ExecutionStatus.RUNNING

            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=config.working_dir,
                env={**dict(__import__("os").environ), **config.env_vars} if config.env_vars else None,
            )

            self._running_processes[execution_id] = process

            # Read output streams concurrently
            async def read_stdout():
                if process.stdout:
                    async for line in process.stdout:
                        decoded = line.decode("utf-8", errors="replace").rstrip()
                        stdout_lines.append(decoded)
                        if on_stdout:
                            on_stdout(decoded)

            async def read_stderr():
                if process.stderr:
                    async for line in process.stderr:
                        decoded = line.decode("utf-8", errors="replace").rstrip()
                        stderr_lines.append(decoded)
                        if on_stderr:
                            on_stderr(decoded)

            # Handle timeout
            try:
                if config.timeout:
                    await asyncio.wait_for(
                        asyncio.gather(read_stdout(), read_stderr(), process.wait()),
                        timeout=config.timeout
                    )
                else:
                    await asyncio.gather(read_stdout(), read_stderr(), process.wait())
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                result.status = ExecutionStatus.FAILED
                result.error_message = f"Execution timed out after {config.timeout} seconds"

            # Check if cancelled
            if execution_id in self._cancelled:
                result.status = ExecutionStatus.CANCELLED
                self._cancelled.discard(execution_id)
            elif result.status == ExecutionStatus.RUNNING:
                result.status = ExecutionStatus.COMPLETED
                result.exit_code = process.returncode

                if process.returncode != 0:
                    result.status = ExecutionStatus.FAILED
                    result.error_message = f"Tool exited with code {process.returncode}"

        except FileNotFoundError:
            result.status = ExecutionStatus.FAILED
            result.error_message = f"Python executable not found: {sys.executable}"
        except PermissionError:
            result.status = ExecutionStatus.FAILED
            result.error_message = f"Permission denied executing: {tool.tool_path}"
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.error_message = f"Execution error: {str(e)}"
        finally:
            self._running_processes.pop(execution_id, None)
            result.end_time = datetime.now()

        result.stdout = "\n".join(stdout_lines)
        result.stderr = "\n".join(stderr_lines)

        # Try to parse JSON output if present
        if config.json_output and result.stdout:
            try:
                # Look for JSON in the output
                result.json_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Output wasn't valid JSON, that's OK
                pass

        return result

    async def execute_streaming(
        self,
        tool: DiscoveredTool,
        params: Dict[str, Any],
        config: Optional[ExecutionConfig] = None,
    ) -> AsyncGenerator[tuple[str, str], None]:
        """
        Execute a tool with streaming output.

        Yields tuples of (stream_type, line) where stream_type is
        'stdout', 'stderr', 'status', or 'error'.

        Args:
            tool: The tool to execute
            params: Parameter values
            config: Execution configuration

        Yields:
            Tuples of (stream_type, line)
        """
        if config is None:
            config = ExecutionConfig()

        cmd = build_command(tool, params, config)
        execution_id = f"{tool.name}_{datetime.now().timestamp()}"

        yield ("status", f"Starting {tool.display_name}...")
        yield ("status", f"Command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=config.working_dir,
            )

            self._running_processes[execution_id] = process

            # Create queues for both streams
            queue: asyncio.Queue = asyncio.Queue()
            streams_done = {"stdout": False, "stderr": False}

            async def read_stream(stream, stream_type):
                if stream:
                    async for line in stream:
                        decoded = line.decode("utf-8", errors="replace").rstrip()
                        await queue.put((stream_type, decoded))
                streams_done[stream_type] = True
                await queue.put((f"{stream_type}_done", ""))

            # Start reading both streams
            stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))

            # Yield lines as they come
            done_count = 0
            while done_count < 2:
                try:
                    stream_type, line = await asyncio.wait_for(queue.get(), timeout=0.1)
                    if stream_type.endswith("_done"):
                        done_count += 1
                    else:
                        yield (stream_type, line)
                except asyncio.TimeoutError:
                    # Check if process is still running
                    if process.returncode is not None:
                        break

            # Wait for process to complete
            await process.wait()

            # Ensure tasks are done
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

            # Check result
            if execution_id in self._cancelled:
                yield ("status", "Execution cancelled")
                self._cancelled.discard(execution_id)
            elif process.returncode == 0:
                yield ("status", f"{tool.display_name} completed successfully")
            else:
                yield ("error", f"{tool.display_name} failed with exit code {process.returncode}")

        except FileNotFoundError:
            yield ("error", f"Python executable not found: {sys.executable}")
        except PermissionError:
            yield ("error", f"Permission denied executing: {tool.tool_path}")
        except Exception as e:
            yield ("error", f"Execution error: {str(e)}")
        finally:
            self._running_processes.pop(execution_id, None)

    async def cancel(self, tool_name: str) -> bool:
        """
        Cancel execution of a running tool.

        Args:
            tool_name: Name of the tool to cancel

        Returns:
            True if a process was cancelled, False otherwise
        """
        cancelled = False

        for exec_id, process in list(self._running_processes.items()):
            if exec_id.startswith(f"{tool_name}_"):
                self._cancelled.add(exec_id)
                try:
                    process.terminate()
                    # Give it a moment to terminate gracefully
                    await asyncio.sleep(0.5)
                    if process.returncode is None:
                        process.kill()
                    cancelled = True
                except ProcessLookupError:
                    # Process already terminated
                    pass

        return cancelled

    async def cancel_all(self) -> int:
        """
        Cancel all running executions.

        Returns:
            Number of processes cancelled
        """
        count = 0

        for exec_id, process in list(self._running_processes.items()):
            self._cancelled.add(exec_id)
            try:
                process.terminate()
                await asyncio.sleep(0.1)
                if process.returncode is None:
                    process.kill()
                count += 1
            except ProcessLookupError:
                pass

        return count

    def is_running(self, tool_name: str) -> bool:
        """Check if a tool is currently running."""
        return any(
            exec_id.startswith(f"{tool_name}_")
            for exec_id in self._running_processes
        )

    @property
    def running_count(self) -> int:
        """Get the number of currently running executions."""
        return len(self._running_processes)


# Global executor instance
_global_executor: Optional[ToolExecutor] = None


def get_executor() -> ToolExecutor:
    """Get the global tool executor instance."""
    global _global_executor

    if _global_executor is None:
        _global_executor = ToolExecutor()

    return _global_executor


async def execute_tool(
    tool: DiscoveredTool,
    params: Dict[str, Any],
    plan_mode: bool = False,
    on_output: Optional[Callable[[str, str], None]] = None,
) -> ExecutionResult:
    """
    Convenience function to execute a tool.

    Args:
        tool: The tool to execute
        params: Parameter values
        plan_mode: Whether to run in plan mode
        on_output: Callback for output (receives stream_type and line)

    Returns:
        ExecutionResult
    """
    executor = get_executor()
    config = ExecutionConfig(plan_mode=plan_mode)

    if on_output:
        def on_stdout(line: str):
            on_output("stdout", line)

        def on_stderr(line: str):
            on_output("stderr", line)

        return await executor.execute(
            tool, params, config,
            on_stdout=on_stdout,
            on_stderr=on_stderr
        )
    else:
        return await executor.execute(tool, params, config)
