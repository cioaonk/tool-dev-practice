# CPTC11 Terminal User Interface (TUI) User Guide

## Module Overview

**Purpose:** This guide provides comprehensive training on the CPTC11 Security Toolsmith Terminal User Interface (TUI), a keyboard-driven terminal application for executing and managing security assessment tools.

**Learning Objectives:**
- Understand the TUI architecture and component layout
- Navigate efficiently using keyboard shortcuts
- Execute security tools with proper parameter configuration
- Integrate Docker containers and CORE network topologies as targets
- Customize the interface for operational workflows

**Target Audience:** Security practitioners with basic terminal experience

**Prerequisites:**
- Familiarity with command-line interfaces
- Basic understanding of penetration testing concepts
- Python 3.8+ environment configured

---

## 1. TUI Introduction

### 1.1 Purpose and Benefits

The CPTC11 TUI provides a unified terminal-based interface for security assessment operations. Unlike traditional command-line tool execution, the TUI offers:

**Operational Advantages:**
- Centralized tool discovery and execution from a single interface
- Real-time streaming output with severity-based color coding
- Visual attack pattern tracking and network topology mapping
- Integrated Docker container and CORE network target management
- Parameter validation and configuration persistence

**Training Benefits:**
- Reduces cognitive load by presenting tools in organized categories
- Provides immediate visual feedback on tool execution status
- Tracks operation history for post-assessment review

### 1.2 Technology Stack

The TUI is built on the **Textual framework**, a modern Python library for building rich terminal applications.

**Key Technologies:**
- **Textual 0.47+**: Async-first TUI framework with CSS-like styling
- **Rich**: Terminal rendering library for formatted output
- **asyncio**: Asynchronous execution for non-blocking tool runs
- **Python 3.8+**: Core runtime environment

### 1.3 Installation Requirements

**System Dependencies:**
```bash
# Ensure Python 3.8+ is installed
python3 --version

# Install required packages
pip install textual rich

# For Docker integration (optional)
docker --version

# For CORE network integration (optional)
which core-cli
```

**Launching the TUI:**
```bash
# From the project root
cd /Users/ic/cptc11
python -m python.tui

# Or using the module directly
python /Users/ic/cptc11/python/tui/__main__.py
```

---

## 2. Interface Overview

### 2.1 Dashboard Layout

The TUI presents a multi-panel interface optimized for security operations. Understanding this layout is essential for efficient navigation.

```
+============================================================================+
|                    Security Toolsmith          [Clock: HH:MM:SS]           |
+============================================================================+
|                           |                           |                    |
|   SECURITY TOOLS          |      Tool Output          | ATTACK PATTERN     |
|   ==================      |      ===========          | VISUALIZER         |
|                           |                           | ================   |
|   >> RECONNAISSANCE       | [HH:MM:SS] [INF] Message  |                    |
|   +------------------+    | [HH:MM:SS] [OK ] Success  | Network Topology   |
|   | Port Scanner     |    | [HH:MM:SS] [WRN] Warning  |                    |
|   | Network          |    | [HH:MM:SS] [ERR] Error    |    [*] Attacker    |
|   +------------------+    |                           |         |          |
|                           |                           |         v          |
|   >> WEB TESTING          |                           |    [@] Gateway     |
|   +------------------+    |                           |         |          |
|   | Vuln Scanner     |    |                           |    +----+----+     |
|   +------------------+    |                           |    |         |     |
|                           |                           |   [S]       [S]    |
|   >> CREDENTIAL TESTING   |                           |  Web        DB     |
|   +------------------+    |                           |                    |
|   | Attack Simulator |    |                           | Event Log          |
|   +------------------+    |                           | ----------------   |
|                           |                           | 12:30:15 [MED]     |
|   5 tools available       | 15 entries | Auto: ON    | Port Scan: -> tgt  |
|                           |                           |                    |
+---------------------------+---------------------------+--------------------+
|  [*] READY | Tool: None | Duration: --:-- | Ops: 0           [HH:MM:SS]   |
+============================================================================+
| q Quit | h Help | r Refresh | c Clear | D Docker | N Network              |
+============================================================================+
```

### 2.2 Tool Panel (Left Sidebar)

The Tool Panel displays all discovered security tools organized by category.

**Features:**
- Automatic tool discovery from the `tools/` directory
- Category-based grouping (Reconnaissance, Web Testing, etc.)
- Visual selection highlighting
- Tool count display

**Tool Categories:**
| Category | Description |
|----------|-------------|
| Reconnaissance | Network and host discovery tools |
| Web Testing | Web application security tools |
| Credential Testing | Password and authentication tools |
| Network Services | Service enumeration and testing |
| Evasion/Payload | Payload generation and AV bypass |
| Exploitation | Exploitation framework tools |

### 2.3 Output Viewer (Center Panel)

The Output Viewer displays real-time tool execution output with intelligent formatting.

**Log Level Indicators:**
| Prefix | Level | Color | Meaning |
|--------|-------|-------|---------|
| `[DBG]` | Debug | Dim | Verbose debugging information |
| `[INF]` | Info | White | Standard informational messages |
| `[OK ]` | Success | Green | Successful operations/findings |
| `[WRN]` | Warning | Yellow | Warnings requiring attention |
| `[ERR]` | Error | Red | Error conditions |

**Auto-Detection Patterns:**
The viewer automatically classifies output based on content:
- Lines containing `[+]`, `success`, `found`, `open` -> Success (green)
- Lines containing `error`, `fail`, `[!]` -> Error (red)
- Lines containing `warning`, `warn`, `[w]` -> Warning (yellow)

### 2.4 Status Bar (Bottom)

The status bar provides real-time operational awareness.

```
+----------------------------------------------------------------------------+
|  [*] READY | Tool: Port Scanner | Duration: 02:15 | Ops: 3    [14:30:25]  |
+----------------------------------------------------------------------------+
```

**Status Indicators:**
| Icon | Status | Meaning |
|------|--------|---------|
| `[green]*[/green]` | READY | System idle, awaiting command |
| `[yellow]@[/yellow]` | RUNNING | Tool currently executing |
| `[green]v[/green]` | COMPLETE | Last operation succeeded |
| `[red]X[/red]` | ERROR | Last operation failed |
| `[dim]o[/dim]` | CANCELLED | Operation was cancelled |

### 2.5 Attack Visualizer (Right Panel)

The Attack Visualizer provides ASCII-based network topology and attack pattern visualization.

**Topology Symbols:**
| Symbol | Node Type |
|--------|-----------|
| `[skull]` | Attacker system |
| `[target]` | Target host |
| `[hexagon]` | Network gateway |
| `[square]` | Server |
| `[box]` | Workstation |

**Event Severity Indicators:**
| Icon | Severity | Color |
|------|----------|-------|
| `o` | Low | Green |
| `@` | Medium | Yellow |
| `*` | High | Red |
| `O` | Critical | Red (bold) |

---

## 3. Keyboard Navigation

### 3.1 Complete Keyboard Shortcuts

**Global Application Bindings:**
| Key | Action | Description |
|-----|--------|-------------|
| `Ctrl+Q` | Quit | Exit the application |
| `Ctrl+D` | Toggle Dark Mode | Switch between light/dark themes |

**Dashboard Screen Bindings:**
| Key | Action | Description |
|-----|--------|-------------|
| `q` | Quit | Exit from dashboard |
| `h` | Help | Display help information |
| `r` | Refresh | Refresh the display |
| `c` | Clear Output | Clear the output viewer |
| `D` | Docker Screen | Open Docker management |
| `N` | Network Screen | Open CORE network management |
| `Escape` | Cancel | Cancel running operation |

**Docker Screen Bindings:**
| Key | Action | Description |
|-----|--------|-------------|
| `Escape` | Back | Return to dashboard |
| `r` | Refresh | Refresh container list |
| `u` | Compose Up | Start all Docker services |
| `d` | Compose Down | Stop all Docker services |
| `l` | View Logs | View selected container logs |
| `e` | Exec | Execute command in container |
| `t` | Run Tool | Run tool against container |
| `s` | Start | Start selected container |
| `x` | Stop | Stop selected container |

**Network Screen Bindings:**
| Key | Action | Description |
|-----|--------|-------------|
| `q` / `Escape` | Back | Return to dashboard |
| `r` | Refresh | Refresh network status |
| `s` | Start Network | Start selected topology |
| `x` | Stop Network | Stop current session |
| `g` | Open GUI | Launch CORE GUI |
| `t` | Terminal | Open terminal to selected node |

### 3.2 Navigation Patterns

**Tool Selection:**
1. Use `Tab` or arrow keys to navigate to the Tool Panel
2. Use `Up/Down` arrows to browse tools within categories
3. Press `Enter` to select a tool for configuration

**Input Field Navigation:**
1. Within configuration dialogs, use `Tab` to move between fields
2. Press `Enter` in the last field to submit
3. Press `Escape` to cancel and return

**Panel Focus:**
- `Tab` cycles focus between major panels
- Arrow keys navigate within the focused panel
- `Enter` activates the selected item

### 3.3 Dark Mode Toggle

The TUI supports both light and dark display modes for different operational environments.

**Toggling:**
- Press `Ctrl+D` to toggle between modes
- The setting persists for the current session

**Considerations:**
- Dark mode (default) is optimized for low-light environments
- Light mode may be preferred for screen sharing or documentation

---

## 4. Tool Execution Workflow

### 4.1 Selecting Tools

**Step 1: Browse Available Tools**
Navigate to the Tool Panel and review tools by category.

```
SECURITY TOOLS
==============
>> RECONNAISSANCE
+------------------+
| Port Scanner     |  <-- Use arrows to highlight
| Recon            |
+------------------+

5 tools available
```

**Step 2: Select a Tool**
Press `Enter` on the highlighted tool to open the configuration screen.

### 4.2 Configuring Parameters

When a tool is selected, a modal configuration screen appears.

```
+================================================================+
|              Configure: Port Scanner                            |
+================================================================+
| Scan network ports to discover open services                    |
+----------------------------------------------------------------+
|                                                                 |
| [red]*[/red] target (str)                                       |
| Target IP address or hostname                                   |
| [________________________________________________]              |
|                                                                 |
| ports (str)                                                     |
| Port range to scan (e.g., 1-1000, 22,80,443)                   |
| [________________________________________________]              |
|                                                                 |
| [red]*[/red] Required fields                                    |
|                                                                 |
+----------------------------------------------------------------+
|              [ Cancel ]         [ Run Tool ]                    |
+================================================================+
```

**Parameter Input Guidelines:**
- Required fields are marked with `[red]*[/red]`
- Default values are pre-populated where available
- Use `Tab` to move between fields
- Press `Enter` in the last field or click "Run Tool" to execute

### 4.3 Running Tools

After configuration, tool execution begins immediately.

**Execution Flow:**
1. Status bar updates to "RUNNING" with tool name
2. Output streams to the Output Viewer in real-time
3. Duration timer starts tracking execution time
4. Upon completion, status changes to "COMPLETE" or "ERROR"

**Real-Time Output Example:**
```
14:30:15 [INF] Running Port Scanner...
14:30:15 [DBG] Target: 192.168.1.100
14:30:15 [DBG] Ports: 1-1000
14:30:15 [INF] Executing: /path/to/tools/port-scanner/tool.py
14:30:16 [INF] [*] Scanning 192.168.1.100...
14:30:17 [OK ] [+] Port 22 open (SSH)
14:30:17 [OK ] [+] Port 80 open (HTTP)
14:30:18 [OK ] [+] Port 443 open (HTTPS)
14:30:20 [OK ] === Port Scanner Execution Complete ===
```

### 4.4 Viewing Output

**Output Viewer Features:**
- Scrollable history (up to 10,000 lines)
- Auto-scroll to latest output (toggle with internal control)
- Color-coded by severity level
- Timestamp for each entry

**Entry Format:**
```
HH:MM:SS [LVL] Message content here
```

### 4.5 Saving Results

Results can be exported from the Output Viewer.

**Export Options:**
- Plain text export via the `export_text()` method
- Format preserves timestamps and log levels
- Suitable for inclusion in assessment reports

**Export Format Example:**
```
[2024-01-15 14:30:15] [INFO] Running Port Scanner...
[2024-01-15 14:30:17] [SUCCESS] [+] Port 22 open (SSH)
[2024-01-15 14:30:17] [SUCCESS] [+] Port 80 open (HTTP)
```

---

## 5. Docker Integration

### 5.1 Connecting to Docker Targets

The TUI integrates with Docker to discover and target containers for security assessment.

**Accessing Docker Screen:**
Press `D` from the dashboard or use the footer menu.

**Docker Screen Layout:**
```
+============================================================================+
|                      Docker Management Screen                              |
+============================================================================+
|                    |                              |                        |
| CONTAINERS         |  Container Logs              | CONTROLS               |
| =============      |  ==============              | ========               |
|                    |                              |                        |
| [*] web-server     | 14:30:15 Container started   | [ Start ]              |
|     Status: Up     | 14:30:16 Listening on :80    | [ Stop  ]              |
| [ ] db-server      | 14:30:17 Connection from     | [ Restart ]            |
|     Status: Up     |          192.168.1.1         | [ Exec ]               |
| [ ] api-gateway    |                              | [ Logs ]               |
|     Status: Exited |                              | [ Run Tool ]           |
|                    |                              |                        |
+--------------------+------------------------------+------------------------+
| STATS              | ATTACK SCENARIOS                                      |
| ======             | =================                                     |
| CPU: 2.5%          | [>] Web Application Scan                              |
| Mem: 128MB/512MB   | [>] Database Enumeration                              |
| Net: 1.2KB/s       | [>] API Security Testing                              |
+--------------------+-------------------------------------------------------+
|  [green]Ready[/green] | Container: web-server                  [14:30:25] |
+============================================================================+
```

### 5.2 Container Selection

**Selecting a Container:**
1. Navigate to the container list panel
2. Use arrow keys to highlight a container
3. The container details populate in the stats and controls panels

**Container Information Displayed:**
- Container name and ID
- Current status (running/stopped/exited)
- CPU and memory usage
- Network I/O statistics

### 5.3 Service Targeting

When running tools against Docker containers, the TUI provides service-aware targeting.

**Target Selection Modal:**
```
+================================================+
|         Run Tool Against Container              |
+================================================+
| Target: web-server (172.17.0.2)                 |
+-------------------------------------------------+
|                                                 |
| [>] Port Scanner - Scan container ports         |
| [>] Vuln Scanner - Scan for vulnerabilities     |
| [>] Network Mapper - Map container network      |
| [>] Attack Simulator - Simulate attacks         |
|                                                 |
| [ Cancel ]                                      |
+================================================+
```

**Workflow:**
1. Select container from list
2. Press `t` or click "Run Tool"
3. Select tool from modal
4. Configure with pre-populated target IP
5. Execute and monitor output

---

## 6. CORE Network Integration

### 6.1 Loading Topologies

The TUI integrates with CORE Network Emulator for complex network simulations.

**Accessing Network Screen:**
Press `N` from the dashboard.

**Network Screen Layout:**
```
+============================================================================+
|                    CORE Network Management Screen                          |
+============================================================================+
|                  |                                |                         |
| TOPOLOGIES       |  TOPOLOGY VISUALIZATION       | CONTROLS                |
| ===========      |  ======================       | ========                |
|                  |                                |                         |
| [*] lab-net.imn  |      [*] Attacker             | Session: 1              |
| [ ] dmz-net.imn  |           |                   | Status: Running         |
| [ ] corp-net.imn |           v                   |                         |
|                  |      [@] Gateway              | [ Start Network ]       |
|                  |           |                   | [ Stop Network ]        |
|                  |      +----+----+              | [ Open GUI ]            |
|                  |      |         |              | [ Refresh ]             |
|                  |     [S]       [S]             |                         |
|                  |    Web        DB              |                         |
|                  |                                |                         |
+------------------+--------------------------------+-------------------------+
| NODE TABLE                        | NODE ACTIONS      | TRAFFIC MONITOR    |
| ==========                        | ============      | ===============    |
| Name     | IP          | Status   |                   |                    |
| ---------|-------------|----------|                   |                    |
| gateway  | 10.0.0.1    | Running  | [ Terminal ]      | Packets: 1,234     |
| web-srv  | 10.0.0.10   | Running  | [ Start ]         | Bytes: 45.2 KB     |
| db-srv   | 10.0.0.20   | Running  | [ Stop ]          | Errors: 0          |
|          |             |          | [ Run Tool ]      |                    |
+-----------------------------------+-------------------+--------------------+
| [Network Log] 14:30:15 Network started successfully                        |
+============================================================================+
```

### 6.2 Target Selection

**Selecting Nodes:**
1. Select a topology file from the list
2. The topology visualizer renders the network diagram
3. Nodes populate in the node table
4. Click or navigate to select a specific node

**Node Information:**
- Node name and type
- IP address(es)
- Running services
- Current status

### 6.3 Network Visualization

The topology visualizer renders ASCII network diagrams showing:
- Node relationships and connectivity
- IP address assignments
- Node types (router, server, workstation)
- Link status

**Example Visualization:**
```
Network Topology
================

    [skull] Attacker
         |
         v
    [hexagon] Gateway (10.0.0.1)
         |
    +----+----+
    |         |
    v         v
[square] Web    [square] DB
(10.0.0.10)   (10.0.0.20)

Legend: [skull]=Attacker  [hexagon]=Gateway  [square]=Server  [box]=Workstation
```

---

## 7. Customization Guide

### 7.1 Adding New Tools

Tools are automatically discovered from the `tools/` directory. To add a new tool:

**Step 1: Create Tool Directory**
```bash
mkdir -p /Users/ic/cptc11/tools/my-new-tool
```

**Step 2: Create Tool File (`tool.py`)**
```python
#!/usr/bin/env python3
"""My New Security Tool"""

import argparse

def get_documentation():
    """Return tool documentation for TUI discovery."""
    return {
        "name": "my-new-tool",
        "description": "Description of what the tool does",
        "category": "reconnaissance",  # or web, credential, network, etc.
        "version": "1.0.0",
        "author": "Your Name",
        "arguments": [
            {
                "name": "--target",
                "type": "string",
                "required": True,
                "description": "Target to scan"
            },
            {
                "name": "--verbose",
                "type": "bool",
                "required": False,
                "default": False,
                "description": "Enable verbose output"
            }
        ],
        "features": [
            "Feature 1",
            "Feature 2"
        ],
        "examples": [
            {
                "description": "Basic usage",
                "command": "python tool.py --target 192.168.1.1"
            }
        ],
        "opsec_notes": [
            "OPSEC consideration 1",
            "OPSEC consideration 2"
        ]
    }

def main():
    parser = argparse.ArgumentParser(description="My New Tool")
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Tool implementation here
    print(f"[*] Scanning target: {args.target}")

if __name__ == "__main__":
    main()
```

**Step 3: Restart TUI**
The tool will be automatically discovered on next launch.

### 7.2 Theme Customization

The TUI uses TCSS (Textual CSS) for styling, located at:
```
/Users/ic/cptc11/python/tui/styles/main.tcss
```

**Common Customizations:**

**Change Status Bar Colors:**
```css
ToolsmithStatusBar #status-indicator.--ready {
    color: $success;  /* Change ready state color */
}

ToolsmithStatusBar #status-indicator.--running {
    color: $warning;  /* Change running state color */
}
```

**Adjust Panel Borders:**
```css
ToolPanel {
    border: solid $primary;  /* Options: solid, double, round, none */
}
```

**Modify Output Viewer Background:**
```css
OutputViewer {
    background: $surface-darken-2;
}
```

### 7.3 Widget Configuration

Individual widgets can be configured through their class attributes.

**OutputViewer Settings:**
```python
# In output_viewer.py
yield RichLog(
    id="output-log",
    highlight=True,      # Syntax highlighting
    markup=True,         # Rich markup support
    auto_scroll=True,    # Auto-scroll to new content
    max_lines=10000,     # Maximum line buffer
)
```

**Attack Visualizer Symbols:**
```python
# In attack_visualizer.py
NODE_SYMBOLS = {
    "attacker": "[skull]",      # Change attacker symbol
    "target": "[target]",       # Change target symbol
    "gateway": "[hexagon]",     # Change gateway symbol
    "server": "[square]",       # Change server symbol
    "workstation": "[box]",     # Change workstation symbol
}
```

---

## 8. Hands-On Tutorial: Complete Penetration Testing Session

This tutorial walks through a complete security assessment workflow using the TUI.

### Scenario

You are conducting a security assessment of a Docker-based lab environment containing:
- A web server (nginx)
- A database server (MySQL)
- An API gateway

### Step 1: Launch the TUI

```bash
cd /Users/ic/cptc11
python -m python.tui
```

**Expected Output:**
```
14:30:00 [INF] Security Toolsmith TUI initialized
14:30:00 [OK ] Discovered 5 security tools
14:30:00 [DBG] Categories: Credential Testing, Reconnaissance, Web Testing
14:30:00 [INF] Select a tool from the left panel to begin
```

### Step 2: Access Docker Environment

1. Press `D` to open the Docker screen
2. Wait for container list to populate
3. Verify containers are running

**Container List Should Show:**
```
CONTAINERS
=============
[*] web-server      (Up 2 hours)
[ ] db-server       (Up 2 hours)
[ ] api-gateway     (Up 2 hours)
```

### Step 3: Reconnaissance - Port Scan Web Server

1. Select `web-server` from the container list
2. Press `t` to run a tool
3. Select "Port Scanner" from the modal
4. Verify target IP is pre-populated
5. Enter port range: `1-1000`
6. Click "Run Tool"

**Expected Output:**
```
14:31:15 [INF] Running Port Scanner...
14:31:15 [DBG] Target: 172.17.0.2
14:31:15 [DBG] Ports: 1-1000
14:31:16 [INF] [*] Scanning 172.17.0.2...
14:31:18 [OK ] [+] Port 80 open (HTTP)
14:31:18 [OK ] [+] Port 443 open (HTTPS)
14:31:20 [OK ] === Port Scanner Execution Complete ===
```

### Step 4: Vulnerability Assessment

1. Return to dashboard (press `Escape`)
2. Navigate to Tool Panel
3. Select "Vuln Scanner" under Web Testing
4. Configure:
   - Target: `172.17.0.2:80`
   - Scan Type: `full`
5. Execute and monitor results

### Step 5: Review Attack Visualizer

After running tools, the Attack Visualizer updates automatically.

**Expected Visualization:**
```
Attack Timeline Summary
========================================

14:31:20 | medium   | Port Scanner
14:32:45 | medium   | Vuln Scanner

Total events: 2
```

**Attack Graph:**
```
Toolsmith
   +---> 172.17.0.2
```

### Step 6: Network Topology Assessment (Advanced)

1. Press `N` to open Network screen
2. Select a topology file (e.g., `lab-net.imn`)
3. Review parsed nodes in the node table
4. Select a node and press `t` to run tools
5. Monitor network-wide results

### Step 7: Export Results

1. Return to dashboard
2. Review complete output history in Output Viewer
3. Use export functionality to save results
4. Clear output with `c` for next assessment phase

### Step 8: Clean Up

1. Return to Docker screen (`D`)
2. Press `d` to run `docker-compose down`
3. Verify containers stopped
4. Press `q` to exit TUI

---

## Quick Reference Card

### Essential Shortcuts
| Action | Key |
|--------|-----|
| Quit Application | `Ctrl+Q` |
| Toggle Dark Mode | `Ctrl+D` |
| Docker Screen | `D` |
| Network Screen | `N` |
| Help | `h` |
| Refresh | `r` |
| Clear Output | `c` |
| Cancel Operation | `Escape` |

### Status Indicators
| Status | Icon | Color |
|--------|------|-------|
| Ready | `*` | Green |
| Running | `@` | Yellow |
| Complete | `v` | Green |
| Error | `X` | Red |
| Cancelled | `o` | Gray |

### Log Levels
| Level | Prefix | Color |
|-------|--------|-------|
| Debug | `[DBG]` | Dim |
| Info | `[INF]` | White |
| Success | `[OK ]` | Green |
| Warning | `[WRN]` | Yellow |
| Error | `[ERR]` | Red |

---

## Troubleshooting

### Common Issues

**Tools Not Discovered:**
- Verify tools directory exists: `/Users/ic/cptc11/tools/`
- Check tool files have `get_documentation()` function
- Review console for discovery errors on startup

**Docker Connection Failed:**
- Ensure Docker daemon is running: `docker info`
- Check Docker socket permissions
- Verify network connectivity to Docker API

**CORE Network Unavailable:**
- Install CORE: `sudo apt-get install core-network`
- Verify core-cli is in PATH: `which core-cli`
- Check CORE daemon status: `systemctl status core-daemon`

**Keyboard Shortcuts Not Working:**
- Ensure terminal supports the key combination
- Check for conflicting terminal emulator bindings
- Try alternative keys if available

---

## Appendix: File Locations

| Component | Path |
|-----------|------|
| Main Application | `/Users/ic/cptc11/python/tui/app.py` |
| Tool Panel Widget | `/Users/ic/cptc11/python/tui/widgets/tool_panel.py` |
| Output Viewer Widget | `/Users/ic/cptc11/python/tui/widgets/output_viewer.py` |
| Status Bar Widget | `/Users/ic/cptc11/python/tui/widgets/status_bar.py` |
| Attack Visualizer | `/Users/ic/cptc11/python/tui/visualizers/attack_visualizer.py` |
| Docker Screen | `/Users/ic/cptc11/python/tui/screens/docker_screen.py` |
| Network Screen | `/Users/ic/cptc11/python/tui/screens/network_screen.py` |
| Tool Config Screen | `/Users/ic/cptc11/python/tui/screens/tool_config.py` |
| Tool Discovery | `/Users/ic/cptc11/python/tui/utils/tool_discovery.py` |
| Styles | `/Users/ic/cptc11/python/tui/styles/main.tcss` |

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Word Count: ~2,800 words*
