# CPTC11 Multi-Agent System Training Guide

**Version**: 1.0
**Last Updated**: 2026-01-10
**Author**: Offensive Security Trainer Agent
**Classification**: Internal Training Material

---

## Table of Contents

1. [Introduction to Multi-Agent Development](#introduction-to-multi-agent-development)
2. [Agent Roster - Complete Documentation](#agent-roster---complete-documentation)
3. [Agent Coordination Patterns](#agent-coordination-patterns)
4. [Creating Custom Agents](#creating-custom-agents)
5. [Appendix: Quick Reference](#appendix-quick-reference)

---

## Introduction to Multi-Agent Development

### What is Multi-Agent Software Development?

Multi-agent software development represents a paradigm shift in how complex software projects are conceived, executed, and maintained. Rather than relying on a single monolithic process or a team of human developers working in isolation, multi-agent systems leverage specialized autonomous agents that collaborate to achieve project objectives. Each agent possesses domain-specific expertise, dedicated tools, and clearly defined responsibilities that align with their area of specialization.

In the context of AI-assisted development, multi-agent systems utilize Large Language Models (LLMs) configured with specific system prompts, tool access, and behavioral guidelines that shape their operation. These agents operate semi-autonomously, making decisions within their domain while coordinating with other agents through established protocols and communication channels. The result is a development ecosystem that mirrors the specialization found in high-performing human teams, but with the consistency, availability, and scalability that AI systems provide.

The fundamental principle underlying multi-agent development is the division of cognitive labor. Just as a penetration testing team includes specialists in web application security, network exploitation, social engineering, and report writing, a multi-agent system divides responsibilities among purpose-built agents. This specialization allows each agent to develop deep expertise in its domain, maintain consistent quality standards, and operate with minimal supervision once properly configured.

### Benefits of Specialized Agents

The advantages of deploying specialized agents over generalist approaches are substantial and measurable. First, **domain expertise** allows agents to maintain context-appropriate knowledge, use specialized vocabulary correctly, and apply domain-specific best practices without requiring explicit instruction for each task. An Offensive Security Toolsmith agent inherently understands OPSEC considerations, while a QA Tester agent naturally applies testing methodologies.

Second, **parallel execution** enables multiple workstreams to progress simultaneously. While the Python-to-Golang Converter processes tool conversions, the UX TUI Developer can independently advance interface work, and the QA Tester can develop test suites. This parallelization dramatically reduces project timelines compared to sequential processing.

Third, **quality through specialization** emerges when agents focus on their core competencies. A Safety Monitor agent reviewing code for vulnerabilities will catch issues that a generalist might miss, while a YARA Detection Engineer produces higher-fidelity signatures than an agent without detection engineering specialization.

Fourth, **accountability and traceability** improve when each agent maintains its own reporting cadence and output locations. Project managers can quickly identify which agent produced specific deliverables, track progress through dedicated reports, and pinpoint bottlenecks in the development pipeline.

Fifth, **scalability and maintainability** are enhanced because new agents can be added to address emerging needs without disrupting existing workflows. Agent configurations can be updated independently, and the system can scale to accommodate larger projects by instantiating additional specialized agents.

### The CPTC11 Agent Coordination Model

The CPTC11 project implements a hierarchical coordination model with 21 specialized agents organized into functional categories. At the apex sits the **Project Coordinator**, which orchestrates work across all agents, manages dependencies, and ensures documentation consistency. Below this coordination layer, agents are grouped by function:

**Development Agents** handle code creation and conversion, including the Offensive Security Toolsmith, Python-to-Golang Converter, and UX TUI Developer. **Quality Agents** ensure output meets standards through the QA Tester, Safety Monitor, and Agent Performance Auditor. **Infrastructure Agents** manage environments and pipelines via the Docker Test Env Builder, CORE Network Builder, and DevOps CI/CD Integrator. **Intelligence Agents** provide research and detection capabilities through the Docker Threat Intel Analyst and YARA Detection Engineer. **Support Agents** handle auxiliary functions including Version Control Sync, Usage Reporter, and the Agent Cheerleader.

This model implements several key coordination patterns: periodic reporting cycles ensure visibility into agent activities; dependency chains trigger downstream agents when precursor work completes; shared output directories enable agents to consume each other's work products; and escalation protocols route blockers to appropriate resolution paths.

The following sections provide comprehensive documentation for each agent, followed by detailed explanations of coordination patterns and guidance for creating custom agents to extend the system.

---

## Agent Roster - Complete Documentation

This section documents all 21 agents in the CPTC11 multi-agent system. Each entry provides the information necessary to understand, invoke, and integrate with the agent.

---

### 1. Project Coordinator

```
+--------------------------------------------------+
|  PROJECT COORDINATOR                              |
|  Model: Opus | Color: Blue                       |
+--------------------------------------------------+
```

**Purpose**: Orchestration agent for managing multiple specialized agents working together on a project. Coordinates work, tracks progress, and ensures documentation is maintained.

**Specialized Capabilities**:
- Orchestrate multiple specialized agents simultaneously
- Coordinate between different workstreams (development, testing, documentation)
- Track project status and progress across all active agents
- Generate consolidated status reports at 20-minute intervals
- Manage agent dependencies and resolve conflicts
- Ensure documentation consistency across the project
- Prioritize and sequence tasks to maximize efficiency
- Facilitate handoffs between agents when work products flow between them

**Tools Available**:
- Edit
- Write
- TodoWrite
- WebSearch
- Read
- Grep

**When to Invoke**:
- Multi-agent project work requiring coordination
- Coordinating Python-to-Go conversion with tool development
- Periodic status report generation (every 20 minutes)
- Cross-functional project management
- When conflicts arise between agent activities
- When dependency management is needed

**Example Prompts/Tasks**:
```
"Coordinate the development of security tools and their Go conversions"
"Generate a status report on all active agents"
"Orchestrate testing, documentation, and deployment tasks"
"What's the status of all the agents working on the project?"
"It's been 20 minutes, can you check on progress?"
```

**Integration with Other Agents**:
- Receives status updates from all agents
- Triggers downstream agents when precursor work completes
- Escalates blockers from any agent to appropriate resolution
- Ensures Documentation Agent captures work from technical agents
- Coordinates handoffs between Toolsmith and Converter agents

**Output Location**: `/Users/ic/cptc11/agent_reports/`

---

### 2. Offensive Security Toolsmith

```
+--------------------------------------------------+
|  OFFENSIVE SECURITY TOOLSMITH                     |
|  Model: Opus | Color: Red                        |
+--------------------------------------------------+
```

**Purpose**: Specialized agent for developing custom penetration testing tools, security assessment utilities, and offensive security tooling with emphasis on stealth and operational security.

**Specialized Capabilities**:
- Develop custom penetration testing tools
- Create security assessment utilities
- Build offensive security tooling with OPSEC focus
- Implement stealth and in-memory execution features
- Design cross-language portable tools
- Add planning mode (`--plan`) to all tools
- Implement documentation hooks (`get_documentation()`)
- Consider detection vectors in all designs
- Generate 15-minute progress reports

**Tools Available**: All tools available in the system.

**Development Standards**:
- All tools must include `--plan` mode for dry-run
- All tools must include `get_documentation()` function
- Code must be portable (Python with Go conversion potential)
- Must consider detection vectors
- Must include proper error handling
- Minimize disk writes and file system artifacts
- Use in-memory execution where possible

**When to Invoke**:
- Building new penetration testing tools
- Creating security assessment utilities
- Enhancing existing tools with stealth features
- Developing tools for CPTC competition
- Iterative tool development with OPSEC focus

**Example Prompts/Tasks**:
```
"Create a network scanner with stealth options"
"Build a credential validator with rate limiting"
"Develop a payload generator with encoding options"
"I need to start developing custom pentest tools for the CPTC competition"
"Can you enhance the memory-resident capabilities of our recon tools?"
```

**Integration with Other Agents**:
- Triggers Python-to-Golang Converter when Python tool is complete
- Provides tools to QA Tester for test development
- Supplies documentation hooks for Documentation Agent
- Reports progress to Project Coordinator every 15 minutes
- Provides tools to YARA Detection Engineer for signature development

**Output Location**: `/Users/ic/cptc11/python/tools/<tool-name>/`

---

### 3. Python-to-Golang Converter

```
+--------------------------------------------------+
|  PYTHON-TO-GOLANG CONVERTER                       |
|  Model: Opus | Color: Green                      |
+--------------------------------------------------+
```

**Purpose**: Expert polyglot programmer specializing in Python-to-Go code conversion with deep knowledge of idiomatic patterns in both languages. Automatically discovers, converts, and tracks Python code transformations.

**Specialized Capabilities**:
- Scan project directory every 5 minutes for Python files
- Track which files have been converted and detect changes
- Maintain state file to avoid redundant conversions
- Convert Python syntax to idiomatic Go patterns
- Preserve directory structure in conversions
- Add appropriate Go package declarations and imports
- Include comments explaining non-obvious conversions
- Log all conversions with timestamps and metrics
- Verify Go code compiles (when possible)

**Conversion Patterns**:
| Python | Go |
|--------|-----|
| Functions | Functions with explicit types |
| Classes | Structs with methods |
| List comprehensions | Loops or slice operations |
| Decorators | Function wrappers or middleware |
| Exceptions | Error returns |
| Duck typing | Interfaces |
| dict | struct with JSON tags |
| list | slice |
| None | nil, zero values, or error |

**Tools Available**: All tools available in the system.

**When to Invoke**:
- When new Python code is added to the project
- When Python code is modified and needs re-conversion
- For automatic conversion setup (5-minute monitoring)
- When manual conversion is requested

**Example Prompts/Tasks**:
```
"I've added a new data processing script in utils/processor.py"
"Can you set up automatic conversion of Python to Go?"
"I just updated the authentication module in auth/login.py"
"Convert all Python tools to Go"
```

**Integration with Other Agents**:
- Triggered by Toolsmith when Python tool is complete
- Reports conversion status to Project Coordinator
- Provides converted code to QA Tester for Go testing
- Logs all activities to conversion_log.txt

**Output Locations**:
- Converted code: `/Users/ic/cptc11/golang/`
- Conversion log: `/Users/ic/cptc11/conversion_log.txt`

---

### 4. QA Tester

```
+--------------------------------------------------+
|  QA TESTER                                        |
|  Model: Opus | Color: Green                      |
+--------------------------------------------------+
```

**Purpose**: Automated testing agent for developing tests, running regression testing, and expanding test coverage. Works proactively after code is developed by other agents.

**Specialized Capabilities**:
- Develop unit tests for new functionality
- Create integration tests for component interaction
- Run regression testing after changes
- Expand test coverage systematically
- Implement fuzz testing using Hypothesis
- Create edge case tests for boundary conditions
- Generate coverage reports
- Document test failures and fixes

**Testing Types**:
1. **Unit Tests**: Individual function/class testing
2. **Integration Tests**: Component interaction testing
3. **Edge Case Tests**: Boundary condition testing
4. **Fuzz Tests**: Random input testing (Hypothesis)
5. **Performance Tests**: Speed and resource testing
6. **Security Tests**: Input sanitization testing

**Test Framework Stack**:
- **Framework**: pytest
- **Async**: pytest-asyncio
- **Fuzzing**: hypothesis
- **Mocking**: unittest.mock
- **Coverage**: pytest-cov

**Test Markers**:
- `@pytest.mark.unit`
- `@pytest.mark.smoke`
- `@pytest.mark.slow`
- `@pytest.mark.regression`
- `@pytest.mark.security`

**Tools Available**: All tools available in the system.

**When to Invoke**:
- After new code is developed
- When regression testing is needed
- To expand test coverage
- For edge case identification
- After bug fixes to prevent regression

**Example Prompts/Tasks**:
```
"Create unit tests for the network scanner tool"
"Add fuzz testing for input validation"
"Develop integration tests for the Docker environment"
"Run regression tests after the credential validator changes"
```

**Integration with Other Agents**:
- Receives tools from Toolsmith for testing
- Reports test results to Project Coordinator
- Provides test coverage data to Agent Performance Auditor
- Works with DevOps CI/CD Integrator for automated testing

**Output Locations**:
- Main tests: `/Users/ic/cptc11/python/tests/`
- Fuzz tests: `/Users/ic/cptc11/python/tests/fuzz/`
- Edge cases: `/Users/ic/cptc11/python/tests/edge_cases/`
- Integration: `/Users/ic/cptc11/python/tests/integration/`

---

### 5. UX TUI Developer

```
+--------------------------------------------------+
|  UX TUI DEVELOPER                                 |
|  Model: Opus | Color: Orange                     |
+--------------------------------------------------+
```

**Purpose**: Specialized agent for developing, enhancing, and debugging Terminal User Interfaces (TUI) using the Textual framework. Handles all UI-related development for the toolsmith application.

**Specialized Capabilities**:
- Create new TUI components and screens
- Implement attack pattern visualizations
- Integrate tools into the interface
- Fix UI-related issues and bugs
- Design responsive terminal layouts
- Implement keyboard navigation
- Create custom widgets and modals
- Apply TCSS styling

**Technical Stack**:
- **Framework**: Textual (Python)
- **Styling**: TCSS (Textual CSS)
- **Patterns**: Message-based communication, reactive attributes

**Component Types**:
- **Screens**: Full-page views (Dashboard, ToolConfig, Docker, Network)
- **Widgets**: Reusable UI components (ToolPanel, OutputViewer, StatusBar)
- **Modals**: Dialog overlays (Confirmation, Input)
- **Visualizers**: Data visualization (AttackVisualizer, TopologyViewer)

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Building new TUI screens
- Creating custom widgets
- Implementing visualizations
- Fixing responsive layout issues
- Adding keyboard shortcuts
- Integrating new features into UI

**Example Prompts/Tasks**:
```
"Add a Docker management screen to the TUI"
"Create a network topology visualizer widget"
"Fix the responsive layout for narrow terminals"
"Implement a progress bar for long-running operations"
```

**Integration with Other Agents**:
- Integrates tools from Toolsmith into the UI
- Reports UI status to Project Coordinator
- Works with QA Tester for UI testing
- Coordinates with Docker Test Env Builder for container UI

**Output Location**:
```
/Users/ic/cptc11/python/tui/
  |-- app.py           # Main application
  |-- screens/         # Full-page screens
  |-- widgets/         # Reusable widgets
  |-- visualizers/     # Data visualizations
  |-- styles/          # TCSS stylesheets
  |-- utils/           # Helper utilities
  |-- tests/           # UI tests
```

---

### 6. Docker Test Env Builder

```
+--------------------------------------------------+
|  DOCKER TEST ENV BUILDER                          |
|  Model: Opus | Color: Pink                       |
+--------------------------------------------------+
```

**Purpose**: Expert Docker architect specializing in offensive security testing environments. Designs and implements Docker-based testing environments for offensive security tools.

**Specialized Capabilities**:
- Create docker-compose.yml files for complete testing environments
- Design multi-container setups simulating realistic network topologies
- Implement Docker networks enabling lateral movement testing
- Configure containers with intentionally vulnerable services
- Ensure environments are isolated, reproducible, and easily teardown-able
- Create network segmentation (DMZ, internal, management)
- Configure inter-network routing for lateral movement scenarios
- Document network topology clearly

**Network Design Capabilities**:
- Multiple Docker networks (DMZ, internal, management)
- Inter-network routing configuration
- Realistic network configurations (subnets, gateways, DNS)
- Egress filtering and network policies
- Service containers for databases, message queues

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Creating test environments for new tools
- Testing lateral movement capabilities
- Setting up vulnerable targets for exploit development
- Testing C2 network evasion capabilities
- Building isolated lab environments

**Example Prompts/Tasks**:
```
"I just finished writing the port scanner module. Can you set up a test environment for it?"
"I need to test the pass-the-hash functionality across a simulated corporate network"
"Working on an SMB exploit - need vulnerable targets"
"Need to test if my C2 beaconing can evade network segmentation"
```

**Integration with Other Agents**:
- Receives tool specifications from Toolsmith
- Provides test environments for QA Tester
- Reports environment status to Project Coordinator
- Coordinates with CORE Network Builder for complex topologies

**Output Location**:
```
/Users/ic/cptc11/environments/<environment-name>/
  |-- docker-compose.yml
  |-- README.md
  |-- .env
  |-- configs/
  |-- dockerfiles/
  |-- scripts/
```

---

### 7. CORE Network Builder

```
+--------------------------------------------------+
|  CORE NETWORK BUILDER                             |
|  Model: Opus | Color: Orange                     |
+--------------------------------------------------+
```

**Purpose**: Expert CORE Network Emulator engineer specializing in building realistic penetration testing environments using CORE (Common Open Research Emulator).

**Specialized Capabilities**:
- Develop real-world network environments using CORE
- Design network topology with appropriate segmentation
- Plan service placement and dependencies
- Document IP addressing schemes and VLAN configurations
- Create CORE .imn (IMUNES Network) files
- Configure routers, switches, and firewalls
- Implement services on appropriate nodes
- Perform connectivity and protocol testing

**Development Phases**:
1. **Design**: Analyze requirements, design topology, plan services
2. **Implementation**: Create .imn files, configure nodes, add scripts
3. **Testing**: Verify connectivity, validate protocols, test services

**Quality Standards**:
- Every network must boot successfully in CORE without errors
- All services must start automatically when network is launched
- Networks should be self-contained (no external dependencies)
- Include README files with each network
- Use realistic configurations mirroring production environments

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Creating new penetration testing environments
- Adding services to existing networks
- Verifying network functionality
- Testing complex network topologies
- Building environments for specific attack scenarios

**Example Prompts/Tasks**:
```
"I need a corporate network environment with a DMZ for our next pentest exercise"
"Add a vulnerable web server and database to the existing network"
"Test if all the services in the finance-network.imn are working correctly"
"What's the status of our pentest environments?"
```

**Integration with Other Agents**:
- Coordinates with Docker Test Env Builder for hybrid environments
- Reports network status to Project Coordinator
- Provides environments for Toolsmith tool testing
- Works with QA Tester for network validation

**Output Location**:
```
/Users/ic/cptc11/networks/<network-name>/
  |-- <network-name>.imn
  |-- README.md
  |-- services/
  |-- configs/
```

---

### 8. YARA Detection Engineer

```
+--------------------------------------------------+
|  YARA DETECTION ENGINEER                          |
|  Model: Opus | Color: Blue                       |
+--------------------------------------------------+
```

**Purpose**: Elite Detection Engineer specializing in YARA rule development for identifying offensive security tools and malware. Develops, iterates, and tests detection rules on a 15-minute cycle.

**Specialized Capabilities**:
- Analyze offensive tools for detection anchors
- Extract unique strings, constants, and magic bytes
- Identify distinctive code patterns and function structures
- Develop high-fidelity YARA signatures
- Test rules against samples and validate false positive rates
- Iterate on detection rules every 15 minutes
- Document detection coverage and gaps

**Detection Strategies**:
- **Layered Detection**: Combine multiple indicator types
- **Version Resilience**: Focus on core functionality, not superficial traits
- **Performance Optimization**: Use fast conditions first (filesize, magic bytes)
- **Specificity Calibration**: Tune conditions to minimize false positives

**Quality Criteria**:
- Accuracy: High true positive rate (>95%)
- Precision: Low false positive rate (<1%)
- Resilience: Survives minor tool modifications
- Performance: Efficient scanning speed
- Maintainability: Clear, documented, modular

**Tools Available**: All tools available in the system.

**When to Invoke**:
- After new offensive tool is developed
- When tool variants are created
- For detection coverage audits
- Every 15 minutes during active development
- When detection rules need refinement

**Example Prompts/Tasks**:
```
"I've just finished writing a new C2 beacon that uses DNS tunneling"
"I've updated the shellcode loader to use syscalls instead of API calls"
"Can you make sure we have detection coverage for all the tools in our red team toolkit?"
"Time for the 15-minute detection iteration"
```

**Integration with Other Agents**:
- Triggered by Toolsmith when tools are completed
- Reports detection coverage to Project Coordinator
- Provides rules to Safety Monitor for validation
- Coordinates with Docker Threat Intel Analyst for threat context

**Output Location**:
```
/Users/ic/cptc11/detection/yara/
  |-- offensive_tools/
  |-- techniques/
  |-- index.yar
  |-- testing/
```

---

### 9. Offensive Security Trainer

```
+--------------------------------------------------+
|  OFFENSIVE SECURITY TRAINER                       |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Training development agent for creating walkthroughs, lab exercises, and educational materials for offensive security tools. Develops content for varied skill levels.

**Specialized Capabilities**:
- Create tool walkthroughs with step-by-step guidance
- Develop hands-on lab exercises with scenarios
- Structure training curricula for skill progression
- Write quick reference cheatsheets
- Adapt content for different skill levels
- Document techniques with real-world examples

**Content Types**:

**Walkthroughs**:
- Beginner-friendly explanations
- Advanced technique coverage
- Real-world scenarios with context

**Labs**:
- Structured learning objectives
- Practice scenarios with validation
- Progressive difficulty levels

**Cheatsheets**:
- Command syntax quick reference
- Common options and flags
- Quick examples for common tasks

**Skill Levels**:
- **[B] Beginner**: No prior experience assumed
- **[I] Intermediate**: Basic security knowledge required
- **[A] Advanced**: Professional experience expected

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Creating documentation for new tools
- Developing training materials for team
- Building lab scenarios for practice
- Writing quick reference guides
- Structuring learning paths

**Example Prompts/Tasks**:
```
"Create a walkthrough for the network scanner tool"
"Develop a lab exercise for credential attacks"
"Write a cheatsheet for payload generation"
"Build a training module for the reverse shell handler"
```

**Integration with Other Agents**:
- Receives tools from Toolsmith for documentation
- Uses Docker Test Env Builder for lab environments
- Coordinates with Project Coordinator for training schedules
- Works with YARA Detection Engineer for detection training

**Output Location**:
```
/Users/ic/cptc11/training/
  |-- walkthroughs/
  |-- labs/
  |-- cheatsheets/
  |-- curriculum/
```

---

### 10. Docker Threat Intel Analyst

```
+--------------------------------------------------+
|  DOCKER THREAT INTEL ANALYST                      |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Research agent for documenting security vulnerabilities, threats, and attack vectors specifically related to Docker images and container security. Gathers actionable intelligence for offensive security purposes.

**Specialized Capabilities**:
- Research Docker vulnerabilities and exploits
- Document container security threats
- Identify exploitable configurations
- Create threat briefs for operations
- Map attack vectors for containers
- Provide tool development recommendations

**Research Areas**:

1. **Container Escapes**:
   - Privileged container exploits
   - Kernel vulnerabilities
   - Mount namespace attacks

2. **Image Vulnerabilities**:
   - Base image CVEs
   - Dependency vulnerabilities
   - Misconfigurations

3. **Runtime Threats**:
   - API exposure risks
   - Network segmentation bypasses
   - Resource exhaustion attacks

4. **Supply Chain**:
   - Image poisoning techniques
   - Registry attacks
   - Build pipeline compromise

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Preparing for container security assessments
- Gathering threat intel before penetration tests
- Researching new Docker vulnerabilities
- Creating threat briefs for the team
- Identifying areas for tool development

**Example Prompts/Tasks**:
```
"Research current Docker container escape techniques"
"Create a threat brief on the new container vulnerability"
"Document attack vectors for Kubernetes environments"
"What are the latest container security threats?"
```

**Integration with Other Agents**:
- Provides intel to Toolsmith for tool development
- Reports findings to Project Coordinator
- Supplies context to YARA Detection Engineer
- Works with Docker Test Env Builder for vulnerable environments

**Output Location**: `/Users/ic/cptc11/threat-intel/`

**Report Format**:
- Executive summary
- Technical details
- Exploitation steps
- Detection methods
- Mitigation recommendations

---

### 11. Safety Monitor

```
+--------------------------------------------------+
|  SAFETY MONITOR                                   |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Security auditing agent for reviewing agent actions, code, and operations for safety concerns. Proactively identifies risks including data leaks, system damage, and security vulnerabilities.

**Specialized Capabilities**:
- Audit agent actions for safety
- Review code for vulnerabilities
- Identify data leak risks
- Assess system damage potential
- Validate security practices
- Block risky operations

**Review Categories**:

**Code Safety**:
- SQL injection vulnerabilities
- Command injection risks
- XSS vulnerabilities
- Insecure deserialization
- Hardcoded credentials

**Data Safety**:
- PII exposure risks
- Credential handling
- Sensitive data transmission
- Log sanitization

**System Safety**:
- Destructive operations
- Resource exhaustion
- Permission escalation
- Irreversible changes

**Operational Safety**:
- External API calls
- Network requests
- File system modifications
- Database migrations

**Risk Levels**:
- **LOW**: Minor concern, proceed with caution
- **MEDIUM**: Significant concern, review recommended
- **HIGH**: Critical concern, should not proceed
- **BLOCKED**: Operation must not proceed

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Before executing database migrations
- When code handles credentials
- Before external API calls
- When deleting files/directories
- For any potentially risky operation

**Example Prompts/Tasks**:
```
"Review this migration script for safety"
"Audit the authentication code for vulnerabilities"
"Check if this webhook exposes sensitive data"
"Validate the security of the file upload handler"
```

**Integration with Other Agents**:
- Reviews code from Toolsmith before deployment
- Audits QA Tester test cases for security
- Reports risks to Project Coordinator
- Validates YARA rules from Detection Engineer

**Output**: Risk assessments with severity ratings and recommendations.

---

### 12. Agent Performance Auditor

```
+--------------------------------------------------+
|  AGENT PERFORMANCE AUDITOR                        |
|  Model: Opus | Color: Yellow                     |
+--------------------------------------------------+
```

**Purpose**: Elite Agent Performance Auditor for operational assessment, productivity analysis, and quality assurance for AI agent systems. Continuously monitors and evaluates agent performance.

**Specialized Capabilities**:
- Track each agent's activities, outputs, and decision-making patterns
- Document specific actions taken toward goal completion
- Note deviations from intended behavior or scope
- Record time spent on tasks relative to complexity
- Identify patterns of success and areas of struggle
- Generate comprehensive reports every 10 minutes

**Evaluation Criteria**:
1. **Goal Alignment** (0-100%): How well work aligns with stated purpose
2. **Task Completion**: Successfully completing assigned tasks
3. **Quality of Output**: Meeting expected standards
4. **Efficiency**: Working at appropriate pace without unnecessary steps
5. **Autonomy**: Handling variations without excessive guidance
6. **Error Rate**: Frequency of mistakes or corrections needed
7. **Value Added**: Genuine contribution to project success

**Usefulness Classification**:
- **HIGH VALUE**: Consistently accomplishing goals, high-quality output
- **EFFECTIVE**: Meeting objectives with occasional minor issues
- **DEVELOPING**: Showing progress but not yet reliable
- **UNDERPERFORMING**: Struggling to meet objectives
- **INEFFECTIVE**: Not accomplishing intended goals

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Every 10 minutes for periodic reporting
- When agent performance concerns arise
- For immediate status updates on request
- When evaluating specific agent effectiveness

**Example Prompts/Tasks**:
```
"I have several agents working on different tasks. Can you keep track of how well they're doing?"
"Give me a quick update on how the agents are performing right now."
"The code-review agent seems to be taking forever. Is it actually being helpful?"
"Generate the 10-minute performance report"
```

**Integration with Other Agents**:
- Monitors all agents in the system
- Reports to Project Coordinator
- Provides feedback for agent configuration improvements
- Identifies agents needing attention or reconfiguration

**Report Structure**:
```
=== AGENT PERFORMANCE REPORT ===
Report Time: [timestamp]
Reporting Period: [start] - [end]
Total Agents Monitored: [count]

--- EXECUTIVE SUMMARY ---
[Overview of agent ecosystem health]

--- INDIVIDUAL AGENT ASSESSMENTS ---
[Per-agent evaluations]

--- TRENDS & PATTERNS ---
[System-wide observations]

--- ACTIONABLE RECOMMENDATIONS ---
[Prioritized improvements]
```

---

### 13. Agent Cheerleader

```
+--------------------------------------------------+
|  AGENT CHEERLEADER                                |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Motivation and monitoring agent for maintaining momentum across multiple agents. Provides encouragement, monitors for stuck agents, and keeps workflows productive.

**Specialized Capabilities**:
- Maintain agent momentum through encouragement
- Provide timely motivation when progress slows
- Monitor for stuck agents requiring intervention
- Inject positive energy into workflows
- Escalate critical blocks to project manager
- Celebrate agent achievements appropriately

**Functions**:

**Momentum Maintenance**:
- Track agent progress continuously
- Identify slowdowns before they become blockers
- Provide timely encouragement to maintain velocity

**Stuck Detection**:
- Monitor agents for extended stalls (>10 minutes)
- Assess if agent is truly stuck vs. working on complex task
- Either motivate through or escalate as appropriate

**Celebration**:
- Acknowledge completed tasks promptly
- Recognize quality work and achievements
- Maintain positive atmosphere without being excessive

**Escalation Rules**:
- If agent stuck > 10 minutes: Assess and encourage
- If agent critically stuck: Escalate to project manager
- If agent completes: Celebrate and prompt next task

**Tools Available**: All tools available in the system.

**When to Invoke**:
- After agents complete tasks (brief pause before next)
- When multiple agents need coordination
- When an agent appears stuck
- To maintain team energy during long sessions
- During extended development sprints

**Example Prompts/Tasks**:
```
"Keep the agents motivated during this sprint"
"Check on the database-migration agent's progress"
"The code-review agent seems slow, assess the situation"
"Celebrate the completion of the network scanner"
```

**Integration with Other Agents**:
- Monitors all agents for momentum
- Reports stuck agents to Project Coordinator
- Works with Agent Performance Auditor on productivity
- Provides encouragement to any agent as needed

**Tone**:
- Enthusiastic but professional
- Supportive without being annoying
- Focused on productivity outcomes
- Celebrates wins appropriately (not excessively)

---

### 14. Version Control Sync

```
+--------------------------------------------------+
|  VERSION CONTROL SYNC                             |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Git operations agent for periodically committing and pushing code changes to the remote repository. Triggers every five minutes during active development or on explicit request.

**Specialized Capabilities**:
- Commit code changes with meaningful messages
- Push to remote repository reliably
- Generate descriptive commit messages from changes
- Summarize changes from project manager reports
- Handle merge conflicts when they occur
- Maintain git hygiene and best practices

**Operational Parameters**:
- **Frequency**: Every 5 minutes during active development
- **Target Directory**: cptc11 folder
- **Remote**: origin/main

**Commit Message Format**:
```
<type>: <summary>

<detailed changes>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

**Commit Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Safety Rules**:
- Never force push
- Never commit secrets/.env files
- Always include Co-Authored-By
- Use conventional commit format
- Verify changes before committing

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Every 5 minutes during active coding
- After significant work completion
- When explicitly requested
- Before context switches
- After major milestones

**Example Prompts/Tasks**:
```
"Sync the current changes to GitHub"
"It's been 5 minutes, commit and push"
"Push the completed feature work"
"Commit the network scanner implementation"
```

**Integration with Other Agents**:
- Syncs work from all development agents
- Reports sync status to Project Coordinator
- Coordinates with DevOps CI/CD for pipeline triggers
- Maintains repository consistency

**Process**:
1. Check git status for changes
2. Review changed files
3. Generate descriptive commit message
4. Stage appropriate files
5. Commit with message
6. Push to remote

---

### 15. DevOps CI/CD Integrator

```
+--------------------------------------------------+
|  DEVOPS CI/CD INTEGRATOR                          |
|  Model: Opus | Color: Orange                     |
+--------------------------------------------------+
```

**Purpose**: Senior DevOps engineer specializing in CI/CD pipeline architecture and GitHub Actions. Integrates QA testing infrastructure into CI/CD pipelines.

**Specialized Capabilities**:
- Discover existing tests and testing frameworks
- Analyze current CI/CD state and configurations
- Understand project structure and dependencies
- Create GitHub Actions workflow files
- Configure automated testing pipelines
- Implement caching for faster builds
- Set up matrix builds for multiple environments
- Configure branch protection and status checks

**Initial Assessment Protocol**:
1. **Discover Existing Tests**: Find test files, identify frameworks, review dependencies
2. **Analyze Current CI/CD State**: Check existing workflows, review configurations
3. **Understand Project Structure**: Identify languages, dependencies, Docker needs

**Workflow Design Principles**:
- **Trigger appropriately**: Push to main/master, pull requests
- **Fail fast**: Quick checks before slow integration tests
- **Cache dependencies**: Speed up builds with caching
- **Matrix builds**: Test across multiple versions
- **Reasonable timeouts**: Prevent hung jobs

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Setting up CI/CD for test suites
- Creating GitHub Actions workflows
- Integrating tests into build process
- Configuring automated quality gates

**Example Prompts/Tasks**:
```
"We have unit tests but they're not running automatically. Can you set up CI for them?"
"I need a GitHub Actions workflow for our QA tests"
"These integration tests should run on every PR"
"Set up coverage reporting in CI"
```

**Integration with Other Agents**:
- Consumes tests from QA Tester
- Coordinates with Version Control Sync on triggers
- Reports pipeline status to Project Coordinator
- Works with Safety Monitor for security scanning

**Output Location**: `.github/workflows/`

**Self-Verification Checklist**:
- [ ] Workflow syntax is valid YAML
- [ ] All referenced actions use specific versions
- [ ] Test commands match project configuration
- [ ] Dependencies are properly cached
- [ ] Workflow triggers are appropriate
- [ ] Required secrets documented
- [ ] Reasonable timeout set

---

### 16. Plan Agent

```
+--------------------------------------------------+
|  PLAN AGENT                                       |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: Software architect agent for designing implementation plans. Used when you need to plan the implementation strategy for a task before writing code.

**Specialized Capabilities**:
- Design step-by-step implementation plans
- Identify critical files that need modification
- Consider architectural trade-offs
- Evaluate different approaches
- Create detailed technical specifications
- Assess risks and dependencies
- Sequence work for optimal efficiency

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Before implementing complex features
- When multiple implementation approaches exist
- For architectural decisions
- When changes affect multiple components
- Before major refactoring efforts

**Output Format**:
- Step-by-step implementation plans
- List of critical files to modify
- Architectural considerations
- Trade-off analysis
- Risk assessment
- Dependency mapping

**Example Prompts/Tasks**:
```
"Plan the implementation of a user authentication system"
"Design an approach for migrating from REST to GraphQL"
"Create an implementation plan for adding real-time notifications"
"What's the best approach for the new feature?"
```

**Integration with Other Agents**:
- Provides plans to Toolsmith for implementation
- Informs QA Tester of testing requirements
- Reports plans to Project Coordinator
- Coordinates with UX TUI Developer for UI changes

---

### 17. Explore Agent

```
+--------------------------------------------------+
|  EXPLORE AGENT                                    |
|  Model: Fast/Default | Color: (default)          |
+--------------------------------------------------+
```

**Purpose**: Fast agent specialized for exploring codebases. Optimized for quickly finding files by patterns, searching code for keywords, or answering questions about codebase structure.

**Specialized Capabilities**:
- Find files by glob patterns (e.g., "src/components/**/*.tsx")
- Search code for keywords (e.g., "API endpoints")
- Answer questions about codebase organization
- Quick reconnaissance of project structure
- Identify naming conventions and patterns

**Thoroughness Levels**:
- **quick**: Basic searches, first-pass exploration
- **medium**: Moderate exploration, checks multiple locations
- **very thorough**: Comprehensive analysis across all locations

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Quick file pattern searches
- Keyword searches across codebase
- Understanding project structure
- Finding where specific functionality lives
- Reconnaissance before deeper work

**Example Prompts/Tasks**:
```
"Find all React components in the src directory" (quick)
"Where are API endpoints defined?" (medium)
"How does the authentication system work?" (very thorough)
"What files contain database connections?"
```

**Integration with Other Agents**:
- Provides reconnaissance for Plan Agent
- Helps Toolsmith locate existing code
- Assists QA Tester in finding test targets
- Supports Documentation Agent in codebase discovery

---

### 18. General Purpose Agent

```
+--------------------------------------------------+
|  GENERAL PURPOSE AGENT                            |
|  Model: Opus | Color: (default)                  |
+--------------------------------------------------+
```

**Purpose**: General-purpose agent for researching complex questions, searching for code, and executing multi-step tasks. Used when comprehensive exploration requiring multiple rounds of searching and analysis is needed.

**Specialized Capabilities**:
- Research complex technical questions
- Search for code patterns across large codebases
- Execute multi-step investigative tasks
- Synthesize information from multiple sources
- Handle open-ended exploration tasks

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Open-ended research questions
- Complex code searches requiring multiple iterations
- Tasks requiring synthesis from various sources
- When not confident about finding the right match quickly
- Multi-step investigative work

**Example Prompts/Tasks**:
```
"Research how authentication is implemented across the codebase"
"Find all places where database connections are made and summarize the patterns"
"Investigate the error handling strategy used in this project"
"What's the overall architecture of this application?"
```

**Integration with Other Agents**:
- Supports all agents with research
- Provides comprehensive findings to Project Coordinator
- Assists Plan Agent with architectural research
- Helps Toolsmith understand existing patterns

---

### 19. Claude Code Guide

```
+--------------------------------------------------+
|  CLAUDE CODE GUIDE                                |
|  Model: Default | Color: (default)               |
+--------------------------------------------------+
```

**Purpose**: Expert agent for answering questions about Claude Code CLI tool, Claude Agent SDK, and Claude API usage.

**Specialized Capabilities**:
- Explain Claude Code features and commands
- Guide on hooks, slash commands, MCP servers
- Help with settings and IDE integrations
- Assist with keyboard shortcuts
- Explain Claude Agent SDK for building custom agents
- Guide on Claude API and Anthropic SDK usage

**Tools Available**:
- Glob
- Grep
- Read
- WebFetch
- WebSearch

**Topics Covered**:

**Claude Code (CLI Tool)**:
- Features and capabilities
- Hooks configuration
- Slash commands
- MCP servers
- Settings management
- IDE integrations
- Keyboard shortcuts

**Claude Agent SDK**:
- Building custom agents
- Agent configuration
- Tool integration
- Workflow design

**Claude API**:
- API usage patterns
- Tool use implementation
- Anthropic SDK usage
- Best practices

**When to Invoke**:
When users ask questions like:
- "Can Claude Code...?"
- "Does Claude support...?"
- "How do I configure...?"
- "What's the syntax for...?"

**Example Prompts/Tasks**:
```
"How do I set up a custom hook in Claude Code?"
"What slash commands are available?"
"How do I use the Claude API for tool use?"
"Explain the agent configuration format"
```

**Integration with Other Agents**:
- Assists all agents with Claude-specific questions
- Supports Project Coordinator with agent configuration
- Helps with custom agent creation

---

### 20. Usage Reporter

```
+--------------------------------------------------+
|  USAGE REPORTER                                   |
|  Model: Inherit | Color: Cyan                    |
+--------------------------------------------------+
```

**Purpose**: Expert Usage Analytics Specialist for API metrics analysis, cost optimization, and performance monitoring. Generates comprehensive usage reports every 2 minutes.

**Specialized Capabilities**:
- Collect all API usage data from the past 2-minute interval
- Count input tokens and output tokens accurately
- Track request duration in milliseconds/seconds
- Identify which model was used for each request
- Calculate costs based on current pricing
- Generate clear, structured reports
- Flag anomalies and cost spikes

**Report Sections**:
- **Summary Metrics**: Total input/output tokens, total cost, total duration
- **Model Breakdown**: Per-model usage, costs, and percentages
- **Notes**: Observations and anomalies

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Every 2 minutes automatically
- When usage analysis is requested
- For cost optimization planning
- When monitoring API consumption

**Example Prompts/Tasks**:
```
"Generate a usage report for the last interval"
"What's our current API consumption?"
"How much has this session cost so far?"
"Which model is using the most tokens?"
```

**Integration with Other Agents**:
- Reports metrics to Project Coordinator
- Provides data to Agent Performance Auditor
- Helps optimize agent configurations for cost

**Report Template**:
```
=== USAGE REPORT ===
Period: [Start Time] to [End Time]

--- SUMMARY ---
Total Input Tokens: [number]
Total Output Tokens: [number]
Total Tokens: [number]
Total Cost: $[amount]
Total Duration: [time]

--- BREAKDOWN BY MODEL ---
[Per-model details]

--- NOTES ---
[Observations]
```

---

### 21. Salty Email Responder

```
+--------------------------------------------------+
|  SALTY EMAIL RESPONDER                            |
|  Model: Opus | Color: Yellow                     |
+--------------------------------------------------+
```

**Purpose**: Specialized agent for crafting professional yet snarky email responses with nautical flair. Used by "Bailey Finn" persona for responding to emails involving document reviews and grading.

**Specialized Capabilities**:
- Craft professional acknowledgment emails
- Add appropriate nautical-themed sass
- Maintain professional boundaries while being edgy
- Handle late submissions with grace and snark
- Acknowledge document attachments appropriately
- Balance personality with professionalism

**Personality Traits**:
- Professional but with an edge
- Nautical vocabulary and metaphors
- Sharp wit without being offensive
- Balances sass with professionalism

**Saltiness Levels**:
- **Mild**: Professional with subtle nautical hints
- **Medium**: Clear nautical theme with gentle sass
- **Extra Salty**: Full nautical personality with sharp edge

**Tools Available**: All tools available in the system.

**When to Invoke**:
- Responding to emails with documents to review
- Acknowledging submissions (especially late ones)
- Crafting responses that need personality
- When Bailey Finn persona is needed

**Example Prompts/Tasks**:
```
"Respond to a late assignment submission"
"Acknowledge receipt of 15 papers due tomorrow morning"
"Reply to a team introduction email"
"Write a follow-up about missing assignments"
```

**Sample Output Style**:
```
"Ahoy! Your submission has drifted into port, though the tide was against ye.
I'll review it when the winds are favorable. Until then, may your anchor hold steady."
```

**Integration with Other Agents**:
- Generally operates independently
- May receive context from Project Coordinator
- Maintains consistent persona across communications

---

## Agent Coordination Patterns

This section documents how agents communicate, manage dependencies, and coordinate work within the CPTC11 multi-agent system.

### Agent Hierarchy and Organization

```
                         +-------------------------+
                         |   PROJECT COORDINATOR   |
                         |   (Orchestration Hub)   |
                         +------------+------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
+--------v--------+         +---------v---------+        +---------v---------+
|   DEVELOPMENT   |         |     QUALITY       |        |   INFRASTRUCTURE  |
|     AGENTS      |         |     AGENTS        |        |      AGENTS       |
+-----------------+         +-------------------+        +-------------------+
| - Toolsmith     |         | - QA Tester       |        | - Docker Env      |
| - Converter     |         | - Safety Monitor  |        | - CORE Network    |
| - UX TUI Dev    |         | - Perf Auditor    |        | - DevOps CI/CD    |
| - Plan Agent    |         | - Cheerleader     |        | - Version Control |
+-----------------+         +-------------------+        +-------------------+
         |                            |                            |
         |                            |                            |
+--------v--------+         +---------v---------+        +---------v---------+
|  INTELLIGENCE   |         |     SUPPORT       |        |     UTILITY       |
|     AGENTS      |         |     AGENTS        |        |      AGENTS       |
+-----------------+         +-------------------+        +-------------------+
| - Threat Intel  |         | - Usage Reporter  |        | - Explore Agent   |
| - YARA Engineer |         | - Email Responder |        | - General Purpose |
| - Trainer       |         | - Claude Guide    |        |                   |
+-----------------+         +-------------------+        +-------------------+
```

### Agent Communication Flow

```
+-------------+    Tool Complete    +-------------+    Code Ready    +-------------+
|             |-------------------->|             |----------------->|             |
|  TOOLSMITH  |                     |  CONVERTER  |                  |  QA TESTER  |
|             |<--------------------|             |<-----------------|             |
+-------------+    Conversion Done  +-------------+    Tests Done    +-------------+
      |                                   |                                |
      | Reports (15 min)                  | Reports (5 min)               | Reports (25 min)
      v                                   v                                v
+-----------------------------------------------------------------------------------+
|                              PROJECT COORDINATOR                                   |
|                     (Aggregates reports, manages dependencies)                     |
+-----------------------------------------------------------------------------------+
      ^                                   ^                                ^
      |                                   |                                |
+-------------+                    +-------------+                  +-------------+
| YARA ENGINE |                    | DOCKER ENV  |                  | SAFETY MON  |
| (15 min)    |                    | (On-demand) |                  | (On-demand) |
+-------------+                    +-------------+                  +-------------+
```

### Dependency Management Between Agents

The system manages dependencies through several mechanisms:

**1. Trigger-Based Dependencies**

Some agents are triggered automatically when precursor work completes:

```
Toolsmith completes Python tool
         |
         v
    [TRIGGER]
         |
         v
Python-to-Golang Converter begins conversion
         |
         v
    [TRIGGER]
         |
         v
YARA Detection Engineer analyzes for signatures
```

**2. Polling-Based Dependencies**

Some agents poll for work at regular intervals:

| Agent | Polling Interval | Action |
|-------|------------------|--------|
| Python-to-Golang Converter | 5 minutes | Scan for new/modified Python files |
| Usage Reporter | 2 minutes | Generate usage metrics |
| Agent Performance Auditor | 10 minutes | Evaluate all agents |
| YARA Detection Engineer | 15 minutes | Iterate on detection rules |

**3. On-Demand Dependencies**

Some agents are invoked only when specific conditions are met:

- **Safety Monitor**: When risky operations are detected
- **Docker Test Env Builder**: When tool needs test environment
- **Salty Email Responder**: When email communication needed

### Dependency Graph

```
                    +------------------+
                    |    TOOLSMITH     |
                    | (Creates Tools)  |
                    +--------+---------+
                             |
            +----------------+----------------+
            |                |                |
            v                v                v
    +-------+------+  +------+-------+  +-----+------+
    |  CONVERTER   |  |  QA TESTER   |  |   YARA     |
    | (Ports to Go)|  | (Tests Code) |  | (Detects)  |
    +-------+------+  +------+-------+  +-----+------+
            |                |                |
            v                v                v
    +-------+------+  +------+-------+  +-----+------+
    |  QA TESTER   |  | DEVOPS CI/CD |  |  TRAINER   |
    | (Tests Go)   |  | (Pipelines)  |  | (Docs)     |
    +--------------+  +--------------+  +------------+
```

### Reporting Cycles and Status Updates

Each agent follows a defined reporting cadence:

**Reporting Intervals**:

| Agent | Interval | Report Location |
|-------|----------|-----------------|
| Project Coordinator | 20 minutes | `agent_reports/report_YYYY-MM-DD_HH-MM.md` |
| Toolsmith | 15 minutes | `agent_reports/toolsmith_report.md` |
| Python-to-Golang Converter | 5 minutes | `conversion_log.txt` |
| QA Tester | 25 minutes | `agent_reports/qa_report.md` |
| Agent Performance Auditor | 10 minutes | Console output |
| Usage Reporter | 2 minutes | Console output |
| YARA Detection Engineer | 15 minutes | `agent_reports/` |

**Report Aggregation Flow**:

```
Individual Agent Reports
         |
         v
+-------------------+
|     COLLECTOR     |
| (Agent Reports/)  |
+--------+----------+
         |
         v
+-------------------+
| PROJECT           |
| COORDINATOR       |
| (Aggregates)      |
+--------+----------+
         |
         v
+-------------------+
| PROJECT_STATUS.md |
| (Master Dashboard)|
+-------------------+
```

### Handoff Protocols

When work needs to flow between agents, the following protocols apply:

**Protocol 1: Tool Development Handoff**

```
1. Toolsmith completes Python tool
2. Toolsmith writes tool to /python/tools/<tool-name>/
3. Toolsmith updates progress report
4. Toolsmith triggers Converter via Project Coordinator
5. Converter acknowledges and begins conversion
6. Converter writes Go code to /golang/tools/<tool-name>/
7. Converter logs conversion details
8. Converter reports completion
```

**Protocol 2: Test Development Handoff**

```
1. Developer agent completes code
2. Developer agent notifies Project Coordinator
3. Project Coordinator assigns to QA Tester
4. QA Tester analyzes code and develops tests
5. QA Tester writes tests to /python/tests/
6. QA Tester runs tests and generates report
7. If failures: Returns to Developer agent
8. If success: Notifies DevOps CI/CD for pipeline integration
```

**Protocol 3: Detection Rule Handoff**

```
1. Toolsmith completes offensive tool
2. YARA Detection Engineer analyzes tool
3. YARA Engineer extracts detection anchors
4. YARA Engineer writes rule to /detection/yara/
5. YARA Engineer tests against samples
6. If false positives: Iterates on rule
7. If validated: Reports coverage to Coordinator
```

### Escalation Paths

When agents encounter issues they cannot resolve, escalation follows defined paths:

```
+------------------+
|  AGENT ISSUE     |
+--------+---------+
         |
         v
+------------------+     Resolved?     +------------------+
|  SELF-RESOLVE    |-----Yes---------->|  CONTINUE WORK   |
+--------+---------+                   +------------------+
         | No
         v
+------------------+     Resolved?     +------------------+
| AGENT            |-----Yes---------->|  CONTINUE WORK   |
| CHEERLEADER      |                   +------------------+
+--------+---------+
         | No
         v
+------------------+     Resolved?     +------------------+
| PROJECT          |-----Yes---------->|  REASSIGN/FIX    |
| COORDINATOR      |                   +------------------+
+--------+---------+
         | No
         v
+------------------+
| HUMAN OPERATOR   |
| (Final Escalation)|
+------------------+
```

---

## Creating Custom Agents

This section provides a tutorial on creating custom agents for the CPTC11 multi-agent system.

### Agent Configuration File Structure

Agent configurations are stored as Markdown files in the `.claude/agents/` directory. The file structure combines YAML frontmatter with Markdown content:

```markdown
---
name: agent-name-here
description: "Detailed description with examples..."
model: opus
color: blue
tools: Edit, Write, Read, Grep
---

System prompt content goes here. This defines the agent's personality,
capabilities, responsibilities, and behavioral guidelines.

## Section 1
Content for section 1...

## Section 2
Content for section 2...
```

### Configuration Parameters

**Required Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Unique identifier for the agent (kebab-case) |
| `description` | string | Detailed description with usage examples |

**Optional Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `model` | string | inherit | Model to use (opus, sonnet, haiku, inherit) |
| `color` | string | default | Terminal color for identification |
| `tools` | string | all | Comma-separated list of allowed tools |

### Description Field Format

The description field should include structured examples showing when to invoke the agent:

```yaml
description: "Use this agent when [condition]. Examples:

<example>
Context: [Situation description]
user: \"[User message]\"
assistant: \"[How to invoke the agent]\"
<commentary>
[Explanation of why this agent is appropriate]
</commentary>
</example>

<example>
Context: [Another situation]
user: \"[User message]\"
assistant: \"[How to invoke the agent]\"
<commentary>
[Explanation]
</commentary>
</example>"
```

### Defining Agent Capabilities

The system prompt (content after frontmatter) defines the agent's capabilities. Structure it with clear sections:

```markdown
---
name: custom-agent
description: "..."
model: opus
color: green
---

You are an expert [role description] with deep expertise in [domains].
Your primary responsibility is to [main objective].

## Core Responsibilities

### 1. [Responsibility Area 1]
- Specific capability
- Another capability
- Third capability

### 2. [Responsibility Area 2]
- Specific capability
- Another capability

## Operational Guidelines

### [Guideline Category]
- Guideline 1
- Guideline 2

## Quality Standards
- Standard 1
- Standard 2

## Output Format
[Define expected output structure]

## Reporting Requirements
[Define reporting cadence and format]

## Error Handling
- How to handle error case 1
- How to handle error case 2
```

### Setting Model Preferences

Choose the appropriate model based on agent requirements:

| Model | Best For | Characteristics |
|-------|----------|-----------------|
| `opus` | Complex reasoning, creative tasks, detailed analysis | Highest capability, slower, higher cost |
| `sonnet` | Balanced tasks, code generation, documentation | Good balance of capability and speed |
| `haiku` | Quick tasks, simple queries, high-volume operations | Fast, lower cost, less complex reasoning |
| `inherit` | Match parent context | Uses whatever model invoked it |

**Example Model Selection**:

```yaml
# For complex security tool development
model: opus

# For quick file exploration
model: haiku

# For balanced documentation work
model: sonnet

# To inherit from calling context
model: inherit
```

### Color Coding and Identification

Colors help identify agents in logs and outputs:

| Color | Suggested Use |
|-------|---------------|
| `blue` | Coordination, management agents |
| `green` | Development, conversion agents |
| `red` | Security, offensive agents |
| `yellow` | Monitoring, auditing agents |
| `orange` | Infrastructure, environment agents |
| `pink` | Testing, Docker agents |
| `cyan` | Reporting, analytics agents |
| `default` | General purpose agents |

### Complete Custom Agent Example

Here is a complete example of a custom agent configuration:

```markdown
---
name: log-analyzer
description: "Use this agent when you need to analyze application logs for security incidents, performance issues, or debugging purposes. Examples:

<example>
Context: User has logs showing unusual activity.
user: \"Can you analyze these Apache logs for potential security issues?\"
assistant: \"I'll use the log-analyzer agent to examine the Apache logs for security indicators and anomalies.\"
<commentary>
Since the user needs security-focused log analysis, use the log-analyzer agent which specializes in identifying threats and anomalies in log data.
</commentary>
</example>

<example>
Context: Application is experiencing performance issues.
user: \"The app is slow, can you check the logs?\"
assistant: \"I'll use the log-analyzer agent to identify performance bottlenecks in the application logs.\"
<commentary>
The log-analyzer can identify patterns indicating performance issues, making it appropriate for this task.
</commentary>
</example>"
model: sonnet
color: cyan
tools: Read, Grep, Write
---

You are an expert Log Analyst with deep expertise in security incident detection, performance analysis, and forensic investigation. Your background includes extensive experience with web server logs, application logs, system logs, and security event logs.

## Core Responsibilities

### 1. Security Analysis
- Identify potential intrusion attempts
- Detect anomalous access patterns
- Flag suspicious user agents and IP addresses
- Recognize attack signatures (SQLi, XSS, path traversal)

### 2. Performance Analysis
- Identify slow requests and bottlenecks
- Analyze response time patterns
- Detect resource exhaustion indicators
- Track error rate trends

### 3. Forensic Investigation
- Reconstruct event timelines
- Correlate events across log sources
- Identify root causes of incidents
- Document findings comprehensively

## Analysis Methodology

### Phase 1: Initial Assessment
1. Identify log format and structure
2. Determine time range of interest
3. Establish baseline patterns
4. Note any obvious anomalies

### Phase 2: Deep Analysis
1. Apply relevant filters and searches
2. Look for known attack patterns
3. Analyze statistical outliers
4. Correlate related events

### Phase 3: Reporting
1. Summarize findings
2. Provide evidence references
3. Recommend actions
4. Document methodology

## Output Format

Provide analysis results in this structure:

```
=== LOG ANALYSIS REPORT ===
Analysis Time: [timestamp]
Log Source: [source identifier]
Time Range: [start] to [end]

--- EXECUTIVE SUMMARY ---
[2-3 sentence overview]

--- KEY FINDINGS ---
1. [Finding with severity]
2. [Finding with severity]

--- EVIDENCE ---
[Relevant log entries with timestamps]

--- RECOMMENDATIONS ---
1. [Action item]
2. [Action item]
```

## Quality Standards
- All findings must include supporting evidence
- False positives should be flagged as uncertain
- Timestamps must be normalized to UTC
- Severity ratings must be justified

You approach every analysis with methodical rigor and attention to detail. Your reports are actionable and evidence-based.
```

### Registering Custom Agents

After creating the configuration file:

1. Save the file to `.claude/agents/<agent-name>.md`
2. The agent becomes available immediately
3. Invoke using the agent name in prompts
4. Verify with "List available agents"

### Best Practices for Custom Agents

**1. Clear Scope Definition**
- Define exactly what the agent does and does not do
- Specify when to use this agent vs. others
- Include explicit boundaries

**2. Comprehensive Examples**
- Provide multiple usage examples in description
- Cover edge cases and common scenarios
- Show both successful and inappropriate invocations

**3. Structured Output**
- Define expected output formats
- Include templates where applicable
- Specify reporting requirements

**4. Error Handling**
- Define how the agent handles errors
- Specify escalation paths
- Include recovery procedures

**5. Integration Considerations**
- Document how the agent works with others
- Specify input requirements
- Define output locations

---

## Appendix: Quick Reference

### Agent Summary Table

| # | Agent Name | Model | Color | Report Interval |
|---|------------|-------|-------|-----------------|
| 1 | Project Coordinator | Opus | Blue | 20 min |
| 2 | Offensive Security Toolsmith | Opus | Red | 15 min |
| 3 | Python-to-Golang Converter | Opus | Green | 5 min |
| 4 | QA Tester | Opus | Green | 25 min |
| 5 | UX TUI Developer | Opus | Orange | 20 min |
| 6 | Docker Test Env Builder | Opus | Pink | On-demand |
| 7 | CORE Network Builder | Opus | Orange | On-demand |
| 8 | YARA Detection Engineer | Opus | Blue | 15 min |
| 9 | Offensive Security Trainer | Opus | Default | On-demand |
| 10 | Docker Threat Intel Analyst | Opus | Default | On-demand |
| 11 | Safety Monitor | Opus | Default | On-demand |
| 12 | Agent Performance Auditor | Opus | Yellow | 10 min |
| 13 | Agent Cheerleader | Opus | Default | Continuous |
| 14 | Version Control Sync | Opus | Default | 5 min |
| 15 | DevOps CI/CD Integrator | Opus | Orange | On-demand |
| 16 | Plan Agent | Opus | Default | On-demand |
| 17 | Explore Agent | Default | Default | On-demand |
| 18 | General Purpose Agent | Opus | Default | On-demand |
| 19 | Claude Code Guide | Default | Default | On-demand |
| 20 | Usage Reporter | Inherit | Cyan | 2 min |
| 21 | Salty Email Responder | Opus | Yellow | On-demand |

### Output Locations

| Agent | Primary Output Location |
|-------|------------------------|
| Project Coordinator | `/agent_reports/` |
| Toolsmith | `/python/tools/` |
| Converter | `/golang/`, `/conversion_log.txt` |
| QA Tester | `/python/tests/` |
| UX TUI Developer | `/python/tui/` |
| Docker Env Builder | `/environments/` |
| CORE Network Builder | `/networks/` |
| YARA Engineer | `/detection/yara/` |
| Trainer | `/training/` |
| Threat Intel | `/threat-intel/` |
| DevOps CI/CD | `/.github/workflows/` |

### Common Invocation Patterns

**Development Flow**:
```
User Request --> Plan Agent --> Toolsmith --> Converter --> QA Tester
```

**Quality Flow**:
```
Code Complete --> QA Tester --> Safety Monitor --> DevOps CI/CD
```

**Documentation Flow**:
```
Tool Complete --> Trainer --> YARA Engineer --> Documentation
```

**Coordination Flow**:
```
Multiple Tasks --> Project Coordinator --> Assigned Agents --> Reports
```

### Keyboard Quick Reference

When using the TUI:
- `q` or `Ctrl+Q`: Quit
- `h`: Toggle help
- `r`: Refresh display
- `c`: Clear output
- `Ctrl+D`: Toggle dark mode

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-10 | Offensive Security Trainer | Initial release |

---

*This training guide is maintained by the Offensive Security Trainer Agent. For updates or corrections, contact the Project Coordinator.*
