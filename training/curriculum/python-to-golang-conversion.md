# Python to Golang Conversion Patterns for Security Tools

## Training Module Overview

**Target Audience:** Intermediate to Advanced Security Practitioners
**Prerequisites:** Basic Python proficiency, familiarity with security tool concepts
**Duration:** 4-6 hours (self-paced)
**Version:** 1.0.0

### Learning Objectives

Upon completion of this module, participants will be able to:

1. Articulate the operational and tactical advantages of converting Python security tools to Go
2. Apply systematic conversion patterns to transform Python code structures into idiomatic Go
3. Identify and convert Python-specific constructs to their Go equivalents
4. Build cross-platform binaries for deployment across diverse target environments
5. Test converted tools for functional parity with original Python implementations

---

## Section 1: Why Convert Python to Go

### 1.1 The Operational Case for Go

In the context of offensive security operations, tool deployment logistics can significantly impact mission success. Python-based tools, while excellent for rapid development and prototyping, present several operational challenges that Go addresses effectively. Understanding these tradeoffs enables practitioners to make informed decisions about when conversion is warranted and when Python remains the appropriate choice.

**Single Binary Deployment** represents perhaps the most compelling advantage for field operations. Python tools require either a Python interpreter on the target system or bundling mechanisms like PyInstaller that produce large executables with potential compatibility issues. Go compiles to a single static binary that contains everything needed for execution. This means an operator can transfer a 5-10 MB executable to a target and run it immediately without dependency concerns. There is no need to check Python versions, install pip packages, or troubleshoot missing modules. The binary either runs or it does not, and troubleshooting becomes significantly simpler.

Consider a reconnaissance scenario where you need to run a network scanner on a compromised Linux server. With Python, you must first verify Python exists, check which version is installed, determine if required modules like `ipaddress` or `concurrent.futures` are available, and potentially upload additional dependencies. With a Go binary, you transfer one file and execute it. This reduction in operational complexity translates directly to reduced time on target and lower detection probability.

**Performance Benefits** become apparent in compute-intensive operations. Go's compiled nature and efficient concurrency model provide measurably faster execution for tasks like port scanning, hash cracking, and brute-force operations. Python's Global Interpreter Lock (GIL) fundamentally limits true parallel execution in CPU-bound tasks, while Go's goroutines provide lightweight concurrency that scales efficiently across available cores. In benchmark testing, Go implementations of scanning tools typically demonstrate 3-10x performance improvements over equivalent Python code, with the gap widening as thread counts increase.

The performance differential is particularly pronounced in network-intensive operations where Python's GIL forces sequential I/O handling despite using threading constructs. Go's goroutines and channel-based communication enable true concurrent network operations without the overhead of Python's threading limitations.

**Cross-Compilation** capabilities enable building binaries for multiple target platforms from a single development machine. A practitioner on macOS can build executables for Windows, Linux (multiple architectures), and even ARM-based systems with simple environment variable changes. This eliminates the need to maintain multiple development environments or virtual machines for target platform compatibility.

```
GOOS=windows GOARCH=amd64 go build -o scanner.exe scanner.go
GOOS=linux GOARCH=amd64 go build -o scanner-linux scanner.go
GOOS=linux GOARCH=arm64 go build -o scanner-arm64 scanner.go
```

The cross-compilation workflow integrates naturally into continuous integration pipelines, enabling automated builds for all supported platforms from a single codebase.

**Dependency Elimination** reduces the attack surface and operational footprint of deployed tools. Python's rich ecosystem of third-party packages is both a strength and a weakness. While packages like `requests`, `paramiko`, and `impacket` accelerate development, they create dependency chains that must be satisfied on target systems or bundled into deployable packages. Go's standard library provides robust implementations for networking, cryptography, JSON handling, and other common requirements without external dependencies.

When external packages are required in Go, they are statically linked into the binary at compile time. There are no runtime resolution of dependencies, no version conflicts between tools, and no pip installations required on target systems. The compiled binary is entirely self-contained.

**Reduced Detection Surface** emerges from the differences in how Python and Go programs execute. Python scripts require interpreter processes and often leave identifiable artifacts in process listings, temporary files, and system logs. Go binaries execute directly without interpreter overhead and can be named to blend with legitimate system processes. While not a silver bullet for evasion, the reduced footprint contributes to operational security.

### 1.2 When to Keep Python

Not every tool warrants conversion. Python remains preferable for rapid prototyping, tools requiring frequent modification, integration with Python-specific libraries (particularly for Active Directory operations using `impacket`), and situations where the target environment reliably has Python available. The conversion investment should align with operational requirements rather than being pursued for its own sake.

---

## Section 2: Conversion Patterns Reference

This section provides detailed conversion patterns for transforming Python constructs into idiomatic Go code. Each pattern includes the Python source, Go equivalent, and explanatory notes.

### 2.1 Python dict to Go struct with JSON Tags

Python dictionaries with known keys should be converted to Go structs for type safety and JSON serialization.

**Python:**
```python
@dataclass
class ScanResult:
    """Represents a single host scan result."""
    ip: str
    is_alive: bool
    response_time: Optional[float] = None
    method: str = "unknown"
    hostname: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "method": self.method,
            "hostname": self.hostname,
            "timestamp": self.timestamp.isoformat()
        }
```

**Go:**
```go
// ScanResult represents a single host scan result
type ScanResult struct {
    IP           string   `json:"ip"`
    IsAlive      bool     `json:"is_alive"`
    ResponseTime *float64 `json:"response_time,omitempty"`
    Method       string   `json:"method"`
    Hostname     *string  `json:"hostname,omitempty"`
    Timestamp    string   `json:"timestamp"`
}

// ToDict returns a map representation for JSON serialization
func (r *ScanResult) ToDict() map[string]interface{} {
    result := map[string]interface{}{
        "ip":        r.IP,
        "is_alive":  r.IsAlive,
        "method":    r.Method,
        "timestamp": r.Timestamp,
    }
    if r.ResponseTime != nil {
        result["response_time"] = *r.ResponseTime
    }
    if r.Hostname != nil {
        result["hostname"] = *r.Hostname
    }
    return result
}
```

**Key Conversion Notes:**
- Python `Optional[T]` becomes Go pointer `*T`
- JSON tags control serialization field names
- `omitempty` excludes nil/zero values from JSON output
- Methods are defined as receiver functions
- Go struct field names use PascalCase while JSON uses snake_case

### 2.2 Python Exceptions to Go Error Returns

Go does not have exceptions. Error handling uses explicit return values.

**Python:**
```python
def scan_host(self, ip: str) -> ScanResult:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return ScanResult(ip=ip, is_alive=True)
    except socket.error as e:
        if config.verbose:
            print(f"[!] Error scanning {ip}: {e}")

    return ScanResult(ip=ip, is_alive=False)
```

**Go:**
```go
func (ns *NetworkScanner) scanHost(ip string) (*ScanResult, error) {
    address := fmt.Sprintf("%s:%d", ip, port)
    timeout := time.Duration(ns.Config.Timeout * float64(time.Second))

    conn, err := net.DialTimeout("tcp", address, timeout)
    if err != nil {
        // Log error if verbose, but don't propagate
        if ns.Config.Verbose {
            fmt.Printf("[!] Error scanning %s: %v\n", ip, err)
        }
        return &ScanResult{IP: ip, IsAlive: false}, nil
    }
    conn.Close()

    return &ScanResult{IP: ip, IsAlive: true}, nil
}
```

**Key Conversion Notes:**
- Return `(value, error)` tuple instead of raising exceptions
- Check errors immediately after operations that can fail
- Use `nil` error to indicate success
- Wrap errors with context using `fmt.Errorf("context: %w", err)`

### 2.3 Python subprocess to Go os/exec

**Python:**
```python
import subprocess

def run_command(cmd: List[str]) -> Tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
```

**Go:**
```go
import (
    "context"
    "os/exec"
    "time"
)

func runCommand(cmd []string) (string, string, int) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

    var stdout, stderr bytes.Buffer
    command.Stdout = &stdout
    command.Stderr = &stderr

    err := command.Run()
    if ctx.Err() == context.DeadlineExceeded {
        return "", "Command timed out", -1
    }

    exitCode := 0
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            exitCode = exitErr.ExitCode()
        } else {
            exitCode = -1
        }
    }

    return stdout.String(), stderr.String(), exitCode
}
```

### 2.4 Python threading to Go Goroutines

**Python:**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan(self) -> List[ScanResult]:
    targets = list(self._expand_targets())

    with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
        futures = {executor.submit(self._scan_host, ip): ip for ip in targets}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    with self._lock:
                        self.results.append(result)
            except Exception as e:
                print(f"Error: {e}")

    return self.results
```

**Go:**
```go
func (ns *NetworkScanner) Scan() []*ScanResult {
    targets := ns.ExpandTargets()

    // Create work channel and results channel
    jobs := make(chan string, len(targets))
    results := make(chan *ScanResult, len(targets))

    // Start worker goroutines
    var wg sync.WaitGroup
    for i := 0; i < ns.Config.Threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for ip := range jobs {
                result := ns.scanHost(ip)
                if result != nil {
                    results <- result
                }
            }
        }()
    }

    // Send jobs
    for _, ip := range targets {
        jobs <- ip
    }
    close(jobs)

    // Wait for workers and close results
    go func() {
        wg.Wait()
        close(results)
    }()

    // Collect results
    for result := range results {
        ns.mutex.Lock()
        ns.Results = append(ns.Results, result)
        ns.mutex.Unlock()
    }

    return ns.Results
}
```

**Key Conversion Notes:**
- `ThreadPoolExecutor` becomes worker goroutines reading from a channel
- `threading.Lock` becomes `sync.Mutex`
- `as_completed` pattern becomes channel range iteration
- `WaitGroup` coordinates goroutine completion

### 2.5 Python dataclasses to Go Structs

**Python:**
```python
@dataclass
class ScanConfig:
    targets: List[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    resolve_hostnames: bool = False
    scan_methods: List[str] = field(default_factory=lambda: ["tcp"])
    tcp_ports: List[int] = field(default_factory=lambda: [80, 443, 22])
    verbose: bool = False
    plan_mode: bool = False
```

**Go:**
```go
type ScanConfig struct {
    Targets          []string
    Timeout          float64
    Threads          int
    DelayMin         float64
    DelayMax         float64
    ResolveHostnames bool
    ScanMethods      []string
    TCPPorts         []int
    Verbose          bool
    PlanMode         bool
}

// NewScanConfig creates a new ScanConfig with default values
func NewScanConfig() *ScanConfig {
    return &ScanConfig{
        Targets:          []string{},
        Timeout:          DefaultTimeout,
        Threads:          DefaultThreads,
        DelayMin:         DefaultDelayMin,
        DelayMax:         DefaultDelayMax,
        ResolveHostnames: false,
        ScanMethods:      []string{"tcp"},
        TCPPorts:         []int{80, 443, 22},
        Verbose:          false,
        PlanMode:         false,
    }
}
```

### 2.6 Python ABC to Go Interfaces

**Python:**
```python
from abc import ABC, abstractmethod

class ScanTechnique(ABC):
    """Abstract base class for scan techniques."""

    @abstractmethod
    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass


class TCPConnectScan(ScanTechnique):
    @property
    def name(self) -> str:
        return "tcp_connect"

    @property
    def description(self) -> str:
        return "TCP Connect scan using socket connections"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        # Implementation
        pass
```

**Go:**
```go
// ScanTechnique defines the interface for scan techniques
type ScanTechnique interface {
    Scan(ip string, config *ScanConfig) *ScanResult
    Name() string
    Description() string
}

// TCPConnectScan implements TCP Connect scanning
type TCPConnectScan struct{}

func (t *TCPConnectScan) Name() string {
    return "tcp_connect"
}

func (t *TCPConnectScan) Description() string {
    return "TCP Connect scan using socket connections"
}

func (t *TCPConnectScan) Scan(ip string, config *ScanConfig) *ScanResult {
    // Implementation
    return nil
}
```

**Key Conversion Notes:**
- Go interfaces are implicitly satisfied (no `implements` keyword)
- Python properties become Go methods
- No inheritance hierarchy required in Go

### 2.7 Python hashlib to Go crypto Packages

**Python:**
```python
import hashlib

def hash_password(password: str, hash_type: str) -> str:
    if hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type == "ntlm":
        # NTLM uses MD4 on UTF-16LE encoded password
        return hashlib.new('md4', password.encode('utf-16-le')).hexdigest()
```

**Go:**
```go
import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
    "unicode/utf16"
)

func hashPassword(password string, hashType string) string {
    switch hashType {
    case "md5":
        h := md5.Sum([]byte(password))
        return hex.EncodeToString(h[:])
    case "sha1":
        h := sha1.Sum([]byte(password))
        return hex.EncodeToString(h[:])
    case "sha256":
        h := sha256.Sum256([]byte(password))
        return hex.EncodeToString(h[:])
    case "sha512":
        h := sha512.Sum512([]byte(password))
        return hex.EncodeToString(h[:])
    case "ntlm":
        // Convert to UTF-16LE
        runes := utf16.Encode([]rune(password))
        bytes := make([]byte, len(runes)*2)
        for i, r := range runes {
            bytes[i*2] = byte(r)
            bytes[i*2+1] = byte(r >> 8)
        }
        h := md4.Sum(bytes) // Note: requires golang.org/x/crypto/md4
        return hex.EncodeToString(h[:])
    }
    return ""
}
```

---

## Section 3: Architecture Comparison

### 3.1 Side-by-Side Structure Comparison

```
+------------------------------------------+------------------------------------------+
|              PYTHON TOOL                  |               GO TOOL                    |
+------------------------------------------+------------------------------------------+
|                                          |                                          |
|  #!/usr/bin/env python3                  |  package main                            |
|  """Docstring"""                         |  // Package comment                      |
|                                          |                                          |
|  # Imports                               |  import (                                |
|  import argparse                         |      "flag"                              |
|  import socket                           |      "net"                               |
|  from dataclasses import dataclass       |      "sync"                              |
|  from typing import List, Optional       |      "time"                              |
|  from abc import ABC, abstractmethod     |  )                                       |
|                                          |                                          |
|  # Constants                             |  // Constants                            |
|  DEFAULT_TIMEOUT = 2.0                   |  const DefaultTimeout = 2.0              |
|  DEFAULT_THREADS = 10                    |  const DefaultThreads = 10               |
|                                          |                                          |
|  # Data Classes                          |  // Data Structures                      |
|  @dataclass                              |  type ScanResult struct {                |
|  class ScanResult:                       |      IP      string `json:"ip"`          |
|      ip: str                             |      IsAlive bool   `json:"is_alive"`    |
|      is_alive: bool                      |  }                                       |
|                                          |                                          |
|  # Abstract Base Class                   |  // Interface                            |
|  class Scanner(ABC):                     |  type Scanner interface {                |
|      @abstractmethod                     |      Scan(ip string) *ScanResult         |
|      def scan(self, ip: str): pass       |  }                                       |
|                                          |                                          |
|  # Implementation                        |  // Implementation                       |
|  class TCPScanner(Scanner):              |  type TCPScanner struct {                |
|      def __init__(self, config):         |      Config *ScanConfig                  |
|          self.config = config            |  }                                       |
|      def scan(self, ip: str):            |  func (s *TCPScanner) Scan(...) {...}    |
|          ...                             |                                          |
|                                          |                                          |
|  # CLI                                   |  // CLI                                  |
|  def parse_arguments():                  |  func main() {                           |
|      parser = argparse.ArgumentParser()  |      timeout := flag.Float64("t", 2.0,   |
|      parser.add_argument("-t", ...)      |          "Timeout in seconds")           |
|      return parser.parse_args()          |      flag.Parse()                        |
|                                          |  }                                       |
|  def main():                             |                                          |
|      args = parse_arguments()            |                                          |
|      ...                                 |                                          |
|                                          |                                          |
|  if __name__ == "__main__":              |  // (main function runs automatically)   |
|      main()                              |                                          |
|                                          |                                          |
+------------------------------------------+------------------------------------------+
```

### 3.2 CLI Argument Handling: argparse vs flag

**Python argparse:**
```python
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Network Scanner - Stealthy Host Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24 --plan
  %(prog)s 192.168.1.1-254 --methods tcp dns
        """
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Target IPs, CIDR ranges, or IP ranges"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Concurrent threads (default: {DEFAULT_THREADS})"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()
```

**Go flag:**
```go
func main() {
    config := NewScanConfig()

    // Define flags (Go flag package supports both short and long forms)
    timeout := flag.Float64("t", DefaultTimeout, "Connection timeout")
    flag.Float64Var(&config.Timeout, "timeout", DefaultTimeout, "Connection timeout")

    threads := flag.Int("T", DefaultThreads, "Concurrent threads")
    flag.IntVar(&config.Threads, "threads", DefaultThreads, "Concurrent threads")

    flag.BoolVar(&config.Verbose, "v", false, "Enable verbose output")
    flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")

    // Custom usage message
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, `Network Scanner - Stealthy Host Discovery Tool

Usage:
  %s [flags] targets...

Examples:
  scanner 192.168.1.0/24 --plan
  scanner 192.168.1.1-254 -m tcp,dns

Flags:
`, os.Args[0])
        flag.PrintDefaults()
    }

    flag.Parse()

    // Positional arguments (targets) come from flag.Args()
    targets := flag.Args()
    if len(targets) == 0 {
        fmt.Fprintln(os.Stderr, "Error: No targets specified")
        flag.Usage()
        os.Exit(1)
    }

    config.Targets = targets
}
```

### 3.3 Output Formatting Comparison

**Python:**
```python
import json
from datetime import datetime

def output_results(results: List[ScanResult], output_file: Optional[str]):
    # Console output
    print("=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Total hosts scanned: {len(results)}")

    live_hosts = [r for r in results if r.is_alive]
    print(f"Live hosts found:    {len(live_hosts)}")

    if live_hosts:
        print("\nLIVE HOSTS:")
        print("-" * 60)
        for host in live_hosts:
            hostname_str = f" ({host.hostname})" if host.hostname else ""
            time_str = f" [{host.response_time:.3f}s]" if host.response_time else ""
            print(f"  {host.ip}{hostname_str}{time_str} - {host.method}")

    # JSON file output
    if output_file:
        output_data = {
            "scan_time": datetime.now().isoformat(),
            "results": [r.to_dict() for r in results]
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
```

**Go:**
```go
import (
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"
)

func outputResults(results []*ScanResult, outputFile string) {
    // Console output
    fmt.Println(strings.Repeat("=", 60))
    fmt.Println("SCAN RESULTS")
    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("Total hosts scanned: %d\n", len(results))

    var liveHosts []*ScanResult
    for _, r := range results {
        if r.IsAlive {
            liveHosts = append(liveHosts, r)
        }
    }
    fmt.Printf("Live hosts found:    %d\n", len(liveHosts))

    if len(liveHosts) > 0 {
        fmt.Println("\nLIVE HOSTS:")
        fmt.Println(strings.Repeat("-", 60))
        for _, host := range liveHosts {
            hostnameStr := ""
            if host.Hostname != nil {
                hostnameStr = fmt.Sprintf(" (%s)", *host.Hostname)
            }
            timeStr := ""
            if host.ResponseTime != nil {
                timeStr = fmt.Sprintf(" [%.3fs]", *host.ResponseTime)
            }
            fmt.Printf("  %s%s%s - %s\n", host.IP, hostnameStr, timeStr, host.Method)
        }
    }

    // JSON file output
    if outputFile != "" {
        outputData := map[string]interface{}{
            "scan_time": time.Now().Format(time.RFC3339),
            "results": func() []map[string]interface{} {
                var r []map[string]interface{}
                for _, result := range results {
                    r = append(r, result.ToDict())
                }
                return r
            }(),
        }

        jsonData, _ := json.MarshalIndent(outputData, "", "  ")
        os.WriteFile(outputFile, jsonData, 0644)
    }
}
```

---

## Section 4: Step-by-Step Conversion Tutorial

This section walks through converting a Python tool to Go using the network-scanner as a reference implementation.

### Step 1: Analyze the Python Tool Structure

Before writing any Go code, thoroughly analyze the Python implementation:

```
+-------------------------------------------------------------------------+
|                        ANALYSIS CHECKLIST                                |
+-------------------------------------------------------------------------+
|                                                                         |
|  1. IMPORTS                                                             |
|     [ ] Standard library modules used                                   |
|     [ ] Third-party dependencies                                        |
|     [ ] Type hints and their implications                               |
|                                                                         |
|  2. DATA STRUCTURES                                                     |
|     [ ] Dataclasses and their fields                                    |
|     [ ] Type annotations (Optional, List, Dict)                         |
|     [ ] Default values and factory functions                            |
|                                                                         |
|  3. CLASS HIERARCHY                                                     |
|     [ ] Abstract base classes                                           |
|     [ ] Concrete implementations                                        |
|     [ ] Method signatures                                               |
|                                                                         |
|  4. CONCURRENCY                                                         |
|     [ ] Thread pool usage                                               |
|     [ ] Synchronization primitives                                      |
|     [ ] Shared state management                                         |
|                                                                         |
|  5. I/O OPERATIONS                                                      |
|     [ ] Network operations                                              |
|     [ ] File operations                                                 |
|     [ ] Console output formatting                                       |
|                                                                         |
|  6. ERROR HANDLING                                                      |
|     [ ] Exception types caught                                          |
|     [ ] Error recovery patterns                                         |
|     [ ] Graceful degradation                                            |
|                                                                         |
+-------------------------------------------------------------------------+
```

### Step 2: Create the Go File Structure

Begin with the package declaration and imports:

```go
// scanner.go - Go port of network-scanner/tool.py
// A comprehensive network scanning utility for authorized penetration testing.
//
// Build instructions:
//   go build -o scanner scanner.go
//
// WARNING: This tool is intended for authorized security assessments only.

package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "math/rand"
    "net"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)
```

### Step 3: Define Constants and Types

Convert Python constants and dataclasses:

```go
// Constants - match Python DEFAULT_* values
const (
    DefaultTimeout  = 2.0
    DefaultThreads  = 10
    DefaultDelayMin = 0.0
    DefaultDelayMax = 0.1
)

// ScanResult - converted from @dataclass
type ScanResult struct {
    IP           string   `json:"ip"`
    IsAlive      bool     `json:"is_alive"`
    ResponseTime *float64 `json:"response_time,omitempty"`
    Method       string   `json:"method"`
    Hostname     *string  `json:"hostname,omitempty"`
    Timestamp    string   `json:"timestamp"`
}

// ScanConfig - converted from @dataclass
type ScanConfig struct {
    Targets          []string
    Timeout          float64
    Threads          int
    DelayMin         float64
    DelayMax         float64
    ResolveHostnames bool
    ScanMethods      []string
    TCPPorts         []int
    Verbose          bool
    PlanMode         bool
}
```

### Step 4: Convert Interfaces from ABCs

Transform Python abstract base classes to Go interfaces:

```go
// ScanTechnique - converted from ABC
type ScanTechnique interface {
    Scan(ip string, config *ScanConfig) *ScanResult
    Name() string
    Description() string
}

// TCPConnectScan implements ScanTechnique
type TCPConnectScan struct{}

func (t *TCPConnectScan) Name() string {
    return "tcp_connect"
}

func (t *TCPConnectScan) Description() string {
    return "TCP Connect scan using socket connections to detect live hosts"
}

func (t *TCPConnectScan) Scan(ip string, config *ScanConfig) *ScanResult {
    startTime := time.Now()

    for _, port := range config.TCPPorts {
        address := fmt.Sprintf("%s:%d", ip, port)
        timeout := time.Duration(config.Timeout * float64(time.Second))

        conn, err := net.DialTimeout("tcp", address, timeout)
        if err == nil {
            conn.Close()
            responseTime := time.Since(startTime).Seconds()

            return &ScanResult{
                IP:           ip,
                IsAlive:      true,
                ResponseTime: &responseTime,
                Method:       fmt.Sprintf("tcp_connect:%d", port),
                Timestamp:    time.Now().Format(time.RFC3339),
            }
        }
    }

    return &ScanResult{
        IP:        ip,
        IsAlive:   false,
        Method:    "tcp_connect",
        Timestamp: time.Now().Format(time.RFC3339),
    }
}
```

### Step 5: Convert the Main Scanner Class

Transform the core scanner with threading to goroutines:

```go
type NetworkScanner struct {
    Config     *ScanConfig
    Results    []*ScanResult
    stopEvent  chan struct{}
    mutex      sync.Mutex
    techniques map[string]ScanTechnique
}

func NewNetworkScanner(config *ScanConfig) *NetworkScanner {
    return &NetworkScanner{
        Config:    config,
        Results:   []*ScanResult{},
        stopEvent: make(chan struct{}),
        techniques: map[string]ScanTechnique{
            "tcp": &TCPConnectScan{},
            "arp": &ARPScan{},
            "dns": &DNSResolutionScan{},
        },
    }
}

func (ns *NetworkScanner) Scan() []*ScanResult {
    targets := ns.ExpandTargets()

    jobs := make(chan string, len(targets))
    results := make(chan *ScanResult, len(targets))

    var wg sync.WaitGroup
    for i := 0; i < ns.Config.Threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for ip := range jobs {
                result := ns.scanHost(ip)
                if result != nil {
                    results <- result
                }
            }
        }()
    }

    for _, ip := range targets {
        jobs <- ip
    }
    close(jobs)

    go func() {
        wg.Wait()
        close(results)
    }()

    for result := range results {
        ns.mutex.Lock()
        ns.Results = append(ns.Results, result)
        ns.mutex.Unlock()
    }

    return ns.Results
}
```

### Step 6: Testing Parity

Create test cases that verify identical behavior:

```go
// scanner_test.go
package main

import (
    "testing"
)

func TestExpandTargetsCIDR(t *testing.T) {
    config := &ScanConfig{
        Targets: []string{"192.168.1.0/30"},
    }
    scanner := NewNetworkScanner(config)

    targets := scanner.ExpandTargets()

    // /30 should produce 2 usable hosts (excluding network and broadcast)
    expected := []string{"192.168.1.1", "192.168.1.2"}

    if len(targets) != len(expected) {
        t.Errorf("Expected %d targets, got %d", len(expected), len(targets))
    }
}

func TestExpandTargetsRange(t *testing.T) {
    config := &ScanConfig{
        Targets: []string{"10.0.0.1-5"},
    }
    scanner := NewNetworkScanner(config)

    targets := scanner.ExpandTargets()

    if len(targets) != 5 {
        t.Errorf("Expected 5 targets, got %d", len(targets))
    }
}
```

### Step 7: Build for Multiple Platforms

Create a build script for cross-compilation:

```bash
#!/bin/bash
# build-all.sh - Cross-compile for multiple platforms

TOOL_NAME="scanner"
VERSION="1.0.0"
OUTPUT_DIR="./dist"

mkdir -p $OUTPUT_DIR

# Build matrix
PLATFORMS=(
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm"
    "windows/amd64"
    "windows/386"
    "darwin/amd64"
    "darwin/arm64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS="${PLATFORM%/*}"
    GOARCH="${PLATFORM#*/}"

    OUTPUT_NAME="${TOOL_NAME}-${VERSION}-${GOOS}-${GOARCH}"

    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "${OUTPUT_DIR}/${OUTPUT_NAME}" scanner.go

    if [ $? -eq 0 ]; then
        echo "  -> ${OUTPUT_DIR}/${OUTPUT_NAME}"
    else
        echo "  -> FAILED"
    fi
done

echo ""
echo "Build complete. Binaries in ${OUTPUT_DIR}/"
ls -la ${OUTPUT_DIR}/
```

---

## Section 5: CPTC11 Go Tools Reference

The following ten tools have been converted from Python to Go for the CPTC11 toolkit.

### 5.1 Tool Index

| # | Tool Name | Go Binary | Primary Function |
|---|-----------|-----------|------------------|
| 1 | network-scanner | scanner | Host discovery via TCP/ARP/DNS |
| 2 | port-scanner | scanner | TCP/UDP port scanning |
| 3 | service-fingerprinter | fingerprinter | Service version detection |
| 4 | web-directory-enumerator | enumerator | Web content discovery |
| 5 | credential-validator | validator | Multi-protocol auth testing |
| 6 | dns-enumerator | enumerator | DNS reconnaissance |
| 7 | smb-enumerator | enumerator | SMB share/user enumeration |
| 8 | http-request-tool | httptool | Flexible HTTP client |
| 9 | hash-cracker | cracker | Multi-algorithm hash cracking |
| 10 | reverse-shell-handler | handler | Shell listener/manager |

### 5.2 Build Instructions

**Individual Tool Build:**
```bash
cd /Users/ic/cptc11/golang/tools/network-scanner
go build -o scanner scanner.go

cd /Users/ic/cptc11/golang/tools/port-scanner
go build -o scanner scanner.go

cd /Users/ic/cptc11/golang/tools/service-fingerprinter
go build -o fingerprinter fingerprinter.go

cd /Users/ic/cptc11/golang/tools/web-directory-enumerator
go build -o enumerator enumerator.go

cd /Users/ic/cptc11/golang/tools/credential-validator
go build -o validator validator.go

cd /Users/ic/cptc11/golang/tools/dns-enumerator
go build -o enumerator enumerator.go

cd /Users/ic/cptc11/golang/tools/smb-enumerator
go build -o enumerator enumerator.go

cd /Users/ic/cptc11/golang/tools/http-request-tool
go build -o httptool httptool.go

cd /Users/ic/cptc11/golang/tools/hash-cracker
go build -o cracker cracker.go

cd /Users/ic/cptc11/golang/tools/reverse-shell-handler
go build -o handler handler.go
```

**Optimized Production Build (smaller binary):**
```bash
go build -ldflags="-s -w" -o scanner scanner.go
```

**Cross-Compilation Examples:**
```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o scanner-linux scanner.go

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o scanner.exe scanner.go

# Linux ARM64 (Raspberry Pi, AWS Graviton)
GOOS=linux GOARCH=arm64 go build -o scanner-arm64 scanner.go
```

### 5.3 Usage Examples

**1. Network Scanner**
```bash
# Preview scan plan
./scanner 192.168.1.0/24 --plan

# Basic scan
./scanner 192.168.1.0/24

# Multi-method with custom ports
./scanner 192.168.1.1-254 -m tcp,dns -P 22,80,443,8080 -T 20

# Stealth scan with delays
./scanner 10.0.0.0/24 --delay-min 1 --delay-max 5 -T 5 -v
```

**2. Port Scanner**
```bash
# Top 100 ports
./scanner 192.168.1.1 --top-ports 100

# Port range
./scanner 192.168.1.1 --ports 1-1024

# UDP scan
./scanner 192.168.1.1 --ports 53,161,500 --udp
```

**3. Service Fingerprinter**
```bash
# Fingerprint common ports
./fingerprinter 192.168.1.1 --ports 22,80,443,3306

# Aggressive mode with SSL checks
./fingerprinter target.com --ports 443,8443 --aggressive --ssl-check
```

**4. Web Directory Enumerator**
```bash
# Default wordlist
./enumerator http://target.com

# Custom wordlist with extensions
./enumerator http://target.com -w custom.txt -x php,asp,aspx

# With authentication
./enumerator http://target.com --auth admin:password
```

**5. Credential Validator**
```bash
# Single credential test
./validator 192.168.1.1 --protocol ssh -u admin -P password

# Credential file
./validator target.com --protocol http-basic --credentials creds.txt
```

**6. DNS Enumerator**
```bash
# Basic enumeration
./enumerator example.com

# Zone transfer attempt
./enumerator example.com --zone-transfer

# Subdomain bruteforce
./enumerator example.com -w subdomains.txt -T 20
```

**7. SMB Enumerator**
```bash
# Null session enumeration
./enumerator 192.168.1.1 --null-session

# Authenticated enumeration
./enumerator 192.168.1.1 -u admin -P password -d DOMAIN
```

**8. HTTP Request Tool**
```bash
# GET request
./httptool http://target.com/api/endpoint

# POST with JSON
./httptool http://target.com/api -X POST -d '{"key":"value"}'

# Custom headers
./httptool https://target.com -H "Authorization: Bearer token"
```

**9. Hash Cracker**
```bash
# Dictionary attack
./cracker 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt

# Multiple hashes from file
./cracker --file hashes.txt -w wordlist.txt --type md5

# Bruteforce mode
./cracker 5f4dcc3b5aa765d61d8327deb882cf99 --bruteforce -c alphanumeric --max-len 6
```

**10. Reverse Shell Handler**
```bash
# Basic listener
./handler -l 4444

# SSL listener
./handler -l 443 --ssl

# Generate payloads
./handler --payloads -H 10.0.0.1 -l 4444
```

---

## Section 6: Hands-On Labs

### Lab 1: Simple Utility Conversion

**Objective:** Convert a basic Python hash utility to Go, demonstrating fundamental conversion patterns.

**Environment Setup:**
- Go 1.21+ installed
- Text editor or IDE with Go support
- Terminal access

**Scenario:** You have been provided a Python utility that generates MD5, SHA1, and SHA256 hashes of input strings. Convert this to a Go implementation that produces identical output.

**Starting Python Code:**
```python
#!/usr/bin/env python3
"""Simple hash generator utility."""
import hashlib
import argparse
import sys

def hash_string(data: str, algorithm: str) -> str:
    """Hash a string using the specified algorithm."""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
    }

    if algorithm not in algorithms:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    return algorithms[algorithm](data.encode()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Hash generator utility")
    parser.add_argument("data", help="String to hash")
    parser.add_argument("-a", "--algorithm",
                        choices=['md5', 'sha1', 'sha256'],
                        default='sha256',
                        help="Hash algorithm (default: sha256)")
    args = parser.parse_args()

    try:
        result = hash_string(args.data, args.algorithm)
        print(f"{args.algorithm.upper()}: {result}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

**Task Instructions:**

1. Create a new file `hasher.go`
2. Implement equivalent functionality using Go's crypto packages
3. Use the flag package for command-line argument handling
4. Ensure output format matches the Python version exactly

**Hints (Progressive):**

<details>
<summary>Hint 1: Import Structure</summary>

```go
import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "strings"
)
```
</details>

<details>
<summary>Hint 2: Hash Function Signature</summary>

```go
func hashString(data string, algorithm string) (string, error) {
    // Implementation here
}
```
</details>

<details>
<summary>Hint 3: Switch Statement for Algorithms</summary>

```go
switch algorithm {
case "md5":
    h := md5.Sum([]byte(data))
    return hex.EncodeToString(h[:]), nil
// Continue for other algorithms...
}
```
</details>

**Solution Guide:**
```go
package main

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "strings"
)

func hashString(data string, algorithm string) (string, error) {
    switch algorithm {
    case "md5":
        h := md5.Sum([]byte(data))
        return hex.EncodeToString(h[:]), nil
    case "sha1":
        h := sha1.Sum([]byte(data))
        return hex.EncodeToString(h[:]), nil
    case "sha256":
        h := sha256.Sum256([]byte(data))
        return hex.EncodeToString(h[:]), nil
    default:
        return "", fmt.Errorf("unknown algorithm: %s", algorithm)
    }
}

func main() {
    algorithm := flag.String("a", "sha256", "Hash algorithm (md5, sha1, sha256)")
    flag.String("algorithm", "sha256", "Hash algorithm (md5, sha1, sha256)")
    flag.Parse()

    args := flag.Args()
    if len(args) != 1 {
        fmt.Fprintln(os.Stderr, "Error: data argument required")
        os.Exit(1)
    }

    data := args[0]
    result, err := hashString(data, *algorithm)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("%s: %s\n", strings.ToUpper(*algorithm), result)
}
```

**Validation Criteria:**
- [ ] Program compiles without errors
- [ ] Output format matches Python exactly
- [ ] All three hash algorithms produce correct results
- [ ] Error handling mirrors Python behavior

---

### Lab 2: Network Tool Conversion

**Objective:** Convert a Python TCP port checker to Go, focusing on concurrent operations.

**Environment Setup:**
- Lab 1 completed
- Test target available (use localhost or authorized system)

**Scenario:** A Python tool performs concurrent TCP port checks using ThreadPoolExecutor. Convert it to Go using goroutines and channels.

**Starting Python Code:**
```python
#!/usr/bin/env python3
"""TCP Port Checker with concurrent scanning."""
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

def check_port(target: str, port: int, timeout: float) -> Tuple[int, bool]:
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return port, result == 0
    except socket.error:
        return port, False

def scan_ports(target: str, ports: List[int], threads: int, timeout: float) -> dict:
    """Scan multiple ports concurrently."""
    results = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_port, target, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port, is_open = future.result()
            results[port] = is_open

    return results

def main():
    parser = argparse.ArgumentParser(description="TCP Port Checker")
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p", "--ports", default="22,80,443",
                        help="Ports to scan (comma-separated)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Connection timeout")
    parser.add_argument("-T", "--threads", type=int, default=10,
                        help="Concurrent threads")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")]
    results = scan_ports(args.target, ports, args.threads, args.timeout)

    print(f"\nResults for {args.target}:")
    print("-" * 30)
    for port in sorted(results.keys()):
        status = "OPEN" if results[port] else "CLOSED"
        print(f"  Port {port}: {status}")

if __name__ == "__main__":
    main()
```

**Task Instructions:**

1. Create `portcheck.go` with equivalent functionality
2. Use goroutines and channels instead of ThreadPoolExecutor
3. Implement proper synchronization with WaitGroup and Mutex
4. Maintain identical output format

**Hints (Progressive):**

<details>
<summary>Hint 1: Result Structure</summary>

```go
type PortResult struct {
    Port   int
    IsOpen bool
}
```
</details>

<details>
<summary>Hint 2: Worker Goroutine Pattern</summary>

```go
jobs := make(chan int, len(ports))
results := make(chan PortResult, len(ports))

var wg sync.WaitGroup
for i := 0; i < threads; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for port := range jobs {
            // Check port and send result
        }
    }()
}
```
</details>

**Validation Criteria:**
- [ ] Concurrent scanning works correctly
- [ ] Results match Python implementation
- [ ] Thread count is respected
- [ ] Timeout behavior is consistent

---

### Lab 3: Cross-Compilation Exercise

**Objective:** Build a Go tool for multiple platforms and verify functionality.

**Environment Setup:**
- Labs 1 and 2 completed
- Access to test systems (or VMs) running different operating systems

**Scenario:** Prepare a deployment package of the port checker for Linux, Windows, and macOS targets.

**Task Instructions:**

1. Create a build script that produces binaries for:
   - Linux AMD64
   - Linux ARM64
   - Windows AMD64
   - macOS AMD64
   - macOS ARM64

2. Apply size optimization flags

3. Create a verification matrix documenting binary sizes and SHA256 hashes

**Build Script Template:**
```bash
#!/bin/bash
# build-multiplatform.sh

TOOL="portcheck"
VERSION="1.0.0"
OUTDIR="./release"

mkdir -p $OUTDIR

# Define build targets
declare -A TARGETS
TARGETS["linux-amd64"]="linux/amd64"
TARGETS["linux-arm64"]="linux/arm64"
TARGETS["windows-amd64"]="windows/amd64"
TARGETS["darwin-amd64"]="darwin/amd64"
TARGETS["darwin-arm64"]="darwin/arm64"

echo "Building $TOOL v$VERSION"
echo "========================"

for NAME in "${!TARGETS[@]}"; do
    PLATFORM="${TARGETS[$NAME]}"
    GOOS="${PLATFORM%/*}"
    GOARCH="${PLATFORM#*/}"

    OUTPUT="$OUTDIR/${TOOL}-${NAME}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo -n "Building $NAME... "
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUTPUT" portcheck.go

    if [ $? -eq 0 ]; then
        SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
        HASH=$(shasum -a 256 "$OUTPUT" | awk '{print $1}')
        echo "OK ($SIZE)"
        echo "  SHA256: $HASH"
    else
        echo "FAILED"
    fi
done

echo ""
echo "Build artifacts in $OUTDIR/"
```

**Verification Matrix Template:**

| Platform | Binary Name | Size | SHA256 | Verified |
|----------|-------------|------|--------|----------|
| Linux AMD64 | portcheck-linux-amd64 | | | [ ] |
| Linux ARM64 | portcheck-linux-arm64 | | | [ ] |
| Windows AMD64 | portcheck-windows-amd64.exe | | | [ ] |
| macOS AMD64 | portcheck-darwin-amd64 | | | [ ] |
| macOS ARM64 | portcheck-darwin-arm64 | | | [ ] |

**Extension Challenge:**

Integrate UPX compression to further reduce binary sizes:
```bash
upx --best --lzma $OUTPUT
```

Compare pre- and post-compression sizes and document any compatibility issues encountered.

**Validation Criteria:**
- [ ] All platform builds succeed
- [ ] Binaries execute on target platforms
- [ ] SHA256 hashes are documented
- [ ] Size optimization flags applied

---

## Assessment Checklist

Before considering this module complete, verify:

- [ ] Can articulate three or more advantages of Go over Python for tool deployment
- [ ] Successfully converted a dataclass to Go struct with JSON tags
- [ ] Implemented proper error handling without exceptions
- [ ] Converted threaded code to goroutines with channels
- [ ] Built binaries for at least three different platforms
- [ ] Completed all three hands-on labs
- [ ] Tested converted tools for functional parity

---

## Quick Reference Card

### Common Conversions

| Python | Go |
|--------|-----|
| `from typing import Optional` | Use pointer `*T` |
| `from typing import List` | Use slice `[]T` |
| `from typing import Dict` | Use map `map[K]V` |
| `@dataclass` | `type X struct {}` |
| `class X(ABC):` | `type X interface {}` |
| `def __init__(self):` | `func NewX() *X {}` |
| `try: ... except:` | `if err != nil {}` |
| `with ThreadPoolExecutor() as e:` | goroutines + WaitGroup |
| `threading.Lock()` | `sync.Mutex` |
| `import argparse` | `import "flag"` |
| `import json` | `import "encoding/json"` |
| `import hashlib` | `import "crypto/..."` |

### Build Commands

```bash
# Basic build
go build -o tool tool.go

# Optimized build
go build -ldflags="-s -w" -o tool tool.go

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o tool-linux tool.go
GOOS=windows GOARCH=amd64 go build -o tool.exe tool.go
```

---

*Document Version: 1.0.0*
*Last Updated: 2026-01-10*
*Word Count: 2800+*
