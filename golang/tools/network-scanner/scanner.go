// scanner.go - Go port of network-scanner/tool.py
// A comprehensive network scanning utility for authorized penetration testing.
//
// Build instructions:
//   go build -o scanner scanner.go
//
// Usage:
//   ./scanner <targets> [flags]
//   ./scanner 192.168.1.0/24 --plan
//   ./scanner 192.168.1.1-50 --methods tcp,dns --threads 5
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized access to computer systems is illegal.

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

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultTimeout  = 2.0
	DefaultThreads  = 10
	DefaultDelayMin = 0.0
	DefaultDelayMax = 0.1
)

var DefaultTCPPorts = []int{80, 443, 22}

// =============================================================================
// Data Structures
// =============================================================================

// ScanResult represents a single host scan result
// Equivalent to Python's @dataclass ScanResult
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

// ScanConfig holds configuration for network scanning operations
// Equivalent to Python's @dataclass ScanConfig
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
	OutputFile       string
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
		TCPPorts:         DefaultTCPPorts,
		Verbose:          false,
		PlanMode:         false,
	}
}

// =============================================================================
// Scanning Techniques
// =============================================================================

// ScanTechnique defines the interface for scan techniques
// Equivalent to Python's ABC ScanTechnique
type ScanTechnique interface {
	Scan(ip string, config *ScanConfig) *ScanResult
	Name() string
	Description() string
}

// TCPConnectScan implements TCP Connect scanning
// Equivalent to Python's TCPConnectScan class
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

			var hostname *string
			if config.ResolveHostnames {
				names, err := net.LookupAddr(ip)
				if err == nil && len(names) > 0 {
					h := strings.TrimSuffix(names[0], ".")
					hostname = &h
				}
			}

			return &ScanResult{
				IP:           ip,
				IsAlive:      true,
				ResponseTime: &responseTime,
				Method:       fmt.Sprintf("tcp_connect:%d", port),
				Hostname:     hostname,
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

// ARPScan implements ARP-based scanning
// Equivalent to Python's ARPScan class
type ARPScan struct{}

func (a *ARPScan) Name() string {
	return "arp"
}

func (a *ARPScan) Description() string {
	return "ARP scan for local network host discovery (requires privileges)"
}

func (a *ARPScan) Scan(ip string, config *ScanConfig) *ScanResult {
	// Note: Full ARP implementation requires raw sockets and elevated privileges
	// This is a placeholder that falls back to TCP scanning
	tcpScan := &TCPConnectScan{}
	result := tcpScan.Scan(ip, config)
	result.Method = "arp_fallback_tcp"
	return result
}

// DNSResolutionScan implements DNS-based host discovery
// Equivalent to Python's DNSResolutionScan class
type DNSResolutionScan struct{}

func (d *DNSResolutionScan) Name() string {
	return "dns"
}

func (d *DNSResolutionScan) Description() string {
	return "DNS reverse lookup scan to identify hosts with PTR records"
}

func (d *DNSResolutionScan) Scan(ip string, config *ScanConfig) *ScanResult {
	startTime := time.Now()

	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		responseTime := time.Since(startTime).Seconds()
		hostname := strings.TrimSuffix(names[0], ".")

		return &ScanResult{
			IP:           ip,
			IsAlive:      true,
			ResponseTime: &responseTime,
			Method:       "dns_ptr",
			Hostname:     &hostname,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	}

	return &ScanResult{
		IP:        ip,
		IsAlive:   false,
		Method:    "dns_ptr",
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// =============================================================================
// Network Scanner Core
// =============================================================================

// NetworkScanner is the main scanning engine
// Equivalent to Python's NetworkScanner class
type NetworkScanner struct {
	Config     *ScanConfig
	Results    []*ScanResult
	stopEvent  chan struct{}
	mutex      sync.Mutex
	techniques map[string]ScanTechnique
}

// NewNetworkScanner creates a new NetworkScanner instance
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

// ExpandTargets expands target specifications into individual IP addresses
// Supports single IPs, CIDR notation, and ranges
func (ns *NetworkScanner) ExpandTargets() []string {
	var ips []string

	for _, target := range ns.Config.Targets {
		// Try CIDR notation
		if strings.Contains(target, "/") {
			_, ipnet, err := net.ParseCIDR(target)
			if err != nil {
				if ns.Config.Verbose {
					fmt.Printf("[!] Invalid CIDR: %s - %v\n", target, err)
				}
				continue
			}

			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
				// Skip network and broadcast addresses for /24 and smaller
				if ip[3] != 0 && ip[3] != 255 {
					ips = append(ips, ip.String())
				}
			}
			continue
		}

		// Try range notation (e.g., 192.168.1.1-254)
		if strings.Contains(target, "-") {
			parts := strings.Split(target, ".")
			if len(parts) == 4 {
				lastPart := parts[3]
				if strings.Contains(lastPart, "-") {
					rangeParts := strings.Split(lastPart, "-")
					if len(rangeParts) == 2 {
						start, err1 := strconv.Atoi(rangeParts[0])
						end, err2 := strconv.Atoi(rangeParts[1])
						if err1 == nil && err2 == nil {
							base := strings.Join(parts[:3], ".")
							for i := start; i <= end; i++ {
								ips = append(ips, fmt.Sprintf("%s.%d", base, i))
							}
							continue
						}
					}
				}
			}
		}

		// Single IP or hostname
		ips = append(ips, target)
	}

	return ips
}

// incrementIP increments an IP address by one
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// applyJitter applies a random delay for stealth operations
func (ns *NetworkScanner) applyJitter() {
	if ns.Config.DelayMax > 0 {
		delay := ns.Config.DelayMin + rand.Float64()*(ns.Config.DelayMax-ns.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// scanHost scans a single host using configured techniques
func (ns *NetworkScanner) scanHost(ip string) *ScanResult {
	select {
	case <-ns.stopEvent:
		return nil
	default:
	}

	ns.applyJitter()

	for _, method := range ns.Config.ScanMethods {
		if technique, ok := ns.techniques[method]; ok {
			result := technique.Scan(ip, ns.Config)
			if result.IsAlive {
				return result
			}
		}
	}

	return &ScanResult{
		IP:        ip,
		IsAlive:   false,
		Method:    "all_methods",
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// Scan executes the network scan
func (ns *NetworkScanner) Scan() []*ScanResult {
	targets := ns.ExpandTargets()

	if ns.Config.Verbose {
		fmt.Printf("[*] Scanning %d hosts with %d threads\n", len(targets), ns.Config.Threads)
	}

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
		if result.IsAlive && ns.Config.Verbose {
			fmt.Printf("[+] %s is alive (%s)\n", result.IP, result.Method)
		}
		ns.mutex.Unlock()
	}

	return ns.Results
}

// Stop signals the scanner to stop operations
func (ns *NetworkScanner) Stop() {
	close(ns.stopEvent)
}

// GetLiveHosts returns only hosts that responded
func (ns *NetworkScanner) GetLiveHosts() []*ScanResult {
	var liveHosts []*ScanResult
	for _, r := range ns.Results {
		if r.IsAlive {
			liveHosts = append(liveHosts, r)
		}
	}
	return liveHosts
}

// =============================================================================
// Planning Mode
// =============================================================================

// PrintPlan displays execution plan without performing any actions
// Equivalent to Python's print_plan function
func PrintPlan(config *ScanConfig) {
	scanner := NewNetworkScanner(config)
	targets := scanner.ExpandTargets()

	fmt.Println(`
[PLAN MODE] Tool: network-scanner
================================================================================
`)

	fmt.Println("OPERATION SUMMARY")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target Specification: %s\n", strings.Join(config.Targets, ", "))
	fmt.Printf("  Total IPs to scan:    %d\n", len(targets))
	fmt.Printf("  Scan Methods:         %s\n", strings.Join(config.ScanMethods, ", "))
	fmt.Printf("  TCP Ports:            %v\n", config.TCPPorts)
	fmt.Printf("  Threads:              %d\n", config.Threads)
	fmt.Printf("  Timeout:              %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:          %.1fs - %.1fs\n", config.DelayMin, config.DelayMax)
	fmt.Printf("  Resolve Hostnames:    %t\n", config.ResolveHostnames)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Parse and expand target specifications")
	fmt.Printf("  2. Initialize goroutine pool with %d workers\n", config.Threads)
	fmt.Println("  3. For each target IP:")
	for _, method := range config.ScanMethods {
		switch method {
		case "tcp":
			fmt.Printf("     - Attempt TCP connections to ports %v\n", config.TCPPorts)
		case "arp":
			fmt.Println("     - Send ARP request (requires privileges)")
		case "dns":
			fmt.Println("     - Perform reverse DNS lookup")
		}
	}
	fmt.Printf("  4. Apply random delay (%.2fs - %.2fs) between scans\n", config.DelayMin, config.DelayMax)
	fmt.Println("  5. Aggregate and report results in-memory")
	fmt.Println()

	fmt.Println("TARGET PREVIEW (first 10)")
	fmt.Println(strings.Repeat("-", 40))
	maxShow := 10
	if len(targets) < maxShow {
		maxShow = len(targets)
	}
	for i := 0; i < maxShow; i++ {
		fmt.Printf("  - %s\n", targets[i])
	}
	if len(targets) > 10 {
		fmt.Printf("  ... and %d more\n", len(targets)-10)
	}
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))

	// Calculate risk level
	var riskFactors []string
	if len(targets) > 100 {
		riskFactors = append(riskFactors, "Large scan scope")
	}
	for _, method := range config.ScanMethods {
		if method == "arp" {
			riskFactors = append(riskFactors, "ARP scanning may be logged")
			break
		}
	}
	if config.DelayMax < 0.1 {
		riskFactors = append(riskFactors, "Low delay may trigger rate limiting")
	}
	if config.Threads > 50 {
		riskFactors = append(riskFactors, "High thread count increases detection risk")
	}

	riskLevel := "LOW"
	if len(riskFactors) >= 2 {
		riskLevel = "MEDIUM"
	}
	if len(riskFactors) >= 3 {
		riskLevel = "HIGH"
	}

	fmt.Printf("  Risk Level: %s\n", riskLevel)
	if len(riskFactors) > 0 {
		fmt.Println("  Risk Factors:")
		for _, factor := range riskFactors {
			fmt.Printf("    - %s\n", factor)
		}
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Network IDS/IPS may detect port scanning patterns")
	fmt.Println("  - Firewall logs will record connection attempts")
	fmt.Println("  - Host-based security tools may alert on connection probes")
	fmt.Println()

	fmt.Println("OPSEC CONSIDERATIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Results stored in-memory only (no disk artifacts)")
	fmt.Println("  - Configurable jitter between requests")
	fmt.Println("  - Uses standard Go net package (no raw packets without privilege)")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func main() {
	// Initialize random seed for jitter
	rand.Seed(time.Now().UnixNano())

	config := NewScanConfig()

	// Define flags
	timeout := flag.Float64("t", DefaultTimeout, "Connection timeout in seconds")
	timeout2 := flag.Float64("timeout", DefaultTimeout, "Connection timeout in seconds")
	threads := flag.Int("T", DefaultThreads, "Number of concurrent threads")
	threads2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	methods := flag.String("m", "tcp", "Scanning methods to use (comma-separated: tcp,arp,dns)")
	methods2 := flag.String("methods", "tcp", "Scanning methods to use (comma-separated: tcp,arp,dns)")
	ports := flag.String("P", "80,443,22", "TCP ports for connect scanning (comma-separated)")
	ports2 := flag.String("ports", "80,443,22", "TCP ports for connect scanning (comma-separated)")
	delayMin := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between scans (seconds)")
	delayMax := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between scans (seconds)")
	resolve := flag.Bool("r", false, "Resolve hostnames for discovered hosts")
	resolve2 := flag.Bool("resolve", false, "Resolve hostnames for discovered hosts")
	plan := flag.Bool("p", false, "Show execution plan without performing scan")
	plan2 := flag.Bool("plan", false, "Show execution plan without performing scan")
	verbose := flag.Bool("v", false, "Enable verbose output")
	verbose2 := flag.Bool("verbose", false, "Enable verbose output")
	output := flag.String("o", "", "Output file for results (JSON format)")
	output2 := flag.String("output", "", "Output file for results (JSON format)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Network Scanner - Stealthy Host Discovery Tool

Usage:
  %s [flags] targets...

Targets can be:
  - Single IPs:    192.168.1.1
  - CIDR notation: 192.168.1.0/24
  - Ranges:        192.168.1.1-254

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  scanner 192.168.1.0/24 --plan
  scanner 192.168.1.1-254 -m tcp,dns
  scanner 10.0.0.1 10.0.0.2 10.0.0.3 -r -v

WARNING: Use only for authorized security testing.`)
	}

	flag.Parse()

	// Get targets from remaining arguments
	targets := flag.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No targets specified")
		flag.Usage()
		os.Exit(1)
	}

	// Build configuration (handle both short and long flag forms)
	config.Targets = targets

	if *timeout != DefaultTimeout {
		config.Timeout = *timeout
	} else {
		config.Timeout = *timeout2
	}

	if *threads != DefaultThreads {
		config.Threads = *threads
	} else {
		config.Threads = *threads2
	}

	methodStr := *methods
	if *methods2 != "tcp" {
		methodStr = *methods2
	}
	config.ScanMethods = strings.Split(methodStr, ",")

	portStr := *ports
	if *ports2 != "80,443,22" {
		portStr = *ports2
	}
	var tcpPorts []int
	for _, p := range strings.Split(portStr, ",") {
		if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			tcpPorts = append(tcpPorts, port)
		}
	}
	config.TCPPorts = tcpPorts

	config.DelayMin = *delayMin
	config.DelayMax = *delayMax
	config.ResolveHostnames = *resolve || *resolve2
	config.PlanMode = *plan || *plan2
	config.Verbose = *verbose || *verbose2

	if *output != "" {
		config.OutputFile = *output
	} else {
		config.OutputFile = *output2
	}

	// Planning mode
	if config.PlanMode {
		PrintPlan(config)
		os.Exit(0)
	}

	// Execute scan
	fmt.Println("[*] Network Scanner starting...")
	fmt.Printf("[*] Targets: %s\n", strings.Join(config.Targets, ", "))

	scanner := NewNetworkScanner(config)
	results := scanner.Scan()
	liveHosts := scanner.GetLiveHosts()

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total hosts scanned: %d\n", len(results))
	fmt.Printf("Live hosts found:    %d\n", len(liveHosts))
	fmt.Println()

	if len(liveHosts) > 0 {
		fmt.Println("LIVE HOSTS:")
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

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := map[string]interface{}{
			"scan_time": time.Now().Format(time.RFC3339),
			"config": map[string]interface{}{
				"targets": config.Targets,
				"methods": config.ScanMethods,
				"ports":   config.TCPPorts,
			},
			"results": func() []map[string]interface{} {
				var r []map[string]interface{}
				for _, result := range results {
					r = append(r, result.ToDict())
				}
				return r
			}(),
		}

		jsonData, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(config.OutputFile, jsonData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error writing output file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n[*] Results saved to %s\n", config.OutputFile)
	}
}
