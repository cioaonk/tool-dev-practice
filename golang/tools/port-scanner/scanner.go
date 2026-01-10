// scanner.go - Go port of port-scanner/tool.py
// Advanced TCP/UDP Port Scanning Tool
//
// Build instructions:
//   go build -o scanner scanner.go
//
// Usage:
//   ./scanner <target> [flags]
//   ./scanner 192.168.1.1 --plan
//   ./scanner target.com --ports 1-1024 --threads 100
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized port scanning may violate laws and regulations.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultTimeout  = 1.0
	DefaultThreads  = 50
	DefaultDelayMin = 0.0
	DefaultDelayMax = 0.05
)

// Top 20 common ports
var Top20Ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}

// Top 100 common ports
var Top100Ports = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
	113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
	513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
	1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
	2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
	5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
	5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
	8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
}

// Service port mappings
var ServicePorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}

// =============================================================================
// Enums and Data Structures
// =============================================================================

// PortState represents possible states for a scanned port
type PortState string

const (
	StateOpen         PortState = "open"
	StateClosed       PortState = "closed"
	StateFiltered     PortState = "filtered"
	StateOpenFiltered PortState = "open|filtered"
	StateUnknown      PortState = "unknown"
)

// ScanType represents available scan types
type ScanType string

const (
	ScanTCPConnect ScanType = "connect"
	ScanTCPSYN     ScanType = "syn"
	ScanUDP        ScanType = "udp"
)

// PortResult represents the result of scanning a single port
type PortResult struct {
	Port         int       `json:"port"`
	State        PortState `json:"state"`
	Protocol     string    `json:"protocol"`
	Service      string    `json:"service,omitempty"`
	Banner       string    `json:"banner,omitempty"`
	ResponseTime *float64  `json:"response_time,omitempty"`
	Timestamp    string    `json:"timestamp"`
}

// ToDict returns a map representation for JSON serialization
func (r *PortResult) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"port":      r.Port,
		"state":     string(r.State),
		"protocol":  r.Protocol,
		"timestamp": r.Timestamp,
	}
	if r.Service != "" {
		result["service"] = r.Service
	}
	if r.Banner != "" {
		result["banner"] = r.Banner
	}
	if r.ResponseTime != nil {
		result["response_time"] = *r.ResponseTime
	}
	return result
}

// ScanConfig holds configuration for port scanning operations
type ScanConfig struct {
	Target         string
	Ports          []int
	ScanType       ScanType
	Timeout        float64
	Threads        int
	DelayMin       float64
	DelayMax       float64
	BannerGrab     bool
	RandomizePorts bool
	Verbose        bool
	PlanMode       bool
	OutputFile     string
}

// ScanReport represents a complete scan report for a target
type ScanReport struct {
	Target     string        `json:"target"`
	ResolvedIP string        `json:"resolved_ip,omitempty"`
	ScanType   string        `json:"scan_type"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    *time.Time    `json:"end_time,omitempty"`
	Results    []*PortResult `json:"results"`
}

// GetOpenPorts returns only open ports
func (r *ScanReport) GetOpenPorts() []*PortResult {
	var open []*PortResult
	for _, result := range r.Results {
		if result.State == StateOpen {
			open = append(open, result)
		}
	}
	return open
}

// GetFilteredPorts returns only filtered ports
func (r *ScanReport) GetFilteredPorts() []*PortResult {
	var filtered []*PortResult
	for _, result := range r.Results {
		if result.State == StateFiltered {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

// =============================================================================
// Port Parsing Utilities
// =============================================================================

// parsePortSpecification parses port specification into list of ports
func parsePortSpecification(spec string) []int {
	ports := make(map[int]bool)

	// Handle keywords
	specLower := strings.ToLower(strings.TrimSpace(spec))
	if specLower == "top20" {
		return append([]int{}, Top20Ports...)
	} else if specLower == "top100" {
		return append([]int{}, Top100Ports...)
	} else if specLower == "all" {
		result := make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			result[i-1] = i
		}
		return result
	}

	// Parse comma-separated parts
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range specification
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil {
					for p := start; p <= end && p <= 65535; p++ {
						if p >= 1 {
							ports[p] = true
						}
					}
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err == nil && port >= 1 && port <= 65535 {
				ports[port] = true
			}
		}
	}

	// Convert to sorted slice
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

// getServiceName returns common service name for a port
func getServiceName(port int) string {
	if service, ok := ServicePorts[port]; ok {
		return service
	}
	return ""
}

// =============================================================================
// Scan Techniques
// =============================================================================

// ScanTechnique defines the interface for port scanning techniques
type ScanTechnique interface {
	ScanPort(target string, port int, config *ScanConfig) *PortResult
	Name() string
	RequiresRoot() bool
}

// TCPConnectScan implements full TCP handshake scanning
type TCPConnectScan struct{}

func (t *TCPConnectScan) Name() string {
	return "TCP Connect"
}

func (t *TCPConnectScan) RequiresRoot() bool {
	return false
}

func (t *TCPConnectScan) ScanPort(target string, port int, config *ScanConfig) *PortResult {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(config.Timeout * float64(time.Second))

	conn, err := net.DialTimeout("tcp", address, timeout)
	responseTime := time.Since(startTime).Seconds()

	if err == nil {
		// Port is open
		var banner string
		if config.BannerGrab {
			banner = t.grabBanner(conn, port)
		}
		conn.Close()

		return &PortResult{
			Port:         port,
			State:        StateOpen,
			Protocol:     "tcp",
			Service:      getServiceName(port),
			Banner:       banner,
			ResponseTime: &responseTime,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	}

	// Determine if closed or filtered based on error
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return &PortResult{
			Port:      port,
			State:     StateFiltered,
			Protocol:  "tcp",
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}

	// Connection refused = closed
	if strings.Contains(err.Error(), "refused") {
		return &PortResult{
			Port:      port,
			State:     StateClosed,
			Protocol:  "tcp",
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}

	return &PortResult{
		Port:      port,
		State:     StateFiltered,
		Protocol:  "tcp",
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func (t *TCPConnectScan) grabBanner(conn net.Conn, port int) string {
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send probe for HTTP
	probes := map[int][]byte{
		80:   []byte("HEAD / HTTP/1.0\r\n\r\n"),
		8080: []byte("HEAD / HTTP/1.0\r\n\r\n"),
		443:  nil, // HTTPS needs TLS
		22:   nil, // SSH sends banner first
		21:   nil, // FTP sends banner first
		25:   nil, // SMTP sends banner first
	}

	if probe, ok := probes[port]; ok && probe != nil {
		conn.Write(probe)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if len(banner) > 200 {
		banner = banner[:200]
	}
	return banner
}

// TCPSYNScan implements half-open SYN scanning (placeholder - requires raw sockets)
type TCPSYNScan struct{}

func (t *TCPSYNScan) Name() string {
	return "TCP SYN"
}

func (t *TCPSYNScan) RequiresRoot() bool {
	return true
}

func (t *TCPSYNScan) ScanPort(target string, port int, config *ScanConfig) *PortResult {
	// Note: Full SYN scan requires raw sockets and elevated privileges
	// Falling back to TCP Connect scan
	connectScan := &TCPConnectScan{}
	result := connectScan.ScanPort(target, port, config)
	if result.Service != "" {
		result.Service = result.Service + " (fallback)"
	}
	return result
}

// UDPScan implements UDP port scanning
type UDPScan struct{}

func (u *UDPScan) Name() string {
	return "UDP"
}

func (u *UDPScan) RequiresRoot() bool {
	return false
}

func (u *UDPScan) ScanPort(target string, port int, config *ScanConfig) *PortResult {
	address := fmt.Sprintf("%s:%d", target, port)
	timeout := time.Duration(config.Timeout * float64(time.Second))

	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return &PortResult{
			Port:      port,
			State:     StateFiltered,
			Protocol:  "udp",
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	// Send empty UDP packet
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		return &PortResult{
			Port:      port,
			State:     StateFiltered,
			Protocol:  "udp",
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}

	// Try to receive response
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// No response could mean open or filtered
		return &PortResult{
			Port:      port,
			State:     StateOpenFiltered,
			Protocol:  "udp",
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}

	// Got a response - port is open
	banner := ""
	if n > 0 {
		banner = string(buffer[:n])
		if len(banner) > 100 {
			banner = banner[:100]
		}
	}

	return &PortResult{
		Port:      port,
		State:     StateOpen,
		Protocol:  "udp",
		Service:   getServiceName(port),
		Banner:    banner,
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// =============================================================================
// Port Scanner Core
// =============================================================================

// PortScanner is the main port scanning engine
type PortScanner struct {
	Config    *ScanConfig
	Report    *ScanReport
	stopEvent chan struct{}
	mutex     sync.Mutex
	technique ScanTechnique
}

// NewPortScanner creates a new PortScanner instance
func NewPortScanner(config *ScanConfig) *PortScanner {
	var technique ScanTechnique
	switch config.ScanType {
	case ScanTCPSYN:
		technique = &TCPSYNScan{}
	case ScanUDP:
		technique = &UDPScan{}
	default:
		technique = &TCPConnectScan{}
	}

	return &PortScanner{
		Config:    config,
		stopEvent: make(chan struct{}),
		technique: technique,
	}
}

// resolveTarget resolves hostname to IP address
func (ps *PortScanner) resolveTarget() string {
	ips, err := net.LookupIP(ps.Config.Target)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

// applyJitter applies random delay between port scans
func (ps *PortScanner) applyJitter() {
	if ps.Config.DelayMax > 0 {
		delay := ps.Config.DelayMin + rand.Float64()*(ps.Config.DelayMax-ps.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// scanSinglePort scans a single port
func (ps *PortScanner) scanSinglePort(port int, targetIP string) *PortResult {
	select {
	case <-ps.stopEvent:
		return nil
	default:
	}

	ps.applyJitter()
	return ps.technique.ScanPort(targetIP, port, ps.Config)
}

// Scan executes the port scan
func (ps *PortScanner) Scan() *ScanReport {
	// Initialize report
	resolvedIP := ps.resolveTarget()
	ps.Report = &ScanReport{
		Target:     ps.Config.Target,
		ResolvedIP: resolvedIP,
		ScanType:   string(ps.Config.ScanType),
		StartTime:  time.Now(),
		Results:    []*PortResult{},
	}

	if resolvedIP == "" {
		if ps.Config.Verbose {
			fmt.Printf("[!] Could not resolve target: %s\n", ps.Config.Target)
		}
		now := time.Now()
		ps.Report.EndTime = &now
		return ps.Report
	}

	// Prepare ports
	ports := append([]int{}, ps.Config.Ports...)
	if ps.Config.RandomizePorts {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	if ps.Config.Verbose {
		fmt.Printf("[*] Scanning %d ports on %s (%s)\n", len(ports), ps.Config.Target, resolvedIP)
		fmt.Printf("[*] Scan type: %s\n", ps.technique.Name())
	}

	// Create work channel and results channel
	jobs := make(chan int, len(ports))
	results := make(chan *PortResult, len(ports))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < ps.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				result := ps.scanSinglePort(port, resolvedIP)
				if result != nil {
					results <- result
				}
			}
		}()
	}

	// Send jobs
	for _, port := range ports {
		jobs <- port
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		ps.mutex.Lock()
		ps.Report.Results = append(ps.Report.Results, result)
		if result.State == StateOpen && ps.Config.Verbose {
			service := result.Service
			if service == "" {
				service = "unknown"
			}
			fmt.Printf("[+] %d/tcp open - %s\n", result.Port, service)
		}
		ps.mutex.Unlock()
	}

	now := time.Now()
	ps.Report.EndTime = &now
	return ps.Report
}

// Stop signals the scanner to stop
func (ps *PortScanner) Stop() {
	close(ps.stopEvent)
}

// =============================================================================
// Planning Mode
// =============================================================================

// printPlan displays execution plan without performing any actions
func printPlan(config *ScanConfig) {
	// Resolve target for display
	resolvedIP := ""
	ips, err := net.LookupIP(config.Target)
	if err == nil && len(ips) > 0 {
		resolvedIP = ips[0].String()
	} else {
		resolvedIP = "Unable to resolve"
	}

	var technique ScanTechnique
	switch config.ScanType {
	case ScanTCPSYN:
		technique = &TCPSYNScan{}
	case ScanUDP:
		technique = &UDPScan{}
	default:
		technique = &TCPConnectScan{}
	}

	fmt.Println(`
[PLAN MODE] Tool: port-scanner
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target:          %s\n", config.Target)
	fmt.Printf("  Resolved IP:     %s\n", resolvedIP)
	fmt.Printf("  Ports to scan:   %d\n", len(config.Ports))
	if len(config.Ports) > 0 {
		minPort := config.Ports[0]
		maxPort := config.Ports[0]
		for _, p := range config.Ports {
			if p < minPort {
				minPort = p
			}
			if p > maxPort {
				maxPort = p
			}
		}
		fmt.Printf("  Port range:      %d - %d\n", minPort, maxPort)
	}
	fmt.Println()

	fmt.Println("SCAN CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Scan Type:       %s\n", technique.Name())
	fmt.Printf("  Requires Root:   %t\n", technique.RequiresRoot())
	fmt.Printf("  Threads:         %d\n", config.Threads)
	fmt.Printf("  Timeout:         %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:     %.2fs - %.2fs\n", config.DelayMin, config.DelayMax)
	fmt.Printf("  Randomize Ports: %t\n", config.RandomizePorts)
	fmt.Printf("  Banner Grab:     %t\n", config.BannerGrab)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Resolve target hostname to IP address")
	fmt.Printf("  2. Initialize %d worker goroutines\n", config.Threads)
	if config.RandomizePorts {
		fmt.Println("  3. Shuffle port order for stealth")
	}
	fmt.Printf("  4. For each of %d ports:\n", len(config.Ports))
	fmt.Printf("     - Apply random delay (%.2fs - %.2fs)\n", config.DelayMin, config.DelayMax)
	fmt.Printf("     - Perform %s scan\n", technique.Name())
	if config.BannerGrab {
		fmt.Println("     - Attempt banner grab on open ports")
	}
	fmt.Println("  5. Aggregate results in memory")
	fmt.Println()

	fmt.Println("PORT PREVIEW (first 20)")
	fmt.Println(strings.Repeat("-", 40))
	previewCount := 20
	if len(config.Ports) < previewCount {
		previewCount = len(config.Ports)
	}
	for i := 0; i < previewCount; i++ {
		port := config.Ports[i]
		service := getServiceName(port)
		if service == "" {
			service = "unknown"
		}
		fmt.Printf("  - %d/tcp (%s)\n", port, service)
	}
	if len(config.Ports) > 20 {
		fmt.Printf("  ... and %d more ports\n", len(config.Ports)-20)
	}
	fmt.Println()

	// Estimate scan time
	estimatedTime := float64(len(config.Ports)) * config.Timeout / float64(config.Threads)
	estimatedTime += float64(len(config.Ports)) * ((config.DelayMin + config.DelayMax) / 2) / float64(config.Threads)

	fmt.Println("TIME ESTIMATE")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Worst case:      %.1f seconds\n", estimatedTime)
	fmt.Printf("  Typical:         %.1f seconds\n", estimatedTime*0.3)
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))

	var riskFactors []string
	riskLevel := "LOW"

	if len(config.Ports) > 1000 {
		riskFactors = append(riskFactors, "Large number of ports increases detection risk")
	}
	if config.Threads > 100 {
		riskFactors = append(riskFactors, "High thread count may trigger rate limiting")
	}
	if config.DelayMax < 0.01 {
		riskFactors = append(riskFactors, "Low delay increases scan speed visibility")
	}
	if config.ScanType == ScanTCPConnect {
		riskFactors = append(riskFactors, "Connect scans complete full handshake (logged)")
	}

	if len(riskFactors) >= 2 {
		riskLevel = "MEDIUM"
	}
	if len(riskFactors) >= 3 {
		riskLevel = "HIGH"
	}

	fmt.Printf("  Risk Level: %s\n", riskLevel)
	if len(riskFactors) > 0 {
		for _, factor := range riskFactors {
			fmt.Printf("    - %s\n", factor)
		}
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Firewall logs will record connection attempts")
	fmt.Println("  - IDS/IPS may detect port scan patterns")
	fmt.Println("  - Rate limiting may slow or block the scan")
	if config.ScanType == ScanTCPConnect {
		fmt.Println("  - Application logs may record failed connections")
	}
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func main() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())

	// Define flags
	portsFlag := flag.String("P", "top20", "Port specification (e.g., 80, 1-1024, 22,80,443, top20, top100, all)")
	portsFlag2 := flag.String("ports", "top20", "Port specification")
	scanTypeFlag := flag.String("s", "connect", "Type of scan (connect, syn, udp)")
	scanTypeFlag2 := flag.String("scan-type", "connect", "Type of scan (connect, syn, udp)")
	timeoutFlag := flag.Float64("t", DefaultTimeout, "Connection timeout in seconds")
	timeoutFlag2 := flag.Float64("timeout", DefaultTimeout, "Connection timeout in seconds")
	threadsFlag := flag.Int("T", DefaultThreads, "Number of concurrent threads")
	threadsFlag2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	delayMinFlag := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between scans")
	delayMaxFlag := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between scans")
	bannerFlag := flag.Bool("b", false, "Attempt to grab service banners")
	bannerFlag2 := flag.Bool("banner", false, "Attempt to grab service banners")
	noRandomizeFlag := flag.Bool("no-randomize", false, "Disable port order randomization")
	planFlag := flag.Bool("p", false, "Show execution plan without scanning")
	planFlag2 := flag.Bool("plan", false, "Show execution plan without scanning")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseFlag2 := flag.Bool("verbose", false, "Enable verbose output")
	outputFlag := flag.String("o", "", "Output file for results (JSON format)")
	outputFlag2 := flag.String("output", "", "Output file for results (JSON format)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Port Scanner - Advanced TCP/UDP Port Scanning Tool

Usage:
  %s [flags] target

Port Specifications:
  Single port:    80
  Range:          1-1024
  List:           22,80,443
  Combined:       22,80,443,8000-8100
  Keywords:       top20, top100, all

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  scanner 192.168.1.1 --plan
  scanner target.com --ports 1-1024 --threads 100
  scanner 10.0.0.1 --ports top100 --banner --verbose

WARNING: Use only for authorized security testing.`)
	}

	flag.Parse()

	// Get target from remaining arguments
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		flag.Usage()
		os.Exit(1)
	}
	target := args[0]

	// Build configuration
	portSpec := *portsFlag
	if *portsFlag2 != "top20" {
		portSpec = *portsFlag2
	}
	ports := parsePortSpecification(portSpec)
	if len(ports) == 0 {
		fmt.Println("[!] No valid ports specified")
		os.Exit(1)
	}

	scanTypeStr := *scanTypeFlag
	if *scanTypeFlag2 != "connect" {
		scanTypeStr = *scanTypeFlag2
	}
	var scanType ScanType
	switch scanTypeStr {
	case "syn":
		scanType = ScanTCPSYN
	case "udp":
		scanType = ScanUDP
	default:
		scanType = ScanTCPConnect
	}

	timeout := *timeoutFlag
	if *timeoutFlag2 != DefaultTimeout {
		timeout = *timeoutFlag2
	}

	threads := *threadsFlag
	if *threadsFlag2 != DefaultThreads {
		threads = *threadsFlag2
	}

	output := *outputFlag
	if *outputFlag2 != "" {
		output = *outputFlag2
	}

	config := &ScanConfig{
		Target:         target,
		Ports:          ports,
		ScanType:       scanType,
		Timeout:        timeout,
		Threads:        threads,
		DelayMin:       *delayMinFlag,
		DelayMax:       *delayMaxFlag,
		BannerGrab:     *bannerFlag || *bannerFlag2,
		RandomizePorts: !*noRandomizeFlag,
		Verbose:        *verboseFlag || *verboseFlag2,
		PlanMode:       *planFlag || *planFlag2,
		OutputFile:     output,
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute scan
	fmt.Println("[*] Port Scanner starting...")
	fmt.Printf("[*] Target: %s\n", config.Target)
	fmt.Printf("[*] Ports: %d\n", len(config.Ports))

	scanner := NewPortScanner(config)
	report := scanner.Scan()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Target:       %s\n", report.Target)
	fmt.Printf("Resolved IP:  %s\n", report.ResolvedIP)
	fmt.Printf("Scan Type:    %s\n", report.ScanType)
	if report.EndTime != nil {
		duration := report.EndTime.Sub(report.StartTime).Seconds()
		fmt.Printf("Duration:     %.2fs\n", duration)
	}
	fmt.Println()

	openPorts := report.GetOpenPorts()
	filteredPorts := report.GetFilteredPorts()

	fmt.Printf("Open ports:     %d\n", len(openPorts))
	fmt.Printf("Filtered ports: %d\n", len(filteredPorts))
	fmt.Println()

	if len(openPorts) > 0 {
		fmt.Println("OPEN PORTS:")
		fmt.Println(strings.Repeat("-", 60))

		// Sort by port number
		sort.Slice(openPorts, func(i, j int) bool {
			return openPorts[i].Port < openPorts[j].Port
		})

		for _, result := range openPorts {
			service := result.Service
			if service == "" {
				service = "unknown"
			}
			bannerStr := ""
			if result.Banner != "" && len(result.Banner) > 50 {
				bannerStr = fmt.Sprintf(" - %s...", result.Banner[:50])
			} else if result.Banner != "" {
				bannerStr = fmt.Sprintf(" - %s", result.Banner)
			}
			fmt.Printf("  %d/%s open  %s%s\n", result.Port, result.Protocol, service, bannerStr)
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := map[string]interface{}{
			"target":      report.Target,
			"resolved_ip": report.ResolvedIP,
			"scan_type":   report.ScanType,
			"start_time":  report.StartTime.Format(time.RFC3339),
			"end_time":    report.EndTime.Format(time.RFC3339),
			"results": func() []map[string]interface{} {
				var r []map[string]interface{}
				for _, result := range report.Results {
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
