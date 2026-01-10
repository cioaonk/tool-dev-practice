// fingerprinter.go - Go port of service-fingerprinter/tool.py
// Advanced Service Detection and Version Identification Tool
//
// Build instructions:
//   go build -o fingerprinter fingerprinter.go
//
// Usage:
//   ./fingerprinter <target> --ports <ports> [flags]
//   ./fingerprinter 192.168.1.1 --ports 22,80,443 --plan
//   ./fingerprinter target.com --ports 22,80,443,3306 --aggressive
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized service probing may violate laws and regulations.

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
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
	DefaultTimeout  = 5.0
	DefaultThreads  = 10
	DefaultDelayMin = 0.1
	DefaultDelayMax = 0.5
)

// =============================================================================
// Data Structures
// =============================================================================

// ServiceInfo contains information about a detected service
type ServiceInfo struct {
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"`
	ServiceName string                 `json:"service_name"`
	Version     string                 `json:"version,omitempty"`
	Product     string                 `json:"product,omitempty"`
	ExtraInfo   string                 `json:"extra_info,omitempty"`
	Banner      string                 `json:"banner,omitempty"`
	SSLEnabled  bool                   `json:"ssl_enabled"`
	SSLInfo     map[string]interface{} `json:"ssl_info,omitempty"`
	Confidence  int                    `json:"confidence"`
	Timestamp   string                 `json:"timestamp"`
}

// ToDict returns a map representation for JSON serialization
func (s *ServiceInfo) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"port":         s.Port,
		"protocol":     s.Protocol,
		"service_name": s.ServiceName,
		"ssl_enabled":  s.SSLEnabled,
		"confidence":   s.Confidence,
		"timestamp":    s.Timestamp,
	}
	if s.Version != "" {
		result["version"] = s.Version
	}
	if s.Product != "" {
		result["product"] = s.Product
	}
	if s.ExtraInfo != "" {
		result["extra_info"] = s.ExtraInfo
	}
	if s.Banner != "" {
		result["banner"] = s.Banner
	}
	if s.SSLInfo != nil {
		result["ssl_info"] = s.SSLInfo
	}
	return result
}

// FingerprintConfig holds configuration for service fingerprinting
type FingerprintConfig struct {
	Target           string
	Ports            []int
	Timeout          float64
	Threads          int
	DelayMin         float64
	DelayMax         float64
	Aggressive       bool
	SSLCheck         bool
	VersionIntensity int
	Verbose          bool
	PlanMode         bool
	OutputFile       string
}

// ProbeResult holds the result of a service probe
type ProbeResult struct {
	Matched     bool
	ServiceName string
	Version     string
	Product     string
	Banner      string
	Confidence  int
	ExtraInfo   string
}

// =============================================================================
// Service Probes
// =============================================================================

// ServiceProbe defines the interface for service probes
type ServiceProbe interface {
	Name() string
	Ports() []int
	Protocol() string
	Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult
}

// HTTPProbe detects HTTP/HTTPS services
type HTTPProbe struct{}

func (h *HTTPProbe) Name() string {
	return "HTTP"
}

func (h *HTTPProbe) Ports() []int {
	return []int{80, 8080, 8000, 8008, 8443, 443}
}

func (h *HTTPProbe) Protocol() string {
	return "tcp"
}

func (h *HTTPProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	// Send HTTP HEAD request
	request := "HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	_, err := conn.Write([]byte(request))
	if err != nil {
		return &ProbeResult{Matched: false}
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return &ProbeResult{Matched: false}
	}

	response := string(buffer[:n])

	// Check if HTTP response
	if !strings.HasPrefix(response, "HTTP/") {
		return &ProbeResult{Matched: false}
	}

	result := &ProbeResult{
		Matched:     true,
		ServiceName: "http",
		Banner:      response,
		Confidence:  90,
	}
	if len(result.Banner) > 500 {
		result.Banner = result.Banner[:500]
	}

	// Extract server header
	serverRegex := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`)
	if match := serverRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Product = match[1]
		result.Confidence = 95

		// Try to extract version
		versionPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)([Aa]pache|[Nn]ginx|IIS|[Ll]ighttpd)/(\d+[\d.]*)`),
			regexp.MustCompile(`([A-Za-z]+)/(\d+[\d.]*)`),
		}
		for _, pattern := range versionPatterns {
			if verMatch := pattern.FindStringSubmatch(match[1]); len(verMatch) > 2 {
				result.Product = verMatch[1]
				result.Version = verMatch[2]
				break
			}
		}
	}

	return result
}

// SSHProbe detects SSH services
type SSHProbe struct{}

func (s *SSHProbe) Name() string {
	return "SSH"
}

func (s *SSHProbe) Ports() []int {
	return []int{22, 2222, 22222}
}

func (s *SSHProbe) Protocol() string {
	return "tcp"
}

func (s *SSHProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	// SSH servers send banner immediately
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return &ProbeResult{Matched: false}
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	if !strings.HasPrefix(banner, "SSH-") {
		return &ProbeResult{Matched: false}
	}

	result := &ProbeResult{
		Matched:     true,
		ServiceName: "ssh",
		Banner:      banner,
		Confidence:  95,
	}

	// Parse SSH banner format: SSH-protoversion-softwareversion
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) >= 3 {
		software := strings.Split(parts[2], " ")[0]

		if strings.Contains(software, "OpenSSH") {
			result.Product = "OpenSSH"
			verRegex := regexp.MustCompile(`OpenSSH[_\s]*([\d.p]+)`)
			if match := verRegex.FindStringSubmatch(software); len(match) > 1 {
				result.Version = match[1]
			}
		} else if strings.Contains(strings.ToLower(software), "dropbear") {
			result.Product = "Dropbear"
			verRegex := regexp.MustCompile(`(?i)dropbear[_\s]*([\d.]+)`)
			if match := verRegex.FindStringSubmatch(software); len(match) > 1 {
				result.Version = match[1]
			}
		} else {
			if strings.Contains(software, "_") {
				result.Product = strings.Split(software, "_")[0]
			} else {
				result.Product = software
			}
		}
	}

	return result
}

// FTPProbe detects FTP services
type FTPProbe struct{}

func (f *FTPProbe) Name() string {
	return "FTP"
}

func (f *FTPProbe) Ports() []int {
	return []int{21, 2121}
}

func (f *FTPProbe) Protocol() string {
	return "tcp"
}

func (f *FTPProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return &ProbeResult{Matched: false}
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	// FTP banner starts with 220
	if !strings.HasPrefix(banner, "220") {
		return &ProbeResult{Matched: false}
	}

	result := &ProbeResult{
		Matched:     true,
		ServiceName: "ftp",
		Banner:      banner,
		Confidence:  90,
	}

	bannerLower := strings.ToLower(banner)
	if strings.Contains(bannerLower, "vsftpd") {
		result.Product = "vsftpd"
		verRegex := regexp.MustCompile(`(?i)vsftpd\s*([\d.]+)`)
		if match := verRegex.FindStringSubmatch(banner); len(match) > 1 {
			result.Version = match[1]
		}
	} else if strings.Contains(banner, "ProFTPD") {
		result.Product = "ProFTPD"
		verRegex := regexp.MustCompile(`ProFTPD\s*([\d.]+)`)
		if match := verRegex.FindStringSubmatch(banner); len(match) > 1 {
			result.Version = match[1]
		}
	} else if strings.Contains(banner, "FileZilla") {
		result.Product = "FileZilla Server"
		verRegex := regexp.MustCompile(`FileZilla Server\s*([\d.]+)`)
		if match := verRegex.FindStringSubmatch(banner); len(match) > 1 {
			result.Version = match[1]
		}
	}

	return result
}

// SMTPProbe detects SMTP services
type SMTPProbe struct{}

func (s *SMTPProbe) Name() string {
	return "SMTP"
}

func (s *SMTPProbe) Ports() []int {
	return []int{25, 465, 587, 2525}
}

func (s *SMTPProbe) Protocol() string {
	return "tcp"
}

func (s *SMTPProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return &ProbeResult{Matched: false}
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	// SMTP banner starts with 220
	if !strings.HasPrefix(banner, "220") {
		return &ProbeResult{Matched: false}
	}

	result := &ProbeResult{
		Matched:     true,
		ServiceName: "smtp",
		Banner:      banner,
		Confidence:  90,
	}

	if strings.Contains(banner, "Postfix") {
		result.Product = "Postfix"
	} else if strings.Contains(banner, "Sendmail") {
		result.Product = "Sendmail"
		verRegex := regexp.MustCompile(`Sendmail\s*([\d./]+)`)
		if match := verRegex.FindStringSubmatch(banner); len(match) > 1 {
			result.Version = match[1]
		}
	} else if strings.Contains(banner, "Microsoft") || strings.Contains(banner, "Exchange") {
		result.Product = "Microsoft Exchange"
	} else if strings.Contains(banner, "Exim") {
		result.Product = "Exim"
		verRegex := regexp.MustCompile(`Exim\s*([\d.]+)`)
		if match := verRegex.FindStringSubmatch(banner); len(match) > 1 {
			result.Version = match[1]
		}
	}

	return result
}

// MySQLProbe detects MySQL services
type MySQLProbe struct{}

func (m *MySQLProbe) Name() string {
	return "MySQL"
}

func (m *MySQLProbe) Ports() []int {
	return []int{3306}
}

func (m *MySQLProbe) Protocol() string {
	return "tcp"
}

func (m *MySQLProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n < 5 {
		return &ProbeResult{Matched: false}
	}

	// MySQL protocol: byte 5 is protocol version (should be 10 for MySQL 3.21+)
	protocolVersion := buffer[4]
	if protocolVersion != 10 && protocolVersion != 9 {
		return &ProbeResult{Matched: false}
	}

	result := &ProbeResult{
		Matched:     true,
		ServiceName: "mysql",
		Confidence:  90,
	}

	// Extract version string (null-terminated after protocol version)
	versionEnd := 5
	for versionEnd < n && buffer[versionEnd] != 0 {
		versionEnd++
	}
	if versionEnd > 5 {
		version := string(buffer[5:versionEnd])
		result.Banner = fmt.Sprintf("MySQL %s", version)
		result.Product = "MySQL"
		result.Version = version

		// Check for MariaDB
		if strings.Contains(version, "MariaDB") {
			result.Product = "MariaDB"
			verRegex := regexp.MustCompile(`([\d.]+)-MariaDB`)
			if match := verRegex.FindStringSubmatch(version); len(match) > 1 {
				result.Version = match[1]
			}
		}
	}

	return result
}

// RDPProbe detects RDP services
type RDPProbe struct{}

func (r *RDPProbe) Name() string {
	return "RDP"
}

func (r *RDPProbe) Ports() []int {
	return []int{3389}
}

func (r *RDPProbe) Protocol() string {
	return "tcp"
}

func (r *RDPProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	// RDP connection request (X.224 Connection Request)
	rdpNegReq := []byte{
		0x03, 0x00, // TPKT header
		0x00, 0x13, // Length
		0x0e,       // X.224 length
		0xe0,       // X.224 connection request
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // Class
		0x01,       // Cookie length
		0x00,       // Cookie
		0x08,       // RDP NEG REQ length
		0x00, 0x01, // Type: RDP_NEG_REQ
		0x00, 0x00, // Flags
		0x00, 0x00, // Protocol
	}

	conn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	_, err := conn.Write(rdpNegReq)
	if err != nil {
		return &ProbeResult{Matched: false}
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n < 11 {
		return &ProbeResult{Matched: false}
	}

	// Check for X.224 connection confirm
	if buffer[5] == 0xd0 {
		return &ProbeResult{
			Matched:     true,
			ServiceName: "rdp",
			Product:     "Microsoft Remote Desktop",
			Confidence:  85,
			Banner:      "RDP detected",
		}
	}

	return &ProbeResult{Matched: false}
}

// GenericProbe performs generic banner grabbing
type GenericProbe struct{}

func (g *GenericProbe) Name() string {
	return "Generic"
}

func (g *GenericProbe) Ports() []int {
	return []int{}
}

func (g *GenericProbe) Protocol() string {
	return "tcp"
}

func (g *GenericProbe) Probe(conn net.Conn, config *FingerprintConfig) *ProbeResult {
	// First try to receive without sending
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)

	if n == 0 {
		// Try sending some common probes
		probes := [][]byte{
			[]byte("\r\n"),
			[]byte("HELP\r\n"),
			[]byte{0x00},
		}

		for _, probe := range probes {
			conn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			conn.Write(probe)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ = conn.Read(buffer)
			if n > 0 {
				break
			}
		}
	}

	if n == 0 {
		return &ProbeResult{Matched: false}
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if len(banner) > 500 {
		banner = banner[:500]
	}

	return &ProbeResult{
		Matched:     true,
		ServiceName: "unknown",
		Banner:      banner,
		Confidence:  30,
	}
}

// =============================================================================
// SSL/TLS Detection
// =============================================================================

// checkSSL checks if a port is running SSL/TLS
func checkSSL(target string, port int, timeout float64) (bool, map[string]interface{}) {
	address := fmt.Sprintf("%s:%d", target, port)
	timeoutDuration := time.Duration(timeout * float64(time.Second))

	dialer := &net.Dialer{Timeout: timeoutDuration}
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	sslInfo := map[string]interface{}{
		"version": tlsVersionName(state.Version),
		"cipher":  tls.CipherSuiteName(state.CipherSuite),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		sslInfo["subject"] = cert.Subject.CommonName
		sslInfo["issuer"] = cert.Issuer.CommonName
		sslInfo["not_before"] = cert.NotBefore.Format(time.RFC3339)
		sslInfo["not_after"] = cert.NotAfter.Format(time.RFC3339)
	}

	return true, sslInfo
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// =============================================================================
// Service Fingerprinter Core
// =============================================================================

// ServiceFingerprinter is the main fingerprinting engine
type ServiceFingerprinter struct {
	Config       *FingerprintConfig
	Results      []*ServiceInfo
	stopEvent    chan struct{}
	mutex        sync.Mutex
	probes       []ServiceProbe
	genericProbe *GenericProbe
}

// NewServiceFingerprinter creates a new ServiceFingerprinter instance
func NewServiceFingerprinter(config *FingerprintConfig) *ServiceFingerprinter {
	return &ServiceFingerprinter{
		Config:    config,
		Results:   []*ServiceInfo{},
		stopEvent: make(chan struct{}),
		probes: []ServiceProbe{
			&HTTPProbe{},
			&SSHProbe{},
			&FTPProbe{},
			&SMTPProbe{},
			&MySQLProbe{},
			&RDPProbe{},
		},
		genericProbe: &GenericProbe{},
	}
}

// applyJitter applies random delay for stealth
func (sf *ServiceFingerprinter) applyJitter() {
	if sf.Config.DelayMax > 0 {
		delay := sf.Config.DelayMin + rand.Float64()*(sf.Config.DelayMax-sf.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// getProbesForPort returns relevant probes for a port
func (sf *ServiceFingerprinter) getProbesForPort(port int) []ServiceProbe {
	var probes []ServiceProbe

	// Add probes that target this port
	for _, probe := range sf.probes {
		for _, p := range probe.Ports() {
			if p == port {
				probes = append(probes, probe)
				break
			}
		}
	}

	// Add remaining probes if aggressive mode
	if sf.Config.Aggressive {
		for _, probe := range sf.probes {
			found := false
			for _, p := range probes {
				if p.Name() == probe.Name() {
					found = true
					break
				}
			}
			if !found {
				probes = append(probes, probe)
			}
		}
	}

	return probes
}

// fingerprintPort fingerprints a single port
func (sf *ServiceFingerprinter) fingerprintPort(port int) *ServiceInfo {
	select {
	case <-sf.stopEvent:
		return nil
	default:
	}

	sf.applyJitter()

	// First check SSL
	sslEnabled := false
	var sslInfo map[string]interface{}

	if sf.Config.SSLCheck {
		sslEnabled, sslInfo = checkSSL(sf.Config.Target, port, sf.Config.Timeout)
	}

	// Get relevant probes
	probes := sf.getProbesForPort(port)

	var bestResult *ProbeResult

	for _, probe := range probes {
		var conn net.Conn
		var err error

		address := fmt.Sprintf("%s:%d", sf.Config.Target, port)
		timeout := time.Duration(sf.Config.Timeout * float64(time.Second))

		if sslEnabled {
			dialer := &net.Dialer{Timeout: timeout}
			config := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         sf.Config.Target,
			}
			conn, err = tls.DialWithDialer(dialer, "tcp", address, config)
		} else {
			conn, err = net.DialTimeout("tcp", address, timeout)
		}

		if err != nil {
			if sf.Config.Verbose {
				fmt.Printf("[!] Connection failed on port %d: %v\n", port, err)
			}
			continue
		}

		result := probe.Probe(conn, sf.Config)
		conn.Close()

		if result.Matched {
			if bestResult == nil || result.Confidence > bestResult.Confidence {
				bestResult = result
			}

			// High confidence match - stop probing
			if result.Confidence >= 90 {
				break
			}
		}
	}

	// Try generic probe if no match
	if bestResult == nil {
		var conn net.Conn
		var err error

		address := fmt.Sprintf("%s:%d", sf.Config.Target, port)
		timeout := time.Duration(sf.Config.Timeout * float64(time.Second))

		if sslEnabled {
			dialer := &net.Dialer{Timeout: timeout}
			config := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         sf.Config.Target,
			}
			conn, err = tls.DialWithDialer(dialer, "tcp", address, config)
		} else {
			conn, err = net.DialTimeout("tcp", address, timeout)
		}

		if err == nil {
			bestResult = sf.genericProbe.Probe(conn, sf.Config)
			conn.Close()
		}
	}

	if bestResult != nil && bestResult.Matched {
		serviceName := bestResult.ServiceName
		if serviceName == "" {
			serviceName = "unknown"
		}
		if sslEnabled && serviceName == "http" {
			serviceName = "https"
		}

		return &ServiceInfo{
			Port:        port,
			Protocol:    "tcp",
			ServiceName: serviceName,
			Version:     bestResult.Version,
			Product:     bestResult.Product,
			Banner:      bestResult.Banner,
			SSLEnabled:  sslEnabled,
			SSLInfo:     sslInfo,
			Confidence:  bestResult.Confidence,
			ExtraInfo:   bestResult.ExtraInfo,
			Timestamp:   time.Now().Format(time.RFC3339),
		}
	}

	return &ServiceInfo{
		Port:        port,
		Protocol:    "tcp",
		ServiceName: "unknown",
		Confidence:  0,
		Timestamp:   time.Now().Format(time.RFC3339),
	}
}

// Fingerprint executes service fingerprinting
func (sf *ServiceFingerprinter) Fingerprint() []*ServiceInfo {
	if sf.Config.Verbose {
		fmt.Printf("[*] Fingerprinting %d ports on %s\n", len(sf.Config.Ports), sf.Config.Target)
	}

	jobs := make(chan int, len(sf.Config.Ports))
	results := make(chan *ServiceInfo, len(sf.Config.Ports))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < sf.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				result := sf.fingerprintPort(port)
				if result != nil {
					results <- result
				}
			}
		}()
	}

	// Send jobs
	for _, port := range sf.Config.Ports {
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
		sf.mutex.Lock()
		sf.Results = append(sf.Results, result)
		if sf.Config.Verbose && result.Confidence > 0 {
			verStr := ""
			if result.Version != "" {
				verStr = " " + result.Version
			}
			fmt.Printf("[+] %d/tcp - %s%s (%d%%)\n", result.Port, result.ServiceName, verStr, result.Confidence)
		}
		sf.mutex.Unlock()
	}

	return sf.Results
}

// Stop signals the fingerprinter to stop
func (sf *ServiceFingerprinter) Stop() {
	close(sf.stopEvent)
}

// =============================================================================
// Planning Mode
// =============================================================================

func printPlan(config *FingerprintConfig) {
	fmt.Println(`
[PLAN MODE] Tool: service-fingerprinter
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target:          %s\n", config.Target)
	fmt.Printf("  Ports:           %d\n", len(config.Ports))
	if len(config.Ports) > 0 {
		portPreview := config.Ports
		if len(portPreview) > 10 {
			portPreview = portPreview[:10]
		}
		fmt.Printf("  Port List:       %v...\n", portPreview)
	}
	fmt.Println()

	fmt.Println("SCAN CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Threads:           %d\n", config.Threads)
	fmt.Printf("  Timeout:           %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:       %.1fs - %.1fs\n", config.DelayMin, config.DelayMax)
	fmt.Printf("  Aggressive Mode:   %t\n", config.Aggressive)
	fmt.Printf("  SSL Detection:     %t\n", config.SSLCheck)
	fmt.Printf("  Version Intensity: %d/9\n", config.VersionIntensity)
	fmt.Println()

	fmt.Println("PROBES TO BE USED")
	fmt.Println(strings.Repeat("-", 40))
	probes := []struct {
		name  string
		ports []int
	}{
		{"HTTP", []int{80, 8080, 8000, 8008, 8443, 443}},
		{"SSH", []int{22, 2222, 22222}},
		{"FTP", []int{21, 2121}},
		{"SMTP", []int{25, 465, 587, 2525}},
		{"MySQL", []int{3306}},
		{"RDP", []int{3389}},
	}
	for _, probe := range probes {
		fmt.Printf("  - %s: targets ports %v\n", probe.name, probe.ports)
	}
	fmt.Println("  - Generic: fallback banner grabbing")
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. For each target port:")
	if config.SSLCheck {
		fmt.Println("     a. Check for SSL/TLS and gather certificate info")
	}
	fmt.Println("     b. Select relevant probes based on port number")
	fmt.Println("     c. Execute probes in order of specificity")
	fmt.Println("     d. Extract service name, version, and banner")
	fmt.Println("     e. Fall back to generic probe if no match")
	fmt.Println("  2. Aggregate results in memory")
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	var riskFactors []string

	if len(config.Ports) > 50 {
		riskFactors = append(riskFactors, "Many ports increase connection footprint")
	}
	if config.Aggressive {
		riskFactors = append(riskFactors, "Aggressive mode sends more probes")
	}
	if config.DelayMax < 0.1 {
		riskFactors = append(riskFactors, "Low delay may trigger rate limiting")
	}

	riskLevel := "LOW"
	if len(riskFactors) >= 2 {
		riskLevel = "MEDIUM"
	}

	fmt.Printf("  Risk Level: %s\n", riskLevel)
	for _, factor := range riskFactors {
		fmt.Printf("    - %s\n", factor)
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Service-specific probes may be logged by applications")
	fmt.Println("  - SSL handshakes leave certificate negotiation traces")
	fmt.Println("  - Banner grabbing attempts may trigger IDS rules")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func parsePorts(portStr string) []int {
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func main() {
	rand.Seed(time.Now().UnixNano())

	portsFlag := flag.String("P", "", "Comma-separated list of ports to fingerprint")
	portsFlag2 := flag.String("ports", "", "Comma-separated list of ports to fingerprint")
	timeoutFlag := flag.Float64("t", DefaultTimeout, "Connection timeout in seconds")
	timeoutFlag2 := flag.Float64("timeout", DefaultTimeout, "Connection timeout in seconds")
	threadsFlag := flag.Int("T", DefaultThreads, "Number of concurrent threads")
	threadsFlag2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	delayMinFlag := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between probes")
	delayMaxFlag := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between probes")
	aggressiveFlag := flag.Bool("a", false, "Try all probes on all ports")
	aggressiveFlag2 := flag.Bool("aggressive", false, "Try all probes on all ports")
	noSSLFlag := flag.Bool("no-ssl", false, "Skip SSL/TLS detection")
	planFlag := flag.Bool("p", false, "Show execution plan without scanning")
	planFlag2 := flag.Bool("plan", false, "Show execution plan without scanning")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseFlag2 := flag.Bool("verbose", false, "Enable verbose output")
	outputFlag := flag.String("o", "", "Output file for results (JSON format)")
	outputFlag2 := flag.String("output", "", "Output file for results (JSON format)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Service Fingerprinter - Advanced Service Detection Tool

Usage:
  %s [flags] target

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  fingerprinter 192.168.1.1 --ports 22,80,443 --plan
  fingerprinter target.com --ports 22,80,443,8080 --aggressive
  fingerprinter 10.0.0.1 --ports 21,22,25,80,443 --verbose

WARNING: Use only for authorized security testing.`)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No target specified")
		flag.Usage()
		os.Exit(1)
	}
	target := args[0]

	portStr := *portsFlag
	if *portsFlag2 != "" {
		portStr = *portsFlag2
	}
	if portStr == "" {
		fmt.Fprintln(os.Stderr, "Error: No ports specified")
		flag.Usage()
		os.Exit(1)
	}
	ports := parsePorts(portStr)
	if len(ports) == 0 {
		fmt.Println("[!] No valid ports specified")
		os.Exit(1)
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

	config := &FingerprintConfig{
		Target:           target,
		Ports:            ports,
		Timeout:          timeout,
		Threads:          threads,
		DelayMin:         *delayMinFlag,
		DelayMax:         *delayMaxFlag,
		Aggressive:       *aggressiveFlag || *aggressiveFlag2,
		SSLCheck:         !*noSSLFlag,
		VersionIntensity: 5,
		Verbose:          *verboseFlag || *verboseFlag2,
		PlanMode:         *planFlag || *planFlag2,
		OutputFile:       output,
	}

	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	fmt.Println("[*] Service Fingerprinter starting...")
	fmt.Printf("[*] Target: %s\n", config.Target)
	fmt.Printf("[*] Ports: %v\n", ports)

	fingerprinter := NewServiceFingerprinter(config)
	results := fingerprinter.Fingerprint()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("FINGERPRINT RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%-8s %-15s %-20s %-15s %-5s\n", "PORT", "SERVICE", "PRODUCT", "VERSION", "SSL")
	fmt.Println(strings.Repeat("-", 70))

	// Sort by port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	for _, result := range results {
		if result.Confidence > 0 {
			sslStr := "No"
			if result.SSLEnabled {
				sslStr = "Yes"
			}
			product := result.Product
			if product == "" {
				product = "-"
			}
			version := result.Version
			if version == "" {
				version = "-"
			}
			fmt.Printf("%-8d %-15s %-20s %-15s %-5s\n",
				result.Port, result.ServiceName, product, version, sslStr)
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := map[string]interface{}{
			"target":    config.Target,
			"timestamp": time.Now().Format(time.RFC3339),
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
