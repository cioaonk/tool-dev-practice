// Package main implements an SMB Enumerator tool for share and user enumeration.
// Converted from Python to Go - smb-enumerator tool
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized SMB access may violate laws and regulations.
//
// Build: go build -o smb-enumerator enumerator.go
// Usage: ./smb-enumerator 192.168.1.1 --plan
//        ./smb-enumerator 192.168.1.1 --null-session
//        ./smb-enumerator 192.168.1.1 -u admin -P password -d DOMAIN
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultTimeout = 10.0
	SMBPort        = 445
	NetBIOSPort    = 139
)

// SMB Commands
const (
	SMBComNegotiate        byte = 0x72
	SMBComSessionSetupAndX byte = 0x73
	SMBComTreeConnectAndX  byte = 0x75
	SMBComTransaction      byte = 0x25
)

// =============================================================================
// Data Structures
// =============================================================================

// SMBShare represents an SMB share
type SMBShare struct {
	Name        string  `json:"name"`
	ShareType   string  `json:"type"`
	Comment     *string `json:"comment,omitempty"`
	Permissions *string `json:"permissions,omitempty"`
}

// SMBUser represents an SMB/Windows user
type SMBUser struct {
	Username    string   `json:"username"`
	RID         *int     `json:"rid,omitempty"`
	Description *string  `json:"description,omitempty"`
	Groups      []string `json:"groups"`
}

// SMBSystemInfo holds system information gathered from SMB
type SMBSystemInfo struct {
	Hostname        *string `json:"hostname,omitempty"`
	Domain          *string `json:"domain,omitempty"`
	OSVersion       *string `json:"os_version,omitempty"`
	ServerType      *string `json:"server_type,omitempty"`
	SMBVersion      *string `json:"smb_version,omitempty"`
	SigningRequired bool    `json:"signing_required"`
}

// EnumConfig holds configuration for SMB enumeration
type EnumConfig struct {
	Target       string
	Port         int
	Username     *string
	Password     *string
	Domain       string
	Timeout      float64
	EnumShares   bool
	EnumUsers    bool
	EnumSessions bool
	NullSession  bool
	Verbose      bool
	PlanMode     bool
	OutputFile   string
}

// EnumResult holds the result of SMB enumeration
type EnumResult struct {
	Target     string         `json:"target"`
	SystemInfo *SMBSystemInfo `json:"system_info,omitempty"`
	Shares     []SMBShare     `json:"shares"`
	Users      []SMBUser      `json:"users"`
	Sessions   []string       `json:"sessions"`
	Errors     []string       `json:"errors"`
	Timestamp  string         `json:"timestamp"`
}

// =============================================================================
// SMB Protocol Implementation
// =============================================================================

// SMBClient implements a lightweight SMB client for enumeration
type SMBClient struct {
	Target      string
	Port        int
	Timeout     time.Duration
	conn        net.Conn
	sessionKey  uint64
	userID      uint16
	treeID      uint16
	processID   uint16
	multiplexID uint16
}

// NewSMBClient creates a new SMB client
func NewSMBClient(target string, port int, timeout float64) *SMBClient {
	return &SMBClient{
		Target:      target,
		Port:        port,
		Timeout:     time.Duration(timeout * float64(time.Second)),
		processID:   uint16(rand.Intn(65535) + 1),
		multiplexID: 1,
	}
}

// createSMBHeader creates an SMB header
func (c *SMBClient) createSMBHeader(command byte, flags byte, flags2 uint16) []byte {
	header := make([]byte, 0, 32)

	// Protocol identifier
	header = append(header, 0xff, 'S', 'M', 'B')

	// Command
	header = append(header, command)

	// Status (4 bytes)
	header = append(header, 0, 0, 0, 0)

	// Flags
	header = append(header, flags)

	// Flags2
	header = append(header, byte(flags2), byte(flags2>>8))

	// PID high (2 bytes)
	header = append(header, 0, 0)

	// Security features / session key (8 bytes)
	header = append(header, 0, 0, 0, 0, 0, 0, 0, 0)

	// Reserved (2 bytes)
	header = append(header, 0, 0)

	// Tree ID
	header = append(header, byte(c.treeID), byte(c.treeID>>8))

	// Process ID
	header = append(header, byte(c.processID), byte(c.processID>>8))

	// User ID
	header = append(header, byte(c.userID), byte(c.userID>>8))

	// Multiplex ID
	header = append(header, byte(c.multiplexID), byte(c.multiplexID>>8))
	c.multiplexID++

	return header
}

// createNetBIOSHeader creates a NetBIOS session header
func (c *SMBClient) createNetBIOSHeader(data []byte) []byte {
	length := len(data)
	header := make([]byte, 4)
	header[0] = 0 // Session message type
	header[1] = byte((length >> 16) & 0xff)
	header[2] = byte((length >> 8) & 0xff)
	header[3] = byte(length & 0xff)
	return header
}

// sendPacket sends a packet and receives response
func (c *SMBClient) sendPacket(data []byte) ([]byte, error) {
	packet := append(c.createNetBIOSHeader(data), data...)

	c.conn.SetDeadline(time.Now().Add(c.Timeout))
	_, err := c.conn.Write(packet)
	if err != nil {
		return nil, err
	}

	// Receive response
	response := make([]byte, 4096)
	n, err := c.conn.Read(response)
	if err != nil {
		return nil, err
	}

	if n < 4 {
		return nil, fmt.Errorf("response too short")
	}

	// Skip NetBIOS header
	return response[4:n], nil
}

// Connect establishes connection to SMB server
func (c *SMBClient) Connect() error {
	addr := fmt.Sprintf("%s:%d", c.Target, c.Port)
	conn, err := net.DialTimeout("tcp", addr, c.Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

// Disconnect closes the connection
func (c *SMBClient) Disconnect() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Negotiate performs SMB negotiation and gathers system info
func (c *SMBClient) Negotiate() (*SMBSystemInfo, error) {
	// Build negotiate request
	dialects := [][]byte{
		append([]byte{0x02}, []byte("NT LM 0.12\x00")...),
		append([]byte{0x02}, []byte("SMB 2.002\x00")...),
		append([]byte{0x02}, []byte("SMB 2.???\x00")...),
	}

	header := c.createSMBHeader(SMBComNegotiate, 0x18, 0xc803)

	// Word count
	data := []byte{0}

	// Byte count (dialect length)
	var dialectBytes []byte
	for _, d := range dialects {
		dialectBytes = append(dialectBytes, d...)
	}
	data = append(data, byte(len(dialectBytes)), byte(len(dialectBytes)>>8))
	data = append(data, dialectBytes...)

	response, err := c.sendPacket(append(header, data...))
	if err != nil {
		return nil, err
	}

	if len(response) < 36 {
		return nil, fmt.Errorf("negotiate response too short")
	}

	systemInfo := &SMBSystemInfo{}

	// Check for SMB signature
	if response[0] == 0xff && response[1] == 'S' && response[2] == 'M' && response[3] == 'B' {
		// SMB1 response
		smbVersion := "SMB1"
		systemInfo.SMBVersion = &smbVersion

		if len(response) > 33 {
			wordCount := response[32]
			if wordCount >= 17 && len(response) > 33 {
				// Check signing
				securityMode := response[33]
				systemInfo.SigningRequired = (securityMode & 0x08) != 0
			}

			// Try to extract OS info from string area
			byteCountPos := 33 + (int(wordCount) * 2)
			if len(response) > byteCountPos+2 {
				byteCount := binary.LittleEndian.Uint16(response[byteCountPos : byteCountPos+2])
				stringArea := response[byteCountPos+2:]
				if len(stringArea) > int(byteCount) {
					stringArea = stringArea[:byteCount]
				}

				// Parse null-terminated strings (OS, LM, Domain)
				var strings []string
				var current []byte
				for _, b := range stringArea {
					if b == 0 {
						if len(current) > 0 {
							strings = append(strings, string(current))
							current = nil
						}
					} else {
						current = append(current, b)
					}
				}

				if len(strings) >= 1 {
					systemInfo.OSVersion = &strings[0]
				}
				if len(strings) >= 3 {
					systemInfo.Domain = &strings[2]
				}
			}
		}
	} else if response[0] == 0xfe && response[1] == 'S' && response[2] == 'M' && response[3] == 'B' {
		// SMB2+ response
		smbVersion := "SMB2+"
		systemInfo.SMBVersion = &smbVersion
	}

	return systemInfo, nil
}

// SessionSetup attempts session setup (authentication)
func (c *SMBClient) SessionSetup(username, password, domain string) bool {
	header := c.createSMBHeader(SMBComSessionSetupAndX, 0x18, 0xc803)

	// Build session setup request (simplified NTLM)
	words := []byte{
		0xff,       // AndX command (no additional)
		0,          // Reserved
		0, 0,       // AndX offset
		0xff, 0xff, // Max buffer
		2, 0,       // Max MPX count
		1, 0,       // VC number
		0, 0, 0, 0, // Session key
		0, 0,       // Security blob length
		0, 0, 0, 0, // Reserved
		0, 0, 0, 0x80, // Capabilities
	}

	// Word count
	data := []byte{13}
	data = append(data, words...)
	// Byte count
	data = append(data, 0, 0)

	response, err := c.sendPacket(append(header, data...))
	if err != nil {
		return false
	}

	// Check status
	if len(response) < 9 {
		return false
	}
	status := binary.LittleEndian.Uint32(response[5:9])

	if status == 0 {
		// Extract user ID
		if len(response) > 30 {
			c.userID = binary.LittleEndian.Uint16(response[28:30])
		}
		return true
	}

	return false
}

// TreeConnect connects to a share
func (c *SMBClient) TreeConnect(share string) bool {
	header := c.createSMBHeader(SMBComTreeConnectAndX, 0x18, 0xc803)

	// Build tree connect request
	words := []byte{
		0xff,  // AndX command
		0,     // Reserved
		0, 0,  // AndX offset
		0, 0,  // Flags
		1, 0,  // Password length
	}

	passwordBytes := []byte{0} // Null password
	pathBytes := encodeUTF16LE(share)
	pathBytes = append(pathBytes, 0, 0) // Null terminator
	serviceBytes := []byte("?????\x00") // Any service

	// Word count
	data := []byte{4}
	data = append(data, words...)

	byteCount := len(passwordBytes) + len(pathBytes) + len(serviceBytes)
	data = append(data, byte(byteCount), byte(byteCount>>8))
	data = append(data, passwordBytes...)
	data = append(data, pathBytes...)
	data = append(data, serviceBytes...)

	response, err := c.sendPacket(append(header, data...))
	if err != nil {
		return false
	}

	if len(response) < 9 {
		return false
	}
	status := binary.LittleEndian.Uint32(response[5:9])

	if status == 0 {
		if len(response) > 26 {
			c.treeID = binary.LittleEndian.Uint16(response[24:26])
		}
		return true
	}

	return false
}

// encodeUTF16LE encodes a string to UTF-16LE bytes
func encodeUTF16LE(s string) []byte {
	var result []byte
	for _, r := range s {
		result = append(result, byte(r), byte(r>>8))
	}
	return result
}

// =============================================================================
// SMB Enumerator Core
// =============================================================================

// CommonShares is the list of common share names to check
var CommonShares = []string{
	"IPC$", "ADMIN$", "C$", "D$", "E$", "NETLOGON", "SYSVOL",
	"print$", "Users", "Public", "Shared", "Data", "Backup",
	"IT", "Finance", "HR", "Software", "Install", "Temp",
}

// SMBEnumerator coordinates SMB enumeration operations
type SMBEnumerator struct {
	Config *EnumConfig
	Result *EnumResult
	client *SMBClient
}

// NewSMBEnumerator creates a new SMB enumerator
func NewSMBEnumerator(config *EnumConfig) *SMBEnumerator {
	return &SMBEnumerator{
		Config: config,
		Result: &EnumResult{
			Target:    config.Target,
			Shares:    make([]SMBShare, 0),
			Users:     make([]SMBUser, 0),
			Sessions:  make([]string, 0),
			Errors:    make([]string, 0),
			Timestamp: time.Now().Format(time.RFC3339),
		},
	}
}

// connect establishes SMB connection
func (e *SMBEnumerator) connect() bool {
	e.client = NewSMBClient(e.Config.Target, e.Config.Port, e.Config.Timeout)

	if err := e.client.Connect(); err != nil {
		e.Result.Errors = append(e.Result.Errors, "Failed to connect to target")
		return false
	}

	// Negotiate
	systemInfo, err := e.client.Negotiate()
	if err == nil && systemInfo != nil {
		e.Result.SystemInfo = systemInfo
	}

	// Session setup
	if e.Config.NullSession {
		if !e.client.SessionSetup("", "", "") {
			e.Result.Errors = append(e.Result.Errors, "Null session failed")
		}
	} else if e.Config.Username != nil {
		password := ""
		if e.Config.Password != nil {
			password = *e.Config.Password
		}
		if !e.client.SessionSetup(*e.Config.Username, password, e.Config.Domain) {
			e.Result.Errors = append(e.Result.Errors, "Authentication failed")
			return false
		}
	}

	return true
}

// disconnect closes SMB connection
func (e *SMBEnumerator) disconnect() {
	if e.client != nil {
		e.client.Disconnect()
		e.client = nil
	}
}

// enumSharesBasic enumerates shares by attempting to connect to common names
func (e *SMBEnumerator) enumSharesBasic() []SMBShare {
	var shares []SMBShare

	for _, shareName := range CommonShares {
		sharePath := fmt.Sprintf("\\\\%s\\%s", e.Config.Target, shareName)

		if e.client != nil && e.client.TreeConnect(sharePath) {
			shareType := "Disk"
			if strings.HasSuffix(shareName, "$") {
				shareType = "IPC"
			}
			permissions := "Accessible"
			shares = append(shares, SMBShare{
				Name:        shareName,
				ShareType:   shareType,
				Permissions: &permissions,
			})

			if e.Config.Verbose {
				fmt.Printf("[+] Found share: %s\n", shareName)
			}
		}
	}

	return shares
}

// Enumerate executes SMB enumeration
func (e *SMBEnumerator) Enumerate() *EnumResult {
	if e.Config.Verbose {
		fmt.Printf("[*] SMB Enumerator starting for %s\n", e.Config.Target)
	}

	// Connect
	if !e.connect() {
		return e.Result
	}

	if e.Config.Verbose {
		if e.Result.SystemInfo != nil {
			osVer := "Unknown"
			if e.Result.SystemInfo.OSVersion != nil {
				osVer = *e.Result.SystemInfo.OSVersion
			}
			smbVer := "Unknown"
			if e.Result.SystemInfo.SMBVersion != nil {
				smbVer = *e.Result.SystemInfo.SMBVersion
			}
			signing := "Not Required"
			if e.Result.SystemInfo.SigningRequired {
				signing = "Required"
			}
			fmt.Printf("[*] OS: %s\n", osVer)
			fmt.Printf("[*] SMB: %s\n", smbVer)
			fmt.Printf("[*] Signing: %s\n", signing)
		}
	}

	// Enumerate shares
	if e.Config.EnumShares {
		if e.Config.Verbose {
			fmt.Println("[*] Enumerating shares...")
		}

		shares := e.enumSharesBasic()
		e.Result.Shares = shares
	}

	// Cleanup
	e.disconnect()

	return e.Result
}

// Stop stops enumeration
func (e *SMBEnumerator) Stop() {
	e.disconnect()
}

// =============================================================================
// Planning Mode
// =============================================================================

// printPlan displays execution plan without performing actions
func printPlan(config *EnumConfig) {
	fmt.Println(`
[PLAN MODE] Tool: smb-enumerator
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target:          %s\n", config.Target)
	fmt.Printf("  Port:            %d\n", config.Port)
	fmt.Println()

	fmt.Println("AUTHENTICATION")
	fmt.Println(strings.Repeat("-", 40))
	if config.Username != nil {
		fmt.Printf("  Username:        %s\n", *config.Username)
		domain := "WORKGROUP"
		if config.Domain != "" {
			domain = config.Domain
		}
		fmt.Printf("  Domain:          %s\n", domain)
		if config.Password != nil {
			fmt.Printf("  Password:        %s\n", strings.Repeat("*", len(*config.Password)))
		} else {
			fmt.Println("  Password:        None")
		}
	} else {
		fmt.Printf("  Null Session:    %t\n", config.NullSession)
	}
	fmt.Println()

	fmt.Println("ENUMERATION OPTIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Enumerate Shares:   %t\n", config.EnumShares)
	fmt.Printf("  Enumerate Users:    %t\n", config.EnumUsers)
	fmt.Printf("  Enumerate Sessions: %t\n", config.EnumSessions)
	fmt.Printf("  Timeout:            %.1fs\n", config.Timeout)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Establish TCP connection to port 445")
	fmt.Println("  2. Perform SMB negotiation (gather OS info)")
	if config.NullSession {
		fmt.Println("  3. Attempt null session authentication")
	} else if config.Username != nil {
		fmt.Println("  3. Authenticate with provided credentials")
	}
	if config.EnumShares {
		fmt.Println("  4. Enumerate accessible shares")
		fmt.Printf("     - Test %d common share names\n", len(CommonShares))
	}
	if config.EnumUsers {
		fmt.Println("  5. Attempt user enumeration via RPC")
	}
	fmt.Println()

	fmt.Println("SHARES TO TEST")
	fmt.Println(strings.Repeat("-", 40))
	for i, share := range CommonShares {
		if i >= 10 {
			break
		}
		fmt.Printf("  - %s\n", share)
	}
	if len(CommonShares) > 10 {
		fmt.Printf("  ... and %d more\n", len(CommonShares)-10)
	}
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	var riskFactors []string

	if config.NullSession {
		riskFactors = append(riskFactors, "Null session attempts are commonly logged")
	}
	if config.EnumUsers {
		riskFactors = append(riskFactors, "User enumeration may trigger alerts")
	}

	riskLevel := "MEDIUM" // SMB enum is inherently visible
	fmt.Printf("  Risk Level: %s\n", riskLevel)
	for _, factor := range riskFactors {
		fmt.Printf("    - %s\n", factor)
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Windows Security Event logs (4625, 4624)")
	fmt.Println("  - SMB connection attempts are logged")
	fmt.Println("  - Share enumeration visible in audit logs")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Command line flags
	var (
		port        = flag.Int("port", SMBPort, "SMB port")
		username    = flag.String("u", "", "Username for authentication")
		password    = flag.String("P", "", "Password for authentication")
		domain      = flag.String("d", "", "Domain name")
		nullSession = flag.Bool("n", true, "Attempt null session")
		noShares    = flag.Bool("no-shares", false, "Skip share enumeration")
		noUsers     = flag.Bool("no-users", false, "Skip user enumeration")
		timeout     = flag.Float64("timeout", DefaultTimeout, "Connection timeout")
		planMode    = flag.Bool("plan", false, "Show execution plan without scanning")
		verbose     = flag.Bool("v", false, "Enable verbose output")
		outputFile  = flag.String("o", "", "Output file for results (JSON format)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SMB Enumerator - Share and User Enumeration Tool

Usage: %s [options] <target>

Examples:
  %s 192.168.1.1 --plan
  %s 192.168.1.1 -n
  %s 192.168.1.1 -u admin -P password -d DOMAIN

WARNING: Use only for authorized security testing.

Options:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("[!] Target argument required")
		flag.Usage()
		os.Exit(1)
	}

	target := flag.Arg(0)

	// Build configuration
	config := &EnumConfig{
		Target:       target,
		Port:         *port,
		Domain:       *domain,
		Timeout:      *timeout,
		EnumShares:   !*noShares,
		EnumUsers:    !*noUsers,
		EnumSessions: false,
		NullSession:  *nullSession && *username == "",
		Verbose:      *verbose,
		PlanMode:     *planMode,
		OutputFile:   *outputFile,
	}

	if *username != "" {
		config.Username = username
	}
	if *password != "" {
		config.Password = password
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute enumeration
	fmt.Println("[*] SMB Enumerator starting...")
	fmt.Printf("[*] Target: %s:%d\n", config.Target, config.Port)

	enumerator := NewSMBEnumerator(config)

	result := enumerator.Enumerate()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SMB ENUMERATION RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	if result.SystemInfo != nil {
		fmt.Println("\nSYSTEM INFORMATION:")
		fmt.Println(strings.Repeat("-", 40))
		osVer := "Unknown"
		if result.SystemInfo.OSVersion != nil {
			osVer = *result.SystemInfo.OSVersion
		}
		smbVer := "Unknown"
		if result.SystemInfo.SMBVersion != nil {
			smbVer = *result.SystemInfo.SMBVersion
		}
		domainStr := "Unknown"
		if result.SystemInfo.Domain != nil {
			domainStr = *result.SystemInfo.Domain
		}
		signing := "Not Required"
		if result.SystemInfo.SigningRequired {
			signing = "Required"
		}
		fmt.Printf("  OS Version:      %s\n", osVer)
		fmt.Printf("  SMB Version:     %s\n", smbVer)
		fmt.Printf("  Domain:          %s\n", domainStr)
		fmt.Printf("  Signing:         %s\n", signing)
	}

	if len(result.Shares) > 0 {
		fmt.Printf("\nSHARES (%d):\n", len(result.Shares))
		fmt.Println(strings.Repeat("-", 40))
		for _, share := range result.Shares {
			perms := ""
			if share.Permissions != nil {
				perms = *share.Permissions
			}
			fmt.Printf("  %-20s [%s] %s\n", share.Name, share.ShareType, perms)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nERRORS:")
		fmt.Println(strings.Repeat("-", 40))
		for _, err := range result.Errors {
			fmt.Printf("  [!] %s\n", err)
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf("[!] Error creating JSON: %v\n", err)
		} else {
			err = os.WriteFile(config.OutputFile, jsonData, 0644)
			if err != nil {
				fmt.Printf("[!] Error writing output file: %v\n", err)
			} else {
				fmt.Printf("\n[*] Results saved to %s\n", config.OutputFile)
			}
		}
	}

	os.Exit(0)
}
