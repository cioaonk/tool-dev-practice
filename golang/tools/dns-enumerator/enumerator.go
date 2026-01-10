// enumerator.go - Go port of dns-enumerator/tool.py
// Comprehensive DNS Reconnaissance Tool
//
// Build instructions:
//   go build -o enumerator enumerator.go
//
// Usage:
//   ./enumerator <domain> [flags]
//   ./enumerator example.com --plan
//   ./enumerator example.com --zone-transfer
//   ./enumerator example.com -w subdomains.txt -t 20
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized DNS enumeration may violate terms of service.

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
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
	DefaultDelayMin = 0.0
	DefaultDelayMax = 0.1
)

// DNS Record Types
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeAXFR  uint16 = 252
	TypeANY   uint16 = 255
)

// RecordTypeName maps record type to name
var RecordTypeName = map[uint16]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
}

// Default subdomains for bruteforcing
var DefaultSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
	"ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
	"email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
	"admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
	"www1", "smtp1", "autodiscover", "mail3", "mx2", "staging", "beta",
	"intranet", "extranet", "demo", "mobile", "gateway", "dns", "dns1",
	"dns2", "ns3", "backup", "corp", "internal", "private", "public",
	"office", "partner", "admin2", "cpanel", "whm", "direct", "direct-connect",
	"vps", "server1", "server2", "proxy", "git", "svn", "cms", "status",
}

// =============================================================================
// Data Structures
// =============================================================================

// DNSRecord represents a DNS record
type DNSRecord struct {
	Name       string `json:"name"`
	RecordType string `json:"type"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl,omitempty"`
	Priority   int    `json:"priority,omitempty"` // For MX records
	Timestamp  string `json:"timestamp"`
}

// ToDict returns a map representation for JSON serialization
func (r *DNSRecord) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"name":      r.Name,
		"type":      r.RecordType,
		"value":     r.Value,
		"timestamp": r.Timestamp,
	}
	if r.TTL > 0 {
		result["ttl"] = r.TTL
	}
	if r.Priority > 0 {
		result["priority"] = r.Priority
	}
	return result
}

// EnumConfig holds configuration for DNS enumeration
type EnumConfig struct {
	Domain       string
	Nameserver   string
	Wordlist     []string
	RecordTypes  []string
	Timeout      float64
	Threads      int
	DelayMin     float64
	DelayMax     float64
	ZoneTransfer bool
	BruteForce   bool
	Verbose      bool
	PlanMode     bool
	OutputFile   string
}

// =============================================================================
// DNS Protocol Implementation
// =============================================================================

// DNSResolver implements a lightweight DNS resolver using raw UDP sockets
type DNSResolver struct {
	Nameserver    string
	Timeout       float64
	transactionID uint16
}

// NewDNSResolver creates a new DNS resolver instance
func NewDNSResolver(nameserver string, timeout float64) *DNSResolver {
	return &DNSResolver{
		Nameserver:    nameserver,
		Timeout:       timeout,
		transactionID: uint16(rand.Intn(65536)),
	}
}

// buildQuery builds a DNS query packet
func (r *DNSResolver) buildQuery(domain string, recordType uint16) []byte {
	r.transactionID = (r.transactionID + 1) % 65536

	// Transaction ID (2 bytes)
	packet := make([]byte, 0, 512)
	packet = append(packet, byte(r.transactionID>>8), byte(r.transactionID))

	// Flags: standard query, recursion desired (2 bytes)
	packet = append(packet, 0x01, 0x00)

	// Questions: 1, Answers: 0, Authority: 0, Additional: 0 (8 bytes)
	packet = append(packet, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Question section - domain name
	for _, part := range strings.Split(domain, ".") {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00) // End of domain name

	// Type and class (4 bytes)
	packet = append(packet, byte(recordType>>8), byte(recordType))
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}

// parseName parses a domain name from DNS response
func (r *DNSResolver) parseName(data []byte, offset int) (string, int) {
	var labels []string
	originalOffset := offset
	jumped := false

	for {
		if offset >= len(data) {
			break
		}

		length := int(data[offset])

		if length == 0 {
			offset++
			break
		} else if (length & 0xc0) == 0xc0 {
			// Compression pointer
			if !jumped {
				originalOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3fff
			offset = pointer
			jumped = true
		} else {
			offset++
			if offset+length <= len(data) {
				labels = append(labels, string(data[offset:offset+length]))
			}
			offset += length
		}
	}

	if jumped {
		return strings.Join(labels, "."), originalOffset
	}
	return strings.Join(labels, "."), offset
}

// parseResponse parses a DNS response packet
func (r *DNSResolver) parseResponse(data []byte) []*DNSRecord {
	var records []*DNSRecord

	if len(data) < 12 {
		return records
	}

	// Parse header
	flags := binary.BigEndian.Uint16(data[2:4])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])

	// Check for errors (RCODE in lower 4 bits)
	rcode := flags & 0x000f
	if rcode != 0 {
		return records
	}

	offset := 12

	// Skip questions
	for i := uint16(0); i < qdcount; i++ {
		_, offset = r.parseName(data, offset)
		offset += 4 // Type and class
	}

	// Parse answers
	for i := uint16(0); i < ancount; i++ {
		if offset+10 > len(data) {
			break
		}

		name, newOffset := r.parseName(data, offset)
		offset = newOffset

		if offset+10 > len(data) {
			break
		}

		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		// rclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlength) > len(data) {
			break
		}

		rdata := data[offset : offset+int(rdlength)]
		offset += int(rdlength)

		// Parse record data based on type
		var value string
		var priority int

		switch rtype {
		case TypeA:
			if len(rdata) == 4 {
				value = fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
			}
		case TypeAAAA:
			if len(rdata) == 16 {
				var parts []string
				for i := 0; i < 16; i += 2 {
					parts = append(parts, fmt.Sprintf("%02x%02x", rdata[i], rdata[i+1]))
				}
				value = strings.Join(parts, ":")
			}
		case TypeNS, TypeCNAME, TypePTR:
			value, _ = r.parseName(data, offset-int(rdlength))
		case TypeMX:
			if len(rdata) >= 2 {
				priority = int(binary.BigEndian.Uint16(rdata[:2]))
				mxName, _ := r.parseName(data, offset-int(rdlength)+2)
				value = mxName
			}
		case TypeTXT:
			txtOffset := 0
			var txtParts []string
			for txtOffset < len(rdata) {
				txtLen := int(rdata[txtOffset])
				txtOffset++
				if txtOffset+txtLen <= len(rdata) {
					txtParts = append(txtParts, string(rdata[txtOffset:txtOffset+txtLen]))
				}
				txtOffset += txtLen
			}
			value = strings.Join(txtParts, " ")
		case TypeSOA:
			primaryNS, pos := r.parseName(data, offset-int(rdlength))
			respPerson, _ := r.parseName(data, pos)
			value = fmt.Sprintf("%s %s", primaryNS, respPerson)
		default:
			value = fmt.Sprintf("%x", rdata)
		}

		if value != "" {
			recordTypeName := RecordTypeName[rtype]
			if recordTypeName == "" {
				recordTypeName = fmt.Sprintf("TYPE%d", rtype)
			}

			record := &DNSRecord{
				Name:       name,
				RecordType: recordTypeName,
				Value:      value,
				TTL:        int(ttl),
				Timestamp:  time.Now().Format(time.RFC3339),
			}
			if priority > 0 {
				record.Priority = priority
			}
			records = append(records, record)
		}
	}

	return records
}

// Query performs a DNS query
func (r *DNSResolver) Query(domain string, recordType uint16) []*DNSRecord {
	packet := r.buildQuery(domain, recordType)

	conn, err := net.DialTimeout("udp", r.Nameserver+":53", time.Duration(r.Timeout*float64(time.Second)))
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(r.Timeout * float64(time.Second))))

	_, err = conn.Write(packet)
	if err != nil {
		return nil
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil
	}

	return r.parseResponse(response[:n])
}

// Resolve resolves domain to IP address
func (r *DNSResolver) Resolve(domain string) string {
	records := r.Query(domain, TypeA)
	if len(records) > 0 {
		return records[0].Value
	}
	return ""
}

// =============================================================================
// Zone Transfer
// =============================================================================

// ZoneTransfer attempts DNS zone transfer (AXFR)
type ZoneTransfer struct {
	Nameserver string
	Timeout    float64
}

// NewZoneTransfer creates a new ZoneTransfer instance
func NewZoneTransfer(nameserver string, timeout float64) *ZoneTransfer {
	return &ZoneTransfer{
		Nameserver: nameserver,
		Timeout:    timeout,
	}
}

// buildAXFRQuery builds an AXFR query packet
func (zt *ZoneTransfer) buildAXFRQuery(domain string) []byte {
	transactionID := uint16(rand.Intn(65536))

	// Build query similar to regular DNS but for AXFR
	packet := make([]byte, 0, 512)
	packet = append(packet, byte(transactionID>>8), byte(transactionID))
	packet = append(packet, 0x00, 0x00) // Standard query
	packet = append(packet, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	for _, part := range strings.Split(domain, ".") {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00)

	packet = append(packet, 0x00, 0xfc) // AXFR type (252)
	packet = append(packet, 0x00, 0x01) // Class IN

	// TCP length prefix
	length := len(packet)
	tcpPacket := make([]byte, 2+length)
	binary.BigEndian.PutUint16(tcpPacket[:2], uint16(length))
	copy(tcpPacket[2:], packet)

	return tcpPacket
}

// Transfer attempts zone transfer
func (zt *ZoneTransfer) Transfer(domain string) []*DNSRecord {
	var records []*DNSRecord

	conn, err := net.DialTimeout("tcp", zt.Nameserver+":53", time.Duration(zt.Timeout*float64(time.Second)))
	if err != nil {
		return records
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(zt.Timeout * float64(time.Second))))

	query := zt.buildAXFRQuery(domain)
	_, err = conn.Write(query)
	if err != nil {
		return records
	}

	// Receive response
	response := make([]byte, 0, 65536)
	buffer := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}
		response = append(response, buffer[:n]...)
	}

	// Check for transfer denied
	if len(response) > 4 {
		flags := binary.BigEndian.Uint16(response[4:6])
		rcode := flags & 0x000f
		if rcode == 5 { // Refused
			return records
		}
	}

	// Note: Full AXFR parsing would be more complex
	// This is a simplified implementation

	return records
}

// =============================================================================
// DNS Enumerator Core
// =============================================================================

// DNSEnumerator is the main DNS enumeration engine
type DNSEnumerator struct {
	Config          *EnumConfig
	Results         []*DNSRecord
	stopEvent       chan struct{}
	mutex           sync.Mutex
	foundSubdomains map[string]bool
	nameserver      string
	resolver        *DNSResolver
}

// NewDNSEnumerator creates a new DNSEnumerator instance
func NewDNSEnumerator(config *EnumConfig) *DNSEnumerator {
	nameserver := config.Nameserver
	if nameserver == "" {
		nameserver = getSystemNameserver()
		if nameserver == "" {
			nameserver = "8.8.8.8"
		}
	}

	return &DNSEnumerator{
		Config:          config,
		Results:         []*DNSRecord{},
		stopEvent:       make(chan struct{}),
		foundSubdomains: make(map[string]bool),
		nameserver:      nameserver,
		resolver:        NewDNSResolver(nameserver, config.Timeout),
	}
}

// getSystemNameserver tries to get system's configured nameserver
func getSystemNameserver() string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// applyJitter applies random delay for stealth
func (de *DNSEnumerator) applyJitter() {
	if de.Config.DelayMax > 0 {
		delay := de.Config.DelayMin + rand.Float64()*(de.Config.DelayMax-de.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// getRecordType converts string to record type
func getRecordType(typeStr string) uint16 {
	switch strings.ToUpper(typeStr) {
	case "A":
		return TypeA
	case "AAAA":
		return TypeAAAA
	case "NS":
		return TypeNS
	case "CNAME":
		return TypeCNAME
	case "MX":
		return TypeMX
	case "TXT":
		return TypeTXT
	case "SOA":
		return TypeSOA
	case "PTR":
		return TypePTR
	default:
		return TypeA
	}
}

// checkSubdomain checks if a subdomain exists
func (de *DNSEnumerator) checkSubdomain(subdomain string) []*DNSRecord {
	select {
	case <-de.stopEvent:
		return nil
	default:
	}

	de.applyJitter()

	fullDomain := fmt.Sprintf("%s.%s", subdomain, de.Config.Domain)
	var records []*DNSRecord

	for _, recordTypeStr := range de.Config.RecordTypes {
		recordType := getRecordType(recordTypeStr)
		result := de.resolver.Query(fullDomain, recordType)
		records = append(records, result...)
	}

	return records
}

// enumerateRecords enumerates DNS records for the base domain
func (de *DNSEnumerator) enumerateRecords() []*DNSRecord {
	var records []*DNSRecord

	recordTypes := []uint16{TypeA, TypeAAAA, TypeNS, TypeMX, TypeTXT, TypeSOA}

	for _, recordType := range recordTypes {
		result := de.resolver.Query(de.Config.Domain, recordType)
		records = append(records, result...)
	}

	return records
}

// attemptZoneTransfer attempts zone transfer against nameservers
func (de *DNSEnumerator) attemptZoneTransfer() []*DNSRecord {
	var records []*DNSRecord

	// First, get NS records
	nsRecords := de.resolver.Query(de.Config.Domain, TypeNS)

	for _, nsRecord := range nsRecords {
		if de.Config.Verbose {
			fmt.Printf("[*] Attempting zone transfer from %s\n", nsRecord.Value)
		}

		// Resolve NS to IP
		nsIP := de.resolver.Resolve(nsRecord.Value)
		if nsIP == "" {
			continue
		}

		zt := NewZoneTransfer(nsIP, de.Config.Timeout)
		transferRecords := zt.Transfer(de.Config.Domain)

		if len(transferRecords) > 0 {
			if de.Config.Verbose {
				fmt.Printf("[+] Zone transfer successful from %s\n", nsRecord.Value)
			}
			records = append(records, transferRecords...)
		} else {
			if de.Config.Verbose {
				fmt.Printf("[-] Zone transfer denied by %s\n", nsRecord.Value)
			}
		}
	}

	return records
}

// Enumerate executes DNS enumeration
func (de *DNSEnumerator) Enumerate() []*DNSRecord {
	if de.Config.Verbose {
		fmt.Printf("[*] DNS Enumerator starting for %s\n", de.Config.Domain)
		fmt.Printf("[*] Using nameserver: %s\n", de.nameserver)
	}

	// Enumerate base domain records
	if de.Config.Verbose {
		fmt.Println("[*] Querying base domain records...")
	}

	baseRecords := de.enumerateRecords()
	de.Results = append(de.Results, baseRecords...)

	if de.Config.Verbose {
		for _, record := range baseRecords {
			fmt.Printf("[+] %s: %s\n", record.RecordType, record.Value)
		}
	}

	// Attempt zone transfer
	if de.Config.ZoneTransfer {
		if de.Config.Verbose {
			fmt.Println("[*] Attempting zone transfers...")
		}

		ztRecords := de.attemptZoneTransfer()
		de.Results = append(de.Results, ztRecords...)
	}

	// Subdomain bruteforce
	if de.Config.BruteForce && len(de.Config.Wordlist) > 0 {
		if de.Config.Verbose {
			fmt.Printf("[*] Bruteforcing %d subdomains...\n", len(de.Config.Wordlist))
		}

		jobs := make(chan string, len(de.Config.Wordlist))
		results := make(chan []*DNSRecord, len(de.Config.Wordlist))

		// Start worker goroutines
		var wg sync.WaitGroup
		for i := 0; i < de.Config.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for subdomain := range jobs {
					records := de.checkSubdomain(subdomain)
					if len(records) > 0 {
						results <- records
						de.mutex.Lock()
						de.foundSubdomains[subdomain] = true
						de.mutex.Unlock()
					}
				}
			}()
		}

		// Send jobs
		for _, subdomain := range de.Config.Wordlist {
			jobs <- subdomain
		}
		close(jobs)

		// Wait for workers and close results
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect results
		for records := range results {
			de.mutex.Lock()
			de.Results = append(de.Results, records...)
			if de.Config.Verbose {
				for _, record := range records {
					fmt.Printf("[+] %s -> %s\n", record.Name, record.Value)
				}
			}
			de.mutex.Unlock()
		}
	}

	return de.Results
}

// Stop signals the enumerator to stop
func (de *DNSEnumerator) Stop() {
	close(de.stopEvent)
}

// GetUniqueIPs returns unique IP addresses discovered
func (de *DNSEnumerator) GetUniqueIPs() []string {
	ips := make(map[string]bool)
	for _, record := range de.Results {
		if record.RecordType == "A" || record.RecordType == "AAAA" {
			ips[record.Value] = true
		}
	}

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result
}

// =============================================================================
// Planning Mode
// =============================================================================

func printPlan(config *EnumConfig) {
	fmt.Println(`
[PLAN MODE] Tool: dns-enumerator
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Domain:          %s\n", config.Domain)
	ns := config.Nameserver
	if ns == "" {
		ns = "System default"
	}
	fmt.Printf("  Nameserver:      %s\n", ns)
	fmt.Println()

	fmt.Println("ENUMERATION CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Wordlist Size:   %d subdomains\n", len(config.Wordlist))
	fmt.Printf("  Record Types:    %s\n", strings.Join(config.RecordTypes, ", "))
	fmt.Printf("  Zone Transfer:   %t\n", config.ZoneTransfer)
	fmt.Printf("  Bruteforce:      %t\n", config.BruteForce)
	fmt.Printf("  Threads:         %d\n", config.Threads)
	fmt.Printf("  Timeout:         %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:     %.2fs - %.2fs\n", config.DelayMin, config.DelayMax)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Query base domain for common record types (A, AAAA, NS, MX, TXT, SOA)")
	if config.ZoneTransfer {
		fmt.Println("  2. Enumerate NS records and attempt zone transfer against each")
	}
	if config.BruteForce {
		fmt.Printf("  3. Bruteforce %d subdomains using %d threads\n", len(config.Wordlist), config.Threads)
		fmt.Println("     For each subdomain:")
		for _, rt := range config.RecordTypes {
			fmt.Printf("       - Query %s record\n", rt)
		}
	}
	fmt.Println("  4. Aggregate discovered records")
	fmt.Println()

	if len(config.Wordlist) > 0 {
		fmt.Println("SUBDOMAIN PREVIEW (first 20)")
		fmt.Println(strings.Repeat("-", 40))
		previewCount := 20
		if len(config.Wordlist) < previewCount {
			previewCount = len(config.Wordlist)
		}
		for i := 0; i < previewCount; i++ {
			fmt.Printf("  - %s.%s\n", config.Wordlist[i], config.Domain)
		}
		if len(config.Wordlist) > 20 {
			fmt.Printf("  ... and %d more\n", len(config.Wordlist)-20)
		}
		fmt.Println()
	}

	// Estimate
	estimatedQueries := len(config.Wordlist) * len(config.RecordTypes)
	fmt.Println("QUERY ESTIMATE")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Total queries:   ~%d\n", estimatedQueries)
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	var riskFactors []string

	if len(config.Wordlist) > 1000 {
		riskFactors = append(riskFactors, "Large wordlist generates many queries")
	}
	if config.ZoneTransfer {
		riskFactors = append(riskFactors, "Zone transfer attempts may be logged/alerted")
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
	fmt.Println("  - DNS server logs will record all queries")
	fmt.Println("  - Zone transfer attempts are typically logged")
	fmt.Println("  - High query volume may trigger rate limiting")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func loadWordlist(path string) []string {
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			fmt.Printf("[!] Error loading wordlist: %v\n", err)
			fmt.Println("[*] Using built-in wordlist")
			return append([]string{}, DefaultSubdomains...)
		}
		defer file.Close()

		var words []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" && !strings.HasPrefix(word, "#") {
				words = append(words, word)
			}
		}
		return words
	}
	return append([]string{}, DefaultSubdomains...)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	nameserverFlag := flag.String("n", "", "DNS server to use (default: system resolver)")
	nameserverFlag2 := flag.String("nameserver", "", "DNS server to use")
	wordlistFlag := flag.String("w", "", "Subdomain wordlist file (uses built-in if not specified)")
	wordlistFlag2 := flag.String("wordlist", "", "Subdomain wordlist file")
	recordTypesFlag := flag.String("r", "A,AAAA,CNAME", "Comma-separated record types to query")
	recordTypesFlag2 := flag.String("record-types", "", "Comma-separated record types to query")
	zoneTransferFlag := flag.Bool("z", false, "Attempt zone transfer against nameservers")
	zoneTransferFlag2 := flag.Bool("zone-transfer", false, "Attempt zone transfer against nameservers")
	noBruteFlag := flag.Bool("no-brute", false, "Disable subdomain bruteforcing")
	threadsFlag := flag.Int("t", DefaultThreads, "Number of concurrent threads")
	threadsFlag2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	timeoutFlag := flag.Float64("timeout", DefaultTimeout, "Query timeout in seconds")
	delayMinFlag := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between queries")
	delayMaxFlag := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between queries")
	planFlag := flag.Bool("p", false, "Show execution plan without scanning")
	planFlag2 := flag.Bool("plan", false, "Show execution plan without scanning")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseFlag2 := flag.Bool("verbose", false, "Enable verbose output")
	outputFlag := flag.String("o", "", "Output file for results (JSON format)")
	outputFlag2 := flag.String("output", "", "Output file for results (JSON format)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `DNS Enumerator - DNS Reconnaissance Tool

Usage:
  %s [flags] domain

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  enumerator example.com --plan
  enumerator example.com --zone-transfer
  enumerator example.com -w subdomains.txt -t 20

WARNING: Use only for authorized security testing.`)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No domain specified")
		flag.Usage()
		os.Exit(1)
	}
	domain := args[0]

	// Load wordlist
	wordlistPath := *wordlistFlag
	if *wordlistFlag2 != "" {
		wordlistPath = *wordlistFlag2
	}
	wordlist := loadWordlist(wordlistPath)

	// Parse record types
	recordTypesStr := *recordTypesFlag
	if *recordTypesFlag2 != "" {
		recordTypesStr = *recordTypesFlag2
	}
	var recordTypes []string
	for _, rt := range strings.Split(recordTypesStr, ",") {
		recordTypes = append(recordTypes, strings.TrimSpace(strings.ToUpper(rt)))
	}

	nameserver := *nameserverFlag
	if *nameserverFlag2 != "" {
		nameserver = *nameserverFlag2
	}

	threads := *threadsFlag
	if *threadsFlag2 != DefaultThreads {
		threads = *threadsFlag2
	}

	output := *outputFlag
	if *outputFlag2 != "" {
		output = *outputFlag2
	}

	config := &EnumConfig{
		Domain:       domain,
		Nameserver:   nameserver,
		Wordlist:     wordlist,
		RecordTypes:  recordTypes,
		Timeout:      *timeoutFlag,
		Threads:      threads,
		DelayMin:     *delayMinFlag,
		DelayMax:     *delayMaxFlag,
		ZoneTransfer: *zoneTransferFlag || *zoneTransferFlag2,
		BruteForce:   !*noBruteFlag,
		Verbose:      *verboseFlag || *verboseFlag2,
		PlanMode:     *planFlag || *planFlag2,
		OutputFile:   output,
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute enumeration
	fmt.Println("[*] DNS Enumerator starting...")
	fmt.Printf("[*] Target: %s\n", config.Domain)

	enumerator := NewDNSEnumerator(config)
	results := enumerator.Enumerate()
	uniqueIPs := enumerator.GetUniqueIPs()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("DNS ENUMERATION RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total records:      %d\n", len(results))
	fmt.Printf("Unique IPs:         %d\n", len(uniqueIPs))
	fmt.Printf("Subdomains found:   %d\n", len(enumerator.foundSubdomains))
	fmt.Println()

	if len(results) > 0 {
		fmt.Printf("%-8s %-35s %-30s\n", "TYPE", "NAME", "VALUE")
		fmt.Println(strings.Repeat("-", 70))

		// Sort by type and name
		sort.Slice(results, func(i, j int) bool {
			if results[i].RecordType != results[j].RecordType {
				return results[i].RecordType < results[j].RecordType
			}
			return results[i].Name < results[j].Name
		})

		for _, record := range results {
			name := record.Name
			if len(name) > 33 {
				name = name[:31] + ".."
			}
			value := record.Value
			if len(value) > 28 {
				value = value[:26] + ".."
			}
			fmt.Printf("%-8s %-35s %-30s\n", record.RecordType, name, value)
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		subdomainsList := make([]string, 0, len(enumerator.foundSubdomains))
		for sub := range enumerator.foundSubdomains {
			subdomainsList = append(subdomainsList, sub)
		}

		outputData := map[string]interface{}{
			"domain":    config.Domain,
			"timestamp": time.Now().Format(time.RFC3339),
			"records": func() []map[string]interface{} {
				var r []map[string]interface{}
				for _, record := range results {
					r = append(r, record.ToDict())
				}
				return r
			}(),
			"unique_ips":  uniqueIPs,
			"subdomains":  subdomainsList,
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
