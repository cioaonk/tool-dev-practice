// validator.go - Go port of credential-validator/tool.py
// Multi-Protocol Authentication Testing Tool
//
// Build instructions:
//   go build -o validator validator.go
//
// Usage:
//   ./validator <target> --protocol <protocol> [flags]
//   ./validator 192.168.1.1 --protocol ftp -u admin -P password --plan
//   ./validator target.com --protocol http-basic --credentials creds.txt
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized authentication attempts are illegal and unethical.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultTimeout  = 10.0
	DefaultThreads  = 5
	DefaultDelayMin = 0.5
	DefaultDelayMax = 2.0
)

// Protocol represents supported authentication protocols
type Protocol string

const (
	ProtocolSSH       Protocol = "ssh"
	ProtocolFTP       Protocol = "ftp"
	ProtocolHTTPBasic Protocol = "http-basic"
	ProtocolHTTPForm  Protocol = "http-form"
	ProtocolSMTP      Protocol = "smtp"
	ProtocolMySQL     Protocol = "mysql"
)

// ValidationResult represents possible validation outcomes
type ValidationResult string

const (
	ResultValid   ValidationResult = "valid"
	ResultInvalid ValidationResult = "invalid"
	ResultLocked  ValidationResult = "locked"
	ResultError   ValidationResult = "error"
	ResultTimeout ValidationResult = "timeout"
	ResultUnknown ValidationResult = "unknown"
)

// =============================================================================
// Data Structures
// =============================================================================

// Credential represents a username/password pair
type Credential struct {
	Username string
	Password string
	Domain   string
}

func (c *Credential) String() string {
	if c.Domain != "" {
		return fmt.Sprintf("%s\\%s:%s", c.Domain, c.Username, c.Password)
	}
	return fmt.Sprintf("%s:%s", c.Username, c.Password)
}

// Clear securely clears credential from memory
func (c *Credential) Clear() {
	c.Username = strings.Repeat("x", len(c.Username))
	c.Password = strings.Repeat("x", len(c.Password))
	if c.Domain != "" {
		c.Domain = strings.Repeat("x", len(c.Domain))
	}
}

// ValidationAttempt represents the result of a credential validation attempt
type ValidationAttempt struct {
	Credential   *Credential      `json:"-"`
	Protocol     Protocol         `json:"protocol"`
	Target       string           `json:"target"`
	Result       ValidationResult `json:"result"`
	Message      string           `json:"message,omitempty"`
	ResponseTime *float64         `json:"response_time,omitempty"`
	Timestamp    string           `json:"timestamp"`
	Username     string           `json:"username"`
	Domain       string           `json:"domain,omitempty"`
}

// ToDict returns a map representation for JSON serialization
func (v *ValidationAttempt) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"username":  v.Username,
		"protocol":  string(v.Protocol),
		"target":    v.Target,
		"result":    string(v.Result),
		"timestamp": v.Timestamp,
	}
	if v.Domain != "" {
		result["domain"] = v.Domain
	}
	if v.Message != "" {
		result["message"] = v.Message
	}
	if v.ResponseTime != nil {
		result["response_time"] = *v.ResponseTime
	}
	return result
}

// ValidatorConfig holds configuration for credential validation
type ValidatorConfig struct {
	Target            string
	Port              int
	Protocol          Protocol
	Credentials       []*Credential
	Timeout           float64
	Threads           int
	DelayMin          float64
	DelayMax          float64
	StopOnSuccess     bool
	Verbose           bool
	PlanMode          bool
	OutputFile        string
	HTTPPath          string
	HTTPMethod        string
	HTTPUserField     string
	HTTPPassField     string
	HTTPSuccessString string
	HTTPFailureString string
}

// =============================================================================
// Protocol Validators
// =============================================================================

// ProtocolValidator defines the interface for protocol-specific validators
type ProtocolValidator interface {
	Name() string
	DefaultPort() int
	Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt
}

// SSHValidator implements SSH credential validation
type SSHValidator struct{}

func (s *SSHValidator) Name() string {
	return "SSH"
}

func (s *SSHValidator) DefaultPort() int {
	return 22
}

func (s *SSHValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout*float64(time.Second)))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolSSH,
				Target:     address,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Domain:     credential.Domain,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolSSH,
			Target:     address,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Domain:     credential.Domain,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	// Receive banner
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || !strings.HasPrefix(string(buffer[:n]), "SSH-") {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolSSH,
			Target:     address,
			Result:     ResultError,
			Message:    "Not an SSH service",
			Username:   credential.Username,
			Domain:     credential.Domain,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Send client banner
	conn.Write([]byte("SSH-2.0-OpenSSH_Client\r\n"))

	responseTime := time.Since(startTime).Seconds()

	// Note: Full SSH authentication requires implementing the SSH protocol
	// This is a framework placeholder
	return &ValidationAttempt{
		Credential:   credential,
		Protocol:     ProtocolSSH,
		Target:       address,
		Result:       ResultUnknown,
		Message:      "SSH validation requires crypto/ssh library implementation",
		ResponseTime: &responseTime,
		Username:     credential.Username,
		Domain:       credential.Domain,
		Timestamp:    time.Now().Format(time.RFC3339),
	}
}

// FTPValidator implements FTP credential validation
type FTPValidator struct{}

func (f *FTPValidator) Name() string {
	return "FTP"
}

func (f *FTPValidator) DefaultPort() int {
	return 21
}

func (f *FTPValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout*float64(time.Second)))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolFTP,
				Target:     address,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolFTP,
			Target:     address,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))

	// Receive banner
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	banner := string(buffer[:n])

	if !strings.HasPrefix(banner, "220") {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolFTP,
			Target:     address,
			Result:     ResultError,
			Message:    "Not an FTP service",
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Send USER command
	conn.Write([]byte(fmt.Sprintf("USER %s\r\n", credential.Username)))
	n, _ = conn.Read(buffer)
	response := string(buffer[:n])

	if strings.HasPrefix(response, "331") {
		// Send PASS command
		conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", credential.Password)))
		n, _ = conn.Read(buffer)
		response = string(buffer[:n])

		responseTime := time.Since(startTime).Seconds()

		if strings.HasPrefix(response, "230") {
			conn.Write([]byte("QUIT\r\n"))
			return &ValidationAttempt{
				Credential:   credential,
				Protocol:     ProtocolFTP,
				Target:       address,
				Result:       ResultValid,
				Message:      "FTP login successful",
				ResponseTime: &responseTime,
				Username:     credential.Username,
				Timestamp:    time.Now().Format(time.RFC3339),
			}
		} else if strings.HasPrefix(response, "530") {
			return &ValidationAttempt{
				Credential:   credential,
				Protocol:     ProtocolFTP,
				Target:       address,
				Result:       ResultInvalid,
				Message:      "Invalid credentials",
				ResponseTime: &responseTime,
				Username:     credential.Username,
				Timestamp:    time.Now().Format(time.RFC3339),
			}
		}
	}

	return &ValidationAttempt{
		Credential: credential,
		Protocol:   ProtocolFTP,
		Target:     address,
		Result:     ResultUnknown,
		Message:    fmt.Sprintf("Unexpected response: %s", response[:min(50, len(response))]),
		Username:   credential.Username,
		Timestamp:  time.Now().Format(time.RFC3339),
	}
}

// HTTPBasicValidator implements HTTP Basic Authentication validation
type HTTPBasicValidator struct{}

func (h *HTTPBasicValidator) Name() string {
	return "HTTP Basic Auth"
}

func (h *HTTPBasicValidator) DefaultPort() int {
	return 80
}

func (h *HTTPBasicValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, config.HTTPPath)
	targetDisplay := fmt.Sprintf("%s:%d%s", target, port, config.HTTPPath)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout * float64(time.Second)),
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolHTTPBasic,
			Target:     targetDisplay,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Create Basic Auth header
	authString := fmt.Sprintf("%s:%s", credential.Username, credential.Password)
	authBytes := base64.StdEncoding.EncodeToString([]byte(authString))

	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", authBytes))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolHTTPBasic,
				Target:     targetDisplay,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolHTTPBasic,
			Target:     targetDisplay,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	switch resp.StatusCode {
	case 200:
		return &ValidationAttempt{
			Credential:   credential,
			Protocol:     ProtocolHTTPBasic,
			Target:       targetDisplay,
			Result:       ResultValid,
			Message:      "HTTP 200 - Authentication successful",
			ResponseTime: &responseTime,
			Username:     credential.Username,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	case 401:
		return &ValidationAttempt{
			Credential:   credential,
			Protocol:     ProtocolHTTPBasic,
			Target:       targetDisplay,
			Result:       ResultInvalid,
			Message:      "HTTP 401 - Invalid credentials",
			ResponseTime: &responseTime,
			Username:     credential.Username,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	case 403:
		return &ValidationAttempt{
			Credential:   credential,
			Protocol:     ProtocolHTTPBasic,
			Target:       targetDisplay,
			Result:       ResultLocked,
			Message:      "HTTP 403 - Access forbidden (possibly locked)",
			ResponseTime: &responseTime,
			Username:     credential.Username,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	default:
		return &ValidationAttempt{
			Credential:   credential,
			Protocol:     ProtocolHTTPBasic,
			Target:       targetDisplay,
			Result:       ResultUnknown,
			Message:      fmt.Sprintf("HTTP %d", resp.StatusCode),
			ResponseTime: &responseTime,
			Username:     credential.Username,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
	}
}

// HTTPFormValidator implements HTTP Form-based authentication validation
type HTTPFormValidator struct{}

func (h *HTTPFormValidator) Name() string {
	return "HTTP Form Auth"
}

func (h *HTTPFormValidator) DefaultPort() int {
	return 80
}

func (h *HTTPFormValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, config.HTTPPath)
	targetDisplay := fmt.Sprintf("%s:%d%s", target, port, config.HTTPPath)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout * float64(time.Second)),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build form data
	formData := url.Values{}
	formData.Set(config.HTTPUserField, credential.Username)
	formData.Set(config.HTTPPassField, credential.Password)

	req, err := http.NewRequest(config.HTTPMethod, targetURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolHTTPForm,
			Target:     targetDisplay,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolHTTPForm,
				Target:     targetDisplay,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolHTTPForm,
			Target:     targetDisplay,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	// Read body for analysis
	bodyBytes := make([]byte, 8192)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	result := ResultUnknown

	// Check for success string
	if config.HTTPSuccessString != "" && strings.Contains(body, config.HTTPSuccessString) {
		result = ResultValid
	} else if config.HTTPFailureString != "" && strings.Contains(body, config.HTTPFailureString) {
		result = ResultInvalid
	} else if resp.StatusCode == 200 || resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		bodyLower := strings.ToLower(body)
		if strings.Contains(location, "dashboard") || strings.Contains(location, "home") || strings.Contains(bodyLower, "welcome") {
			result = ResultValid
		} else if strings.Contains(bodyLower, "invalid") || strings.Contains(bodyLower, "incorrect") || strings.Contains(bodyLower, "failed") {
			result = ResultInvalid
		}
	}

	return &ValidationAttempt{
		Credential:   credential,
		Protocol:     ProtocolHTTPForm,
		Target:       targetDisplay,
		Result:       result,
		Message:      fmt.Sprintf("HTTP %d", resp.StatusCode),
		ResponseTime: &responseTime,
		Username:     credential.Username,
		Timestamp:    time.Now().Format(time.RFC3339),
	}
}

// SMTPValidator implements SMTP authentication validation
type SMTPValidator struct{}

func (s *SMTPValidator) Name() string {
	return "SMTP"
}

func (s *SMTPValidator) DefaultPort() int {
	return 25
}

func (s *SMTPValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout*float64(time.Second)))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolSMTP,
				Target:     address,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolSMTP,
			Target:     address,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))

	// Receive banner
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	banner := string(buffer[:n])

	if !strings.HasPrefix(banner, "220") {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolSMTP,
			Target:     address,
			Result:     ResultError,
			Message:    "Not an SMTP service",
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Send EHLO
	conn.Write([]byte("EHLO test\r\n"))
	n, _ = conn.Read(buffer)
	response := string(buffer[:n])

	if !strings.Contains(response, "AUTH") {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolSMTP,
			Target:     address,
			Result:     ResultError,
			Message:    "SMTP AUTH not supported",
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Try AUTH LOGIN
	conn.Write([]byte("AUTH LOGIN\r\n"))
	n, _ = conn.Read(buffer)
	response = string(buffer[:n])

	if strings.HasPrefix(response, "334") {
		// Send username (base64)
		conn.Write([]byte(base64.StdEncoding.EncodeToString([]byte(credential.Username)) + "\r\n"))
		n, _ = conn.Read(buffer)
		response = string(buffer[:n])

		if strings.HasPrefix(response, "334") {
			// Send password (base64)
			conn.Write([]byte(base64.StdEncoding.EncodeToString([]byte(credential.Password)) + "\r\n"))
			n, _ = conn.Read(buffer)
			response = string(buffer[:n])

			conn.Write([]byte("QUIT\r\n"))

			responseTime := time.Since(startTime).Seconds()

			if strings.HasPrefix(response, "235") {
				return &ValidationAttempt{
					Credential:   credential,
					Protocol:     ProtocolSMTP,
					Target:       address,
					Result:       ResultValid,
					Message:      "SMTP authentication successful",
					ResponseTime: &responseTime,
					Username:     credential.Username,
					Timestamp:    time.Now().Format(time.RFC3339),
				}
			} else if strings.HasPrefix(response, "535") {
				return &ValidationAttempt{
					Credential:   credential,
					Protocol:     ProtocolSMTP,
					Target:       address,
					Result:       ResultInvalid,
					Message:      "Invalid credentials",
					ResponseTime: &responseTime,
					Username:     credential.Username,
					Timestamp:    time.Now().Format(time.RFC3339),
				}
			}
		}
	}

	return &ValidationAttempt{
		Credential: credential,
		Protocol:   ProtocolSMTP,
		Target:     address,
		Result:     ResultUnknown,
		Message:    "Unexpected SMTP response",
		Username:   credential.Username,
		Timestamp:  time.Now().Format(time.RFC3339),
	}
}

// MySQLValidator implements MySQL authentication validation
type MySQLValidator struct{}

func (m *MySQLValidator) Name() string {
	return "MySQL"
}

func (m *MySQLValidator) DefaultPort() int {
	return 3306
}

func (m *MySQLValidator) Validate(target string, port int, credential *Credential, config *ValidatorConfig) *ValidationAttempt {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, time.Duration(config.Timeout*float64(time.Second)))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return &ValidationAttempt{
				Credential: credential,
				Protocol:   ProtocolMySQL,
				Target:     address,
				Result:     ResultTimeout,
				Username:   credential.Username,
				Timestamp:  time.Now().Format(time.RFC3339),
			}
		}
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolMySQL,
			Target:     address,
			Result:     ResultError,
			Message:    err.Error(),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))

	// Receive greeting packet
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n < 5 {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolMySQL,
			Target:     address,
			Result:     ResultError,
			Message:    "Invalid MySQL greeting",
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	// Check protocol version
	protocolVersion := buffer[4]
	if protocolVersion != 10 {
		return &ValidationAttempt{
			Credential: credential,
			Protocol:   ProtocolMySQL,
			Target:     address,
			Result:     ResultError,
			Message:    fmt.Sprintf("Unsupported MySQL protocol: %d", protocolVersion),
			Username:   credential.Username,
			Timestamp:  time.Now().Format(time.RFC3339),
		}
	}

	responseTime := time.Since(startTime).Seconds()

	// Note: Full MySQL authentication requires implementing mysql_native_password auth
	return &ValidationAttempt{
		Credential:   credential,
		Protocol:     ProtocolMySQL,
		Target:       address,
		Result:       ResultUnknown,
		Message:      "MySQL validation requires full protocol implementation",
		ResponseTime: &responseTime,
		Username:     credential.Username,
		Timestamp:    time.Now().Format(time.RFC3339),
	}
}

// =============================================================================
// Credential Validator Core
// =============================================================================

// CredentialValidator is the main credential validation engine
type CredentialValidator struct {
	Config       *ValidatorConfig
	Results      []*ValidationAttempt
	stopEvent    chan struct{}
	mutex        sync.Mutex
	successFound bool
	validator    ProtocolValidator
	port         int
}

// NewCredentialValidator creates a new CredentialValidator instance
func NewCredentialValidator(config *ValidatorConfig) (*CredentialValidator, error) {
	var validator ProtocolValidator

	switch config.Protocol {
	case ProtocolSSH:
		validator = &SSHValidator{}
	case ProtocolFTP:
		validator = &FTPValidator{}
	case ProtocolHTTPBasic:
		validator = &HTTPBasicValidator{}
	case ProtocolHTTPForm:
		validator = &HTTPFormValidator{}
	case ProtocolSMTP:
		validator = &SMTPValidator{}
	case ProtocolMySQL:
		validator = &MySQLValidator{}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	port := config.Port
	if port == 0 {
		port = validator.DefaultPort()
	}

	return &CredentialValidator{
		Config:    config,
		Results:   []*ValidationAttempt{},
		stopEvent: make(chan struct{}),
		validator: validator,
		port:      port,
	}, nil
}

// applyJitter applies random delay for stealth
func (cv *CredentialValidator) applyJitter() {
	if cv.Config.DelayMax > 0 {
		delay := cv.Config.DelayMin + rand.Float64()*(cv.Config.DelayMax-cv.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// validateCredential validates a single credential
func (cv *CredentialValidator) validateCredential(credential *Credential) *ValidationAttempt {
	select {
	case <-cv.stopEvent:
		return nil
	default:
	}

	if cv.Config.StopOnSuccess && cv.successFound {
		return nil
	}

	cv.applyJitter()

	result := cv.validator.Validate(cv.Config.Target, cv.port, credential, cv.Config)

	if result.Result == ResultValid {
		cv.mutex.Lock()
		cv.successFound = true
		cv.mutex.Unlock()
	}

	return result
}

// Validate executes credential validation
func (cv *CredentialValidator) Validate() []*ValidationAttempt {
	if cv.Config.Verbose {
		fmt.Printf("[*] Validating %d credentials against %s:%d (%s)\n",
			len(cv.Config.Credentials), cv.Config.Target, cv.port, cv.Config.Protocol)
	}

	jobs := make(chan *Credential, len(cv.Config.Credentials))
	results := make(chan *ValidationAttempt, len(cv.Config.Credentials))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < cv.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cred := range jobs {
				result := cv.validateCredential(cred)
				if result != nil {
					results <- result
				}
			}
		}()
	}

	// Send jobs
	for _, cred := range cv.Config.Credentials {
		jobs <- cred
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		cv.mutex.Lock()
		cv.Results = append(cv.Results, result)
		if cv.Config.Verbose {
			status := "[-]"
			if result.Result == ResultValid {
				status = "[+]"
			}
			fmt.Printf("%s %s - %s\n", status, result.Username, result.Result)
		}
		cv.mutex.Unlock()
	}

	return cv.Results
}

// Stop signals the validator to stop
func (cv *CredentialValidator) Stop() {
	close(cv.stopEvent)
}

// GetValidCredentials returns only valid credential attempts
func (cv *CredentialValidator) GetValidCredentials() []*ValidationAttempt {
	var valid []*ValidationAttempt
	for _, r := range cv.Results {
		if r.Result == ResultValid {
			valid = append(valid, r)
		}
	}
	return valid
}

// =============================================================================
// Planning Mode
// =============================================================================

func printPlan(config *ValidatorConfig) {
	var validator ProtocolValidator
	switch config.Protocol {
	case ProtocolSSH:
		validator = &SSHValidator{}
	case ProtocolFTP:
		validator = &FTPValidator{}
	case ProtocolHTTPBasic:
		validator = &HTTPBasicValidator{}
	case ProtocolHTTPForm:
		validator = &HTTPFormValidator{}
	case ProtocolSMTP:
		validator = &SMTPValidator{}
	case ProtocolMySQL:
		validator = &MySQLValidator{}
	}

	port := config.Port
	if port == 0 && validator != nil {
		port = validator.DefaultPort()
	}

	fmt.Println(`
[PLAN MODE] Tool: credential-validator
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target:          %s\n", config.Target)
	fmt.Printf("  Port:            %d\n", port)
	fmt.Printf("  Protocol:        %s\n", config.Protocol)
	fmt.Println()

	fmt.Println("VALIDATION CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Credentials:     %d\n", len(config.Credentials))
	fmt.Printf("  Threads:         %d\n", config.Threads)
	fmt.Printf("  Timeout:         %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:     %.1fs - %.1fs\n", config.DelayMin, config.DelayMax)
	fmt.Printf("  Stop on Success: %t\n", config.StopOnSuccess)
	fmt.Println()

	if config.Protocol == ProtocolHTTPBasic || config.Protocol == ProtocolHTTPForm {
		fmt.Println("HTTP-SPECIFIC OPTIONS")
		fmt.Println(strings.Repeat("-", 40))
		fmt.Printf("  Path:            %s\n", config.HTTPPath)
		fmt.Printf("  Method:          %s\n", config.HTTPMethod)
		if config.Protocol == ProtocolHTTPForm {
			fmt.Printf("  User Field:      %s\n", config.HTTPUserField)
			fmt.Printf("  Pass Field:      %s\n", config.HTTPPassField)
		}
		fmt.Println()
	}

	fmt.Println("CREDENTIAL PREVIEW (first 5)")
	fmt.Println(strings.Repeat("-", 40))
	previewCount := 5
	if len(config.Credentials) < previewCount {
		previewCount = len(config.Credentials)
	}
	for i := 0; i < previewCount; i++ {
		cred := config.Credentials[i]
		maskedPass := strings.Repeat("*", min(len(cred.Password), 8))
		fmt.Printf("  - %s:%s\n", cred.Username, maskedPass)
	}
	if len(config.Credentials) > 5 {
		fmt.Printf("  ... and %d more\n", len(config.Credentials)-5)
	}
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. For each credential pair:")
	fmt.Printf("     - Apply random delay (%.1fs - %.1fs)\n", config.DelayMin, config.DelayMax)
	fmt.Printf("     - Attempt %s authentication\n", config.Protocol)
	fmt.Println("     - Analyze response for success/failure")
	if config.StopOnSuccess {
		fmt.Println("     - Stop immediately if valid credential found")
	}
	fmt.Println("  2. Aggregate results in memory")
	fmt.Println("  3. Clear credential data after completion")
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	var riskFactors []string

	if len(config.Credentials) > 50 {
		riskFactors = append(riskFactors, "Large credential list may trigger lockouts")
	}
	if config.DelayMax < 1.0 {
		riskFactors = append(riskFactors, "Low delay increases lockout risk")
	}
	if config.Threads > 5 {
		riskFactors = append(riskFactors, "Multiple threads may appear as attack")
	}
	if !config.StopOnSuccess {
		riskFactors = append(riskFactors, "Continued testing after success may be suspicious")
	}

	riskLevel := "MEDIUM" // Auth testing is inherently risky
	if len(riskFactors) >= 2 {
		riskLevel = "HIGH"
	}

	fmt.Printf("  Risk Level: %s\n", riskLevel)
	for _, factor := range riskFactors {
		fmt.Printf("    - %s\n", factor)
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Authentication logs will record all attempts")
	fmt.Println("  - Failed logins may trigger account lockout")
	fmt.Println("  - Security systems may alert on multiple failures")
	fmt.Println("  - Source IP will be logged with each attempt")
	fmt.Println()

	fmt.Println("OPSEC CONSIDERATIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Credentials handled in-memory only")
	fmt.Println("  - Passwords not logged to disk")
	fmt.Println("  - Use appropriate delays to avoid detection")
	fmt.Println("  - Consider account lockout policies")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// Helper Functions
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func loadCredentials(credFile, username, password, userlist, passlist string) []*Credential {
	var credentials []*Credential

	// Load from credentials file
	if credFile != "" {
		file, err := os.Open(credFile)
		if err != nil {
			fmt.Printf("[!] Error loading credentials file: %v\n", err)
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && strings.Contains(line, ":") {
					parts := strings.SplitN(line, ":", 2)
					credentials = append(credentials, &Credential{
						Username: parts[0],
						Password: parts[1],
					})
				}
			}
		}
	}

	// Single credential
	if username != "" && password != "" {
		credentials = append(credentials, &Credential{
			Username: username,
			Password: password,
		})
	}

	// Username list + password list (cartesian product)
	if userlist != "" && passlist != "" {
		var users, passwords []string

		userFile, err := os.Open(userlist)
		if err == nil {
			defer userFile.Close()
			scanner := bufio.NewScanner(userFile)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					users = append(users, line)
				}
			}
		}

		passFile, err := os.Open(passlist)
		if err == nil {
			defer passFile.Close()
			scanner := bufio.NewScanner(passFile)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					passwords = append(passwords, line)
				}
			}
		}

		for _, user := range users {
			for _, pass := range passwords {
				credentials = append(credentials, &Credential{
					Username: user,
					Password: pass,
				})
			}
		}
	}

	return credentials
}

// =============================================================================
// CLI Interface
// =============================================================================

func main() {
	rand.Seed(time.Now().UnixNano())

	protocolFlag := flag.String("protocol", "", "Authentication protocol to test (ssh, ftp, http-basic, http-form, smtp, mysql)")
	portFlag := flag.Int("port", 0, "Target port (default: protocol-specific)")
	credentialsFlag := flag.String("c", "", "File with credentials (user:pass format, one per line)")
	credentialsFlag2 := flag.String("credentials", "", "File with credentials")
	usernameFlag := flag.String("u", "", "Single username to test")
	usernameFlag2 := flag.String("username", "", "Single username to test")
	passwordFlag := flag.String("P", "", "Single password to test")
	passwordFlag2 := flag.String("password", "", "Single password to test")
	userlistFlag := flag.String("U", "", "File with usernames (one per line)")
	userlistFlag2 := flag.String("userlist", "", "File with usernames")
	passlistFlag := flag.String("W", "", "File with passwords (one per line)")
	passlistFlag2 := flag.String("passlist", "", "File with passwords")
	threadsFlag := flag.Int("t", DefaultThreads, "Number of concurrent threads")
	threadsFlag2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	timeoutFlag := flag.Float64("timeout", DefaultTimeout, "Connection timeout in seconds")
	delayMinFlag := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between attempts")
	delayMaxFlag := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between attempts")
	stopOnSuccessFlag := flag.Bool("stop-on-success", false, "Stop after finding valid credentials")
	httpPathFlag := flag.String("http-path", "/login", "HTTP path for authentication")
	httpMethodFlag := flag.String("http-method", "POST", "HTTP method for form auth")
	httpUserFieldFlag := flag.String("http-user-field", "username", "Form field name for username")
	httpPassFieldFlag := flag.String("http-pass-field", "password", "Form field name for password")
	httpSuccessFlag := flag.String("http-success", "", "String that indicates successful login")
	httpFailureFlag := flag.String("http-failure", "", "String that indicates failed login")
	planFlag := flag.Bool("p", false, "Show execution plan without testing")
	planFlag2 := flag.Bool("plan", false, "Show execution plan without testing")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseFlag2 := flag.Bool("verbose", false, "Enable verbose output")
	outputFlag := flag.String("o", "", "Output file for results (JSON format)")
	outputFlag2 := flag.String("output", "", "Output file for results (JSON format)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Credential Validator - Multi-Protocol Authentication Testing

Usage:
  %s [flags] target

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  validator 192.168.1.1 --protocol ftp -u admin -P password --plan
  validator target.com --protocol http-basic --credentials creds.txt
  validator 10.0.0.1 --protocol smtp -u user@domain.com -P pass123

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

	if *protocolFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: No protocol specified")
		flag.Usage()
		os.Exit(1)
	}

	protocol := Protocol(*protocolFlag)

	// Load credentials
	credFile := *credentialsFlag
	if *credentialsFlag2 != "" {
		credFile = *credentialsFlag2
	}
	username := *usernameFlag
	if *usernameFlag2 != "" {
		username = *usernameFlag2
	}
	password := *passwordFlag
	if *passwordFlag2 != "" {
		password = *passwordFlag2
	}
	userlist := *userlistFlag
	if *userlistFlag2 != "" {
		userlist = *userlistFlag2
	}
	passlist := *passlistFlag
	if *passlistFlag2 != "" {
		passlist = *passlistFlag2
	}

	credentials := loadCredentials(credFile, username, password, userlist, passlist)

	threads := *threadsFlag
	if *threadsFlag2 != DefaultThreads {
		threads = *threadsFlag2
	}

	output := *outputFlag
	if *outputFlag2 != "" {
		output = *outputFlag2
	}

	config := &ValidatorConfig{
		Target:            target,
		Port:              *portFlag,
		Protocol:          protocol,
		Credentials:       credentials,
		Timeout:           *timeoutFlag,
		Threads:           threads,
		DelayMin:          *delayMinFlag,
		DelayMax:          *delayMaxFlag,
		StopOnSuccess:     *stopOnSuccessFlag,
		Verbose:           *verboseFlag || *verboseFlag2,
		PlanMode:          *planFlag || *planFlag2,
		OutputFile:        output,
		HTTPPath:          *httpPathFlag,
		HTTPMethod:        *httpMethodFlag,
		HTTPUserField:     *httpUserFieldFlag,
		HTTPPassField:     *httpPassFieldFlag,
		HTTPSuccessString: *httpSuccessFlag,
		HTTPFailureString: *httpFailureFlag,
	}

	// Planning mode
	if config.PlanMode {
		if len(config.Credentials) == 0 {
			config.Credentials = []*Credential{{Username: "user", Password: "password"}}
		}
		printPlan(config)
		os.Exit(0)
	}

	if len(credentials) == 0 {
		fmt.Println("[!] No credentials specified")
		fmt.Println("[*] Use -u/-P for single credential, -c for file, or -U/-W for lists")
		os.Exit(1)
	}

	// Execute validation
	fmt.Println("[*] Credential Validator starting...")
	fmt.Printf("[*] Target: %s\n", config.Target)
	fmt.Printf("[*] Protocol: %s\n", config.Protocol)
	fmt.Printf("[*] Credentials: %d\n", len(config.Credentials))

	validator, err := NewCredentialValidator(config)
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}

	results := validator.Validate()
	validCreds := validator.GetValidCredentials()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("VALIDATION RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total tested:    %d\n", len(results))
	fmt.Printf("Valid:           %d\n", len(validCreds))

	invalidCount := 0
	errorCount := 0
	for _, r := range results {
		if r.Result == ResultInvalid {
			invalidCount++
		} else if r.Result == ResultError {
			errorCount++
		}
	}
	fmt.Printf("Invalid:         %d\n", invalidCount)
	fmt.Printf("Errors:          %d\n", errorCount)
	fmt.Println()

	if len(validCreds) > 0 {
		fmt.Println("VALID CREDENTIALS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, result := range validCreds {
			// Note: Password cleared from memory, showing username only
			fmt.Printf("  [+] %s (validated)\n", result.Username)
		}
	}

	// Clear credentials from memory
	for _, cred := range credentials {
		cred.Clear()
	}

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := map[string]interface{}{
			"target":    config.Target,
			"protocol":  string(config.Protocol),
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
