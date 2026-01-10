// Package main implements an HTTP Request Tool for security testing.
// Converted from Python to Go - http-request-tool
//
// WARNING: This tool is intended for authorized security assessments only.
//
// Build: go build -o http-request-tool httptool.go
// Usage: ./http-request-tool http://target.com --plan
//        ./http-request-tool http://target.com/api -X POST -d '{"key":"value"}'
//        ./http-request-tool https://target.com -H "Authorization: Bearer token"
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const (
	DefaultTimeout   = 30.0
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

// =============================================================================
// Data Structures
// =============================================================================

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode   int               `json:"status_code"`
	StatusReason string            `json:"status_reason"`
	Headers      map[string]string `json:"headers"`
	BodyLength   int               `json:"body_length"`
	ResponseTime float64           `json:"response_time"`
	Redirects    []string          `json:"redirects"`
	SSLInfo      *SSLInfo          `json:"ssl_info,omitempty"`
	Body         []byte            `json:"-"`
}

// SSLInfo holds SSL certificate information
type SSLInfo struct {
	Subject      map[string]string `json:"subject,omitempty"`
	Issuer       map[string]string `json:"issuer,omitempty"`
	Version      int               `json:"version,omitempty"`
	NotBefore    string            `json:"not_before,omitempty"`
	NotAfter     string            `json:"not_after,omitempty"`
	SerialNumber string            `json:"serial_number,omitempty"`
}

// RequestConfig holds configuration for HTTP request tool
type RequestConfig struct {
	URL             string
	Method          string
	Headers         map[string]string
	Data            string
	DataFile        string
	Timeout         float64
	FollowRedirects bool
	MaxRedirects    int
	VerifySSL       bool
	Proxy           string
	OutputFile      string
	ShowHeaders     bool
	ShowBody        bool
	RawOutput       bool
	Verbose         bool
	PlanMode        bool
}

// =============================================================================
// HTTP Client
// =============================================================================

// HTTPClient is a flexible HTTP client for security testing
type HTTPClient struct {
	Config  *RequestConfig
	Scheme  string
	Host    string
	Port    string
	Path    string
	Query   string
	UseSSL  bool
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(config *RequestConfig) (*HTTPClient, error) {
	parsedURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}

	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := parsedURL.Host
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Handle port
	port := ""
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		port = parts[1]
	} else {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return &HTTPClient{
		Config: config,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Path:   path,
		Query:  parsedURL.RawQuery,
		UseSSL: scheme == "https",
	}, nil
}

// buildHeaders builds request headers
func (c *HTTPClient) buildHeaders() map[string]string {
	headers := map[string]string{
		"Host":       c.Host,
		"User-Agent": DefaultUserAgent,
		"Accept":     "*/*",
		"Connection": "close",
	}

	// Add/override with custom headers
	for k, v := range c.Config.Headers {
		headers[k] = v
	}

	// Add content-type for POST/PUT with data
	if c.Config.Data != "" {
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}

	return headers
}

// Request executes HTTP request
func (c *HTTPClient) Request() (*HTTPResponse, error) {
	startTime := time.Now()
	var redirects []string

	// Load body data
	body := c.Config.Data
	if c.Config.DataFile != "" {
		data, err := os.ReadFile(c.Config.DataFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load data file: %v", err)
		}
		body = string(data)
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !c.Config.VerifySSL,
		},
	}

	// Custom redirect policy to track redirects
	redirectCount := 0
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !c.Config.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if redirectCount >= c.Config.MaxRedirects {
			return http.ErrUseLastResponse
		}
		redirectCount++
		if len(via) > 0 {
			redirects = append(redirects, via[len(via)-1].URL.String())
		}
		return nil
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       time.Duration(c.Config.Timeout * float64(time.Second)),
		CheckRedirect: checkRedirect,
	}

	// Create request
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(c.Config.Method, c.Config.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	headers := c.buildHeaders()
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Get response headers
	responseHeaders := make(map[string]string)
	for k, v := range resp.Header {
		responseHeaders[k] = strings.Join(v, ", ")
	}

	responseTime := time.Since(startTime).Seconds()

	// Get SSL info
	var sslInfo *SSLInfo
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		sslInfo = &SSLInfo{
			Subject: map[string]string{
				"CommonName":   cert.Subject.CommonName,
				"Organization": strings.Join(cert.Subject.Organization, ", "),
			},
			Issuer: map[string]string{
				"CommonName":   cert.Issuer.CommonName,
				"Organization": strings.Join(cert.Issuer.Organization, ", "),
			},
			Version:      cert.Version,
			NotBefore:    cert.NotBefore.Format(time.RFC3339),
			NotAfter:     cert.NotAfter.Format(time.RFC3339),
			SerialNumber: cert.SerialNumber.String(),
		}
	}

	return &HTTPResponse{
		StatusCode:   resp.StatusCode,
		StatusReason: resp.Status,
		Headers:      responseHeaders,
		Body:         responseBody,
		BodyLength:   len(responseBody),
		ResponseTime: responseTime,
		Redirects:    redirects,
		SSLInfo:      sslInfo,
	}, nil
}

// =============================================================================
// Planning Mode
// =============================================================================

// printPlan displays execution plan without performing actions
func printPlan(config *RequestConfig) {
	parsedURL, _ := url.Parse(config.URL)

	fmt.Println(`
[PLAN MODE] Tool: http-request-tool
================================================================================
`)

	fmt.Println("REQUEST DETAILS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Method:          %s\n", config.Method)
	fmt.Printf("  URL:             %s\n", config.URL)
	fmt.Printf("  Host:            %s\n", parsedURL.Host)
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	fmt.Printf("  Path:            %s\n", path)
	fmt.Printf("  Scheme:          %s\n", parsedURL.Scheme)
	fmt.Println()

	fmt.Println("REQUEST OPTIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Timeout:           %.1fs\n", config.Timeout)
	fmt.Printf("  Follow Redirects:  %t\n", config.FollowRedirects)
	fmt.Printf("  Max Redirects:     %d\n", config.MaxRedirects)
	fmt.Printf("  Verify SSL:        %t\n", config.VerifySSL)
	if config.Proxy != "" {
		fmt.Printf("  Proxy:             %s\n", config.Proxy)
	}
	fmt.Println()

	if len(config.Headers) > 0 {
		fmt.Println("CUSTOM HEADERS")
		fmt.Println(strings.Repeat("-", 40))
		for name, value := range config.Headers {
			display := value
			if len(display) > 50 {
				display = display[:50] + "..."
			}
			fmt.Printf("  %s: %s\n", name, display)
		}
		fmt.Println()
	}

	if config.Data != "" {
		fmt.Println("REQUEST BODY")
		fmt.Println(strings.Repeat("-", 40))
		preview := config.Data
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		fmt.Printf("  %s\n", preview)
		fmt.Printf("  Length: %d bytes\n", len(config.Data))
		fmt.Println()
	}

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	scheme := "HTTP"
	if parsedURL.Scheme == "https" {
		scheme = "HTTPS"
	}
	fmt.Printf("  1. Establish %s connection to %s\n", scheme, parsedURL.Host)
	fmt.Printf("  2. Send %s request to %s\n", config.Method, path)
	if config.Data != "" {
		fmt.Printf("  3. Include request body (%d bytes)\n", len(config.Data))
	}
	fmt.Println("  4. Receive and parse response")
	if config.FollowRedirects {
		fmt.Printf("  5. Follow up to %d redirects if returned\n", config.MaxRedirects)
	}
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

// headerFlags allows multiple -H flags
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func parseHeaders(headerList []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range headerList {
		if strings.Contains(h, ":") {
			parts := strings.SplitN(h, ":", 2)
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func main() {
	// Command line flags
	var headers headerFlags

	method := flag.String("X", "GET", "HTTP method")
	flag.Var(&headers, "H", "Custom header (format: 'Name: Value')")
	data := flag.String("d", "", "Request body data")
	dataFile := flag.String("f", "", "File containing request body")
	followRedirects := flag.Bool("L", false, "Follow redirects")
	maxRedirects := flag.Int("max-redirects", 5, "Maximum redirects to follow")
	insecure := flag.Bool("k", false, "Skip SSL verification")
	timeout := flag.Float64("timeout", DefaultTimeout, "Request timeout")
	noHeaders := flag.Bool("no-headers", false, "Don't show response headers")
	noBody := flag.Bool("no-body", false, "Don't show response body")
	raw := flag.Bool("r", false, "Raw output (body only, no formatting)")
	planMode := flag.Bool("plan", false, "Show execution plan without sending request")
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFile := flag.String("o", "", "Save response body to file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `HTTP Request Tool - Flexible HTTP Client

Usage: %s [options] <url>

Examples:
  %s http://target.com --plan
  %s http://target.com/api -X POST -d '{"key":"value"}'
  %s https://target.com -H "Authorization: Bearer token"

WARNING: Use only for authorized security testing.

Options:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("[!] URL argument required")
		flag.Usage()
		os.Exit(1)
	}

	targetURL := flag.Arg(0)

	// Build configuration
	config := &RequestConfig{
		URL:             targetURL,
		Method:          strings.ToUpper(*method),
		Headers:         parseHeaders(headers),
		Data:            *data,
		DataFile:        *dataFile,
		Timeout:         *timeout,
		FollowRedirects: *followRedirects,
		MaxRedirects:    *maxRedirects,
		VerifySSL:       !*insecure,
		ShowHeaders:     !*noHeaders,
		ShowBody:        !*noBody,
		RawOutput:       *raw,
		Verbose:         *verbose,
		PlanMode:        *planMode,
		OutputFile:      *outputFile,
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute request
	if !config.RawOutput {
		fmt.Printf("[*] %s %s\n", config.Method, config.URL)
	}

	client, err := NewHTTPClient(config)
	if err != nil {
		fmt.Printf("[!] Error parsing URL: %v\n", err)
		os.Exit(1)
	}

	response, err := client.Request()
	if err != nil {
		fmt.Printf("[!] Request failed: %v\n", err)
		os.Exit(1)
	}

	if config.RawOutput {
		// Raw body output
		os.Stdout.Write(response.Body)
		os.Exit(0)
	}

	// Formatted output
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("HTTP/%s\n", response.StatusReason)
	fmt.Printf("Response Time: %.3fs\n", response.ResponseTime)
	fmt.Println(strings.Repeat("=", 60))

	if len(response.Redirects) > 0 {
		fmt.Printf("\nRedirects: %s\n", strings.Join(response.Redirects, " -> "))
	}

	if config.ShowHeaders {
		fmt.Println("\nRESPONSE HEADERS:")
		fmt.Println(strings.Repeat("-", 40))
		for name, value := range response.Headers {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

	if response.SSLInfo != nil {
		fmt.Println("\nSSL CERTIFICATE:")
		fmt.Println(strings.Repeat("-", 40))
		if response.SSLInfo.Subject != nil {
			fmt.Printf("  Subject: %v\n", response.SSLInfo.Subject)
		}
		if response.SSLInfo.Issuer != nil {
			fmt.Printf("  Issuer: %v\n", response.SSLInfo.Issuer)
		}
		if response.SSLInfo.NotAfter != "" {
			fmt.Printf("  Expires: %s\n", response.SSLInfo.NotAfter)
		}
	}

	if config.ShowBody && len(response.Body) > 0 {
		fmt.Printf("\nRESPONSE BODY (%d bytes):\n", len(response.Body))
		fmt.Println(strings.Repeat("-", 40))

		bodyStr := string(response.Body)
		// Truncate long bodies
		if len(bodyStr) > 5000 {
			fmt.Println(bodyStr[:5000])
			fmt.Printf("\n... truncated (%d total bytes)\n", len(bodyStr))
		} else {
			fmt.Println(bodyStr)
		}
	}

	// Save to file if requested
	if config.OutputFile != "" {
		err := os.WriteFile(config.OutputFile, response.Body, 0644)
		if err != nil {
			fmt.Printf("[!] Error saving to file: %v\n", err)
		} else {
			fmt.Printf("\n[*] Response saved to %s\n", config.OutputFile)
		}
	}

	os.Exit(0)
}
