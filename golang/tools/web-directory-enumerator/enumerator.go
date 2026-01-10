// enumerator.go - Go port of web-directory-enumerator/tool.py
// Stealthy Web Content Discovery Tool
//
// Build instructions:
//   go build -o enumerator enumerator.go
//
// Usage:
//   ./enumerator <url> [flags]
//   ./enumerator http://target.com --plan
//   ./enumerator http://target.com -w wordlist.txt -x php,html
//
// WARNING: This tool is intended for authorized security assessments only.
// Unauthorized web scanning may violate laws and regulations.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
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
	DefaultTimeout  = 10.0
	DefaultThreads  = 10
	DefaultDelayMin = 0.0
	DefaultDelayMax = 0.1
)

// Default wordlist entries
var DefaultWordlist = []string{
	"admin", "administrator", "login", "wp-admin", "wp-login.php",
	"dashboard", "config", "backup", "test", "dev", "api", "v1", "v2",
	"robots.txt", "sitemap.xml", ".git", ".svn", ".htaccess", ".env",
	"phpinfo.php", "info.php", "server-status", "wp-config.php",
	"web.config", "config.php", "database", "db", "sql", "mysql",
	"phpmyadmin", "pma", "adminer", "console", "shell", "cmd",
	"uploads", "upload", "files", "images", "img", "assets", "static",
	"css", "js", "javascript", "include", "includes", "lib", "libs",
	"vendor", "node_modules", "packages", "temp", "tmp", "cache",
	"log", "logs", "debug", "error", "errors", "private", "secret",
	"hidden", "internal", "manage", "management", "portal", "user",
	"users", "member", "members", "account", "accounts", "profile",
	"register", "signup", "signin", "auth", "authentication", "oauth",
	"token", "session", "api-docs", "swagger", "graphql", "rest",
}

// Common extensions
var CommonExtensions = []string{
	"", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".txt",
	".xml", ".json", ".bak", ".old", ".orig", ".backup",
}

// =============================================================================
// Data Structures
// =============================================================================

// StatusCategory represents HTTP response categories
type StatusCategory string

const (
	StatusSuccess     StatusCategory = "success"
	StatusRedirect    StatusCategory = "redirect"
	StatusClientError StatusCategory = "client_error"
	StatusServerError StatusCategory = "server_error"
)

// DirectoryResult represents the result of a directory/file check
type DirectoryResult struct {
	URL           string  `json:"url"`
	Path          string  `json:"path"`
	StatusCode    int     `json:"status_code"`
	ContentLength int     `json:"content_length"`
	RedirectURL   string  `json:"redirect_url,omitempty"`
	ResponseTime  float64 `json:"response_time,omitempty"`
	Title         string  `json:"title,omitempty"`
	Interesting   bool    `json:"interesting"`
	Timestamp     string  `json:"timestamp"`
}

// GetStatusCategory returns the category of the status code
func (r *DirectoryResult) GetStatusCategory() StatusCategory {
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		return StatusSuccess
	} else if r.StatusCode >= 300 && r.StatusCode < 400 {
		return StatusRedirect
	} else if r.StatusCode >= 400 && r.StatusCode < 500 {
		return StatusClientError
	}
	return StatusServerError
}

// ToDict returns a map representation for JSON serialization
func (r *DirectoryResult) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"url":            r.URL,
		"path":           r.Path,
		"status_code":    r.StatusCode,
		"content_length": r.ContentLength,
		"interesting":    r.Interesting,
		"timestamp":      r.Timestamp,
	}
	if r.RedirectURL != "" {
		result["redirect_url"] = r.RedirectURL
	}
	if r.ResponseTime > 0 {
		result["response_time"] = r.ResponseTime
	}
	if r.Title != "" {
		result["title"] = r.Title
	}
	return result
}

// EnumConfig holds configuration for directory enumeration
type EnumConfig struct {
	TargetURL       string
	Wordlist        []string
	Extensions      []string
	Timeout         float64
	Threads         int
	DelayMin        float64
	DelayMax        float64
	FollowRedirects bool
	StatusCodes     []int
	ExcludeCodes    []int
	ExcludeLengths  []int
	UserAgent       string
	Headers         map[string]string
	Cookies         map[string]string
	Recursive       bool
	RecursiveDepth  int
	Verbose         bool
	PlanMode        bool
	OutputFile      string
}

// =============================================================================
// HTTP Client
// =============================================================================

// HTTPClient is a lightweight HTTP client for directory enumeration
type HTTPClient struct {
	Config   *EnumConfig
	scheme   string
	host     string
	basePath string
	port     int
	useSSL   bool
	client   *http.Client
}

// NewHTTPClient creates a new HTTPClient instance
func NewHTTPClient(config *EnumConfig) *HTTPClient {
	hc := &HTTPClient{Config: config}
	hc.parseTarget()

	// Create HTTP client with custom transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	hc.client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout * float64(time.Second)),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return hc
}

// parseTarget parses the target URL into components
func (hc *HTTPClient) parseTarget() {
	parsed, err := url.Parse(hc.Config.TargetURL)
	if err != nil {
		// Try to add scheme
		if !strings.HasPrefix(hc.Config.TargetURL, "http") {
			hc.Config.TargetURL = "http://" + hc.Config.TargetURL
			parsed, _ = url.Parse(hc.Config.TargetURL)
		}
	}

	hc.scheme = parsed.Scheme
	if hc.scheme == "" {
		hc.scheme = "http"
	}

	hc.host = parsed.Hostname()
	hc.basePath = parsed.Path
	hc.useSSL = hc.scheme == "https"

	// Handle port
	portStr := parsed.Port()
	if portStr != "" {
		hc.port, _ = strconv.Atoi(portStr)
	} else if hc.useSSL {
		hc.port = 443
	} else {
		hc.port = 80
	}
}

// Request makes an HTTP request to a path
func (hc *HTTPClient) Request(path string, method string) *DirectoryResult {
	fullPath := strings.TrimRight(hc.basePath, "/") + "/" + strings.TrimLeft(path, "/")
	fullURL := fmt.Sprintf("%s://%s:%d%s", hc.scheme, hc.host, hc.port, fullPath)

	startTime := time.Now()

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil
	}

	// Set headers
	req.Header.Set("Host", hc.host)
	req.Header.Set("User-Agent", hc.Config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	// Add custom headers
	for key, value := range hc.Config.Headers {
		req.Header.Set(key, value)
	}

	// Add cookies
	if len(hc.Config.Cookies) > 0 {
		var cookieParts []string
		for key, value := range hc.Config.Cookies {
			cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", key, value))
		}
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		if hc.Config.Verbose {
			fmt.Printf("[!] Request error for %s: %v\n", path, err)
		}
		return nil
	}
	defer resp.Body.Close()

	responseTime := time.Since(startTime).Seconds()

	// Read response body (limit size)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		bodyBytes = []byte{}
	}
	contentLength := len(bodyBytes)

	// Extract title if HTML
	var title string
	bodyLower := strings.ToLower(string(bodyBytes))
	if strings.Contains(bodyLower, "<title") {
		titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
		if match := titleRegex.FindStringSubmatch(string(bodyBytes)); len(match) > 1 {
			title = strings.TrimSpace(match[1])
		}
	}

	// Get redirect URL
	var redirectURL string
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		redirectURL = resp.Header.Get("Location")
	}

	return &DirectoryResult{
		URL:           fullURL,
		Path:          path,
		StatusCode:    resp.StatusCode,
		ContentLength: contentLength,
		RedirectURL:   redirectURL,
		ResponseTime:  responseTime,
		Title:         title,
		Timestamp:     time.Now().Format(time.RFC3339),
	}
}

// =============================================================================
// Directory Enumerator Core
// =============================================================================

// DirectoryEnumerator is the main enumeration engine
type DirectoryEnumerator struct {
	Config         *EnumConfig
	Client         *HTTPClient
	Results        []*DirectoryResult
	stopEvent      chan struct{}
	mutex          sync.Mutex
	foundDirs      map[string]bool
	baselineLength int
}

// NewDirectoryEnumerator creates a new DirectoryEnumerator instance
func NewDirectoryEnumerator(config *EnumConfig) *DirectoryEnumerator {
	return &DirectoryEnumerator{
		Config:    config,
		Client:    NewHTTPClient(config),
		Results:   []*DirectoryResult{},
		stopEvent: make(chan struct{}),
		foundDirs: make(map[string]bool),
	}
}

// applyJitter applies random delay for stealth
func (de *DirectoryEnumerator) applyJitter() {
	if de.Config.DelayMax > 0 {
		delay := de.Config.DelayMin + rand.Float64()*(de.Config.DelayMax-de.Config.DelayMin)
		time.Sleep(time.Duration(delay * float64(time.Second)))
	}
}

// calibrateBaseline determines baseline 404 response characteristics
func (de *DirectoryEnumerator) calibrateBaseline() {
	randomPaths := []string{
		fmt.Sprintf("nonexistent_%d", rand.Intn(90000)+10000),
		fmt.Sprintf("definitely_not_here_%d", rand.Intn(90000)+10000),
	}

	var lengths []int
	for _, path := range randomPaths {
		result := de.Client.Request(path, "GET")
		if result != nil {
			lengths = append(lengths, result.ContentLength)
		}
	}

	if len(lengths) > 0 {
		sum := 0
		for _, l := range lengths {
			sum += l
		}
		de.baselineLength = sum / len(lengths)
	}
}

// isInteresting determines if result is interesting (not a false positive)
func (de *DirectoryEnumerator) isInteresting(result *DirectoryResult) bool {
	// Check against explicit exclude codes
	for _, code := range de.Config.ExcludeCodes {
		if result.StatusCode == code {
			return false
		}
	}

	// Check against exclude lengths
	for _, length := range de.Config.ExcludeLengths {
		if result.ContentLength == length {
			return false
		}
	}

	// Check against baseline (soft 404 detection)
	if de.baselineLength > 0 {
		variance := float64(de.baselineLength) * 0.05
		diff := float64(result.ContentLength - de.baselineLength)
		if diff < 0 {
			diff = -diff
		}
		if diff <= variance && result.StatusCode == 200 {
			return false
		}
	}

	// Check if status code is in accepted list
	for _, code := range de.Config.StatusCodes {
		if result.StatusCode == code {
			return true
		}
	}

	return false
}

// generatePaths generates all paths to test
func (de *DirectoryEnumerator) generatePaths() []string {
	var paths []string

	for _, word := range de.Config.Wordlist {
		word = strings.TrimSpace(word)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}

		// Add base word
		paths = append(paths, word)

		// Add with extensions
		for _, ext := range de.Config.Extensions {
			if ext != "" && !strings.HasSuffix(word, ext) {
				paths = append(paths, word+ext)
			}
		}
	}

	return paths
}

// checkPath checks a single path
func (de *DirectoryEnumerator) checkPath(path string) *DirectoryResult {
	select {
	case <-de.stopEvent:
		return nil
	default:
	}

	de.applyJitter()

	result := de.Client.Request(path, "GET")

	if result != nil && de.isInteresting(result) {
		result.Interesting = true
		return result
	}

	return nil
}

// Enumerate executes directory enumeration
func (de *DirectoryEnumerator) Enumerate() []*DirectoryResult {
	// Calibrate baseline
	if de.Config.Verbose {
		fmt.Println("[*] Calibrating baseline response...")
	}
	de.calibrateBaseline()

	// Generate paths
	paths := de.generatePaths()

	if de.Config.Verbose {
		fmt.Printf("[*] Testing %d paths against %s\n", len(paths), de.Config.TargetURL)
		if de.baselineLength > 0 {
			fmt.Printf("[*] Baseline 404 length: %d bytes\n", de.baselineLength)
		}
	}

	// Create work channel and results channel
	jobs := make(chan string, len(paths))
	results := make(chan *DirectoryResult, len(paths))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < de.Config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				result := de.checkPath(path)
				if result != nil {
					results <- result
				}
			}
		}()
	}

	// Send jobs
	for _, path := range paths {
		jobs <- path
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		de.mutex.Lock()
		de.Results = append(de.Results, result)
		if de.Config.Verbose {
			statusStr := fmt.Sprintf("%d", result.StatusCode)
			if result.RedirectURL != "" {
				statusStr += fmt.Sprintf(" -> %s", result.RedirectURL)
			}
			fmt.Printf("[+] %s (%s) [%db]\n", result.Path, statusStr, result.ContentLength)
		}

		// Track found directories for recursive scan
		if (result.StatusCode == 200 || result.StatusCode == 301 || result.StatusCode == 302) && strings.HasSuffix(result.Path, "/") {
			de.foundDirs[result.Path] = true
		}
		de.mutex.Unlock()
	}

	return de.Results
}

// Stop signals the enumerator to stop
func (de *DirectoryEnumerator) Stop() {
	close(de.stopEvent)
}

// =============================================================================
// Planning Mode
// =============================================================================

func printPlan(config *EnumConfig) {
	var paths []string
	for _, word := range config.Wordlist {
		word = strings.TrimSpace(word)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		paths = append(paths, word)
		for _, ext := range config.Extensions {
			if ext != "" {
				paths = append(paths, word+ext)
			}
		}
	}

	fmt.Println(`
[PLAN MODE] Tool: web-directory-enumerator
================================================================================
`)

	fmt.Println("TARGET INFORMATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Target URL:      %s\n", config.TargetURL)

	parsed, _ := url.Parse(config.TargetURL)
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := parsed.Host
	if host == "" {
		host = config.TargetURL
	}
	fmt.Printf("  Scheme:          %s\n", scheme)
	fmt.Printf("  Host:            %s\n", host)
	fmt.Println()

	fmt.Println("ENUMERATION CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Wordlist Size:   %d words\n", len(config.Wordlist))
	if len(config.Extensions) > 0 {
		fmt.Printf("  Extensions:      %v\n", config.Extensions)
	} else {
		fmt.Println("  Extensions:      None")
	}
	fmt.Printf("  Total Paths:     %d\n", len(paths))
	fmt.Printf("  Threads:         %d\n", config.Threads)
	fmt.Printf("  Timeout:         %.1fs\n", config.Timeout)
	fmt.Printf("  Delay Range:     %.2fs - %.2fs\n", config.DelayMin, config.DelayMax)
	fmt.Printf("  Follow Redirects:%t\n", config.FollowRedirects)
	fmt.Printf("  Status Codes:    %v\n", config.StatusCodes)
	fmt.Println()

	fmt.Println("REQUEST CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	if len(config.UserAgent) > 50 {
		fmt.Printf("  User-Agent:      %s...\n", config.UserAgent[:50])
	} else {
		fmt.Printf("  User-Agent:      %s\n", config.UserAgent)
	}
	if len(config.Headers) > 0 {
		fmt.Printf("  Custom Headers:  %d\n", len(config.Headers))
	}
	if len(config.Cookies) > 0 {
		fmt.Printf("  Cookies:         %d\n", len(config.Cookies))
	}
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Calibrate baseline response (404 detection)")
	fmt.Println("  2. Generate path list from wordlist + extensions")
	fmt.Printf("  3. Initialize %d worker goroutines\n", config.Threads)
	fmt.Println("  4. For each path:")
	fmt.Printf("     - Apply random delay (%.2fs - %.2fs)\n", config.DelayMin, config.DelayMax)
	fmt.Println("     - Send HTTP GET request")
	fmt.Println("     - Analyze response code and content length")
	fmt.Println("     - Filter against baseline and exclude rules")
	fmt.Println("  5. Aggregate interesting results")
	fmt.Println()

	fmt.Println("PATH PREVIEW (first 15)")
	fmt.Println(strings.Repeat("-", 40))
	previewCount := 15
	if len(paths) < previewCount {
		previewCount = len(paths)
	}
	for i := 0; i < previewCount; i++ {
		fmt.Printf("  - /%s\n", paths[i])
	}
	if len(paths) > 15 {
		fmt.Printf("  ... and %d more\n", len(paths)-15)
	}
	fmt.Println()

	// Time estimate
	avgDelay := (config.DelayMin + config.DelayMax) / 2
	estimatedTime := float64(len(paths)) * (config.Timeout + avgDelay) / float64(config.Threads)
	fmt.Println("TIME ESTIMATE")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Worst case:      %.0f seconds\n", estimatedTime)
	fmt.Printf("  Typical:         %.0f seconds\n", estimatedTime*0.2)
	fmt.Println()

	fmt.Println("RISK ASSESSMENT")
	fmt.Println(strings.Repeat("-", 40))
	var riskFactors []string

	if len(paths) > 10000 {
		riskFactors = append(riskFactors, "Large wordlist generates high traffic")
	}
	if config.DelayMax < 0.1 {
		riskFactors = append(riskFactors, "Low delay may trigger WAF/rate limiting")
	}
	if config.Threads > 20 {
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
	for _, factor := range riskFactors {
		fmt.Printf("    - %s\n", factor)
	}
	fmt.Println()

	fmt.Println("DETECTION VECTORS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - Web server access logs will record all requests")
	fmt.Println("  - WAF/IDS may detect enumeration patterns")
	fmt.Println("  - Rate limiting may slow or block requests")
	fmt.Println("  - 404 response analysis may reveal scanning")
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
			return append([]string{}, DefaultWordlist...)
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
	return append([]string{}, DefaultWordlist...)
}

func parseHeaders(headerList []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range headerList {
		if idx := strings.Index(h, ":"); idx != -1 {
			name := strings.TrimSpace(h[:idx])
			value := strings.TrimSpace(h[idx+1:])
			headers[name] = value
		}
	}
	return headers
}

func parseCookies(cookieStr string) map[string]string {
	cookies := make(map[string]string)
	if cookieStr != "" {
		for _, pair := range strings.Split(cookieStr, ";") {
			if idx := strings.Index(pair, "="); idx != -1 {
				name := strings.TrimSpace(pair[:idx])
				value := strings.TrimSpace(pair[idx+1:])
				cookies[name] = value
			}
		}
	}
	return cookies
}

func main() {
	rand.Seed(time.Now().UnixNano())

	wordlistFlag := flag.String("w", "", "Path to wordlist file (uses built-in if not specified)")
	wordlistFlag2 := flag.String("wordlist", "", "Path to wordlist file")
	extensionsFlag := flag.String("x", "", "Comma-separated extensions to append (e.g., php,html,txt)")
	extensionsFlag2 := flag.String("extensions", "", "Comma-separated extensions to append")
	threadsFlag := flag.Int("t", DefaultThreads, "Number of concurrent threads")
	threadsFlag2 := flag.Int("threads", DefaultThreads, "Number of concurrent threads")
	timeoutFlag := flag.Float64("timeout", DefaultTimeout, "Request timeout in seconds")
	delayMinFlag := flag.Float64("delay-min", DefaultDelayMin, "Minimum delay between requests")
	delayMaxFlag := flag.Float64("delay-max", DefaultDelayMax, "Maximum delay between requests")
	statusCodesFlag := flag.String("s", "", "Comma-separated status codes to report (default: 200,201,204,301,302,307,401,403)")
	statusCodesFlag2 := flag.String("status-codes", "", "Comma-separated status codes to report")
	excludeCodesFlag := flag.String("e", "", "Comma-separated status codes to exclude")
	excludeCodesFlag2 := flag.String("exclude-codes", "", "Comma-separated status codes to exclude")
	excludeLengthFlag := flag.String("exclude-length", "", "Comma-separated content lengths to exclude")
	userAgentFlag := flag.String("a", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Custom User-Agent string")
	userAgentFlag2 := flag.String("user-agent", "", "Custom User-Agent string")
	cookieFlag := flag.String("c", "", "Cookies to include (format: 'name=value; name2=value2')")
	cookieFlag2 := flag.String("cookie", "", "Cookies to include")
	planFlag := flag.Bool("p", false, "Show execution plan without scanning")
	planFlag2 := flag.Bool("plan", false, "Show execution plan without scanning")
	verboseFlag := flag.Bool("v", false, "Enable verbose output")
	verboseFlag2 := flag.Bool("verbose", false, "Enable verbose output")
	outputFlag := flag.String("o", "", "Output file for results (JSON format)")
	outputFlag2 := flag.String("output", "", "Output file for results (JSON format)")

	// Custom header flag that can be used multiple times
	var headerFlags []string
	flag.Func("H", "Custom header (format: 'Name: Value')", func(s string) error {
		headerFlags = append(headerFlags, s)
		return nil
	})
	flag.Func("header", "Custom header (format: 'Name: Value')", func(s string) error {
		headerFlags = append(headerFlags, s)
		return nil
	})

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Web Directory Enumerator - Content Discovery Tool

Usage:
  %s [flags] url

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  enumerator http://target.com --plan
  enumerator http://target.com -w wordlist.txt -x php,html
  enumerator https://target.com -t 20 --delay-max 1

WARNING: Use only for authorized security testing.`)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No URL specified")
		flag.Usage()
		os.Exit(1)
	}
	targetURL := args[0]

	// Load wordlist
	wordlistPath := *wordlistFlag
	if *wordlistFlag2 != "" {
		wordlistPath = *wordlistFlag2
	}
	wordlist := loadWordlist(wordlistPath)

	// Parse extensions
	var extensions []string
	extStr := *extensionsFlag
	if *extensionsFlag2 != "" {
		extStr = *extensionsFlag2
	}
	if extStr != "" {
		for _, ext := range strings.Split(extStr, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" && !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions = append(extensions, ext)
		}
	}

	// Parse status codes
	statusCodes := []int{200, 201, 204, 301, 302, 307, 401, 403}
	statusStr := *statusCodesFlag
	if *statusCodesFlag2 != "" {
		statusStr = *statusCodesFlag2
	}
	if statusStr != "" {
		statusCodes = []int{}
		for _, codeStr := range strings.Split(statusStr, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
				statusCodes = append(statusCodes, code)
			}
		}
	}

	// Parse exclude codes
	var excludeCodes []int
	excludeStr := *excludeCodesFlag
	if *excludeCodesFlag2 != "" {
		excludeStr = *excludeCodesFlag2
	}
	if excludeStr != "" {
		for _, codeStr := range strings.Split(excludeStr, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
				excludeCodes = append(excludeCodes, code)
			}
		}
	}

	// Parse exclude lengths
	var excludeLengths []int
	if *excludeLengthFlag != "" {
		for _, lenStr := range strings.Split(*excludeLengthFlag, ",") {
			if length, err := strconv.Atoi(strings.TrimSpace(lenStr)); err == nil {
				excludeLengths = append(excludeLengths, length)
			}
		}
	}

	threads := *threadsFlag
	if *threadsFlag2 != DefaultThreads {
		threads = *threadsFlag2
	}

	userAgent := *userAgentFlag
	if *userAgentFlag2 != "" {
		userAgent = *userAgentFlag2
	}

	cookieStr := *cookieFlag
	if *cookieFlag2 != "" {
		cookieStr = *cookieFlag2
	}

	output := *outputFlag
	if *outputFlag2 != "" {
		output = *outputFlag2
	}

	config := &EnumConfig{
		TargetURL:       targetURL,
		Wordlist:        wordlist,
		Extensions:      extensions,
		Timeout:         *timeoutFlag,
		Threads:         threads,
		DelayMin:        *delayMinFlag,
		DelayMax:        *delayMaxFlag,
		FollowRedirects: false,
		StatusCodes:     statusCodes,
		ExcludeCodes:    excludeCodes,
		ExcludeLengths:  excludeLengths,
		UserAgent:       userAgent,
		Headers:         parseHeaders(headerFlags),
		Cookies:         parseCookies(cookieStr),
		Recursive:       false,
		RecursiveDepth:  2,
		Verbose:         *verboseFlag || *verboseFlag2,
		PlanMode:        *planFlag || *planFlag2,
		OutputFile:      output,
	}

	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute enumeration
	fmt.Println("[*] Web Directory Enumerator starting...")
	fmt.Printf("[*] Target: %s\n", config.TargetURL)
	fmt.Printf("[*] Wordlist: %d entries\n", len(config.Wordlist))
	if len(config.Extensions) > 0 {
		fmt.Printf("[*] Extensions: %v\n", config.Extensions)
	} else {
		fmt.Println("[*] Extensions: None")
	}

	enumerator := NewDirectoryEnumerator(config)
	results := enumerator.Enumerate()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("ENUMERATION RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total requests:   %d\n", len(enumerator.generatePaths()))
	fmt.Printf("Interesting:      %d\n", len(results))
	fmt.Println()

	if len(results) > 0 {
		fmt.Printf("%-8s %-10s %-40s %-20s\n", "STATUS", "SIZE", "PATH", "REDIRECT")
		fmt.Println(strings.Repeat("-", 70))

		// Sort by status code
		sort.Slice(results, func(i, j int) bool {
			return results[i].StatusCode < results[j].StatusCode
		})

		for _, result := range results {
			redirect := "-"
			if result.RedirectURL != "" && len(result.RedirectURL) > 20 {
				redirect = result.RedirectURL[:20]
			} else if result.RedirectURL != "" {
				redirect = result.RedirectURL
			}
			path := result.Path
			if len(path) > 40 {
				path = path[:37] + "..."
			}
			fmt.Printf("%-8d %-10d %-40s %-20s\n",
				result.StatusCode, result.ContentLength, path, redirect)
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := map[string]interface{}{
			"target":    config.TargetURL,
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
