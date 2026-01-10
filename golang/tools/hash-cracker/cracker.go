// Package main implements a Hash Cracker tool for multi-algorithm hash cracking.
// Converted from Python to Go - hash-cracker tool
//
// WARNING: This tool is intended for authorized security assessments only.
// Only crack hashes you have explicit permission to test.
//
// Build: go build -o hash-cracker cracker.go
// Usage: ./hash-cracker 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
//        ./hash-cracker --file hashes.txt -w rockyou.txt --type md5
//        ./hash-cracker 5f4dcc3b5aa765d61d8327deb882cf99 --bruteforce -c alphanumeric
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// =============================================================================
// Configuration and Constants
// =============================================================================

const DefaultThreads = 4

// HashType represents supported hash algorithms
type HashType string

const (
	HashTypeMD5    HashType = "md5"
	HashTypeSHA1   HashType = "sha1"
	HashTypeSHA256 HashType = "sha256"
	HashTypeSHA512 HashType = "sha512"
	HashTypeNTLM   HashType = "ntlm"
)

// Charsets for bruteforce attacks
var Charsets = map[string]string{
	"lowercase":    "abcdefghijklmnopqrstuvwxyz",
	"uppercase":    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"digits":       "0123456789",
	"alpha":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"all":          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

// =============================================================================
// Data Structures
// =============================================================================

// HashTarget represents a hash to crack
type HashTarget struct {
	HashValue string    `json:"hash"`
	HashType  *HashType `json:"type,omitempty"`
	Username  *string   `json:"username,omitempty"`
	Cracked   bool      `json:"cracked"`
	Plaintext *string   `json:"plaintext,omitempty"`
}

// CrackConfig holds configuration for hash cracking
type CrackConfig struct {
	Hashes     []*HashTarget
	Wordlist   string
	HashType   *HashType
	Threads    int
	Rules      []string
	MinLength  int
	MaxLength  int
	Charset    string
	Verbose    bool
	PlanMode   bool
	OutputFile string
	BruteForce bool
}

// CrackResult holds the result of cracking operation
type CrackResult struct {
	TotalHashes  int            `json:"total_hashes"`
	CrackedCount int            `json:"cracked_count"`
	Attempts     int64          `json:"attempts"`
	Duration     float64        `json:"duration"`
	Rate         float64        `json:"rate"`
	Results      []*HashTarget  `json:"results"`
}

// =============================================================================
// Hash Functions
// =============================================================================

// HashEngine provides hash computation for multiple algorithms
type HashEngine struct{}

// MD5 computes MD5 hash
func (h *HashEngine) MD5(plaintext string) string {
	hash := md5.Sum([]byte(plaintext))
	return hex.EncodeToString(hash[:])
}

// SHA1 computes SHA1 hash
func (h *HashEngine) SHA1(plaintext string) string {
	hash := sha1.Sum([]byte(plaintext))
	return hex.EncodeToString(hash[:])
}

// SHA256 computes SHA256 hash
func (h *HashEngine) SHA256(plaintext string) string {
	hash := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(hash[:])
}

// SHA512 computes SHA512 hash
func (h *HashEngine) SHA512(plaintext string) string {
	hash := sha512.Sum512([]byte(plaintext))
	return hex.EncodeToString(hash[:])
}

// NTLM computes NTLM hash (MD4 of UTF-16LE encoded string)
func (h *HashEngine) NTLM(plaintext string) string {
	// Convert to UTF-16LE
	utf16Encoded := utf16.Encode([]rune(plaintext))
	data := make([]byte, len(utf16Encoded)*2)
	for i, r := range utf16Encoded {
		data[i*2] = byte(r)
		data[i*2+1] = byte(r >> 8)
	}

	// MD4 hash - implementing simple MD4 for NTLM
	return md4Hash(data)
}

// md4Hash implements MD4 hashing for NTLM
// Note: This is a simplified implementation
func md4Hash(data []byte) string {
	// MD4 implementation
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xefcdab89
	var h2 uint32 = 0x98badcfe
	var h3 uint32 = 0x10325476

	// Pre-processing: adding padding bits
	msgLen := len(data)
	data = append(data, 0x80)
	for (len(data)+8)%64 != 0 {
		data = append(data, 0)
	}

	// Append length in bits
	bitLen := uint64(msgLen) * 8
	for i := 0; i < 8; i++ {
		data = append(data, byte(bitLen>>(uint(i)*8)))
	}

	// Process each 64-byte chunk
	for i := 0; i < len(data); i += 64 {
		chunk := data[i : i+64]

		// Break chunk into 16 32-bit words
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = uint32(chunk[j*4]) | uint32(chunk[j*4+1])<<8 | uint32(chunk[j*4+2])<<16 | uint32(chunk[j*4+3])<<24
		}

		a, b, c, d := h0, h1, h2, h3

		// Round 1
		for i := 0; i < 16; i++ {
			var k int
			switch i % 4 {
			case 0:
				k = i
			case 1:
				k = i
			case 2:
				k = i
			case 3:
				k = i
			}
			f := (b & c) | (^b & d)
			s := []uint{3, 7, 11, 19}[i%4]
			a = rotateLeft(a+f+x[k], s)
			a, b, c, d = d, a, b, c
		}

		// Round 2
		order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i := 0; i < 16; i++ {
			f := (b & c) | (b & d) | (c & d)
			s := []uint{3, 5, 9, 13}[i%4]
			a = rotateLeft(a+f+x[order2[i]]+0x5a827999, s)
			a, b, c, d = d, a, b, c
		}

		// Round 3
		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i := 0; i < 16; i++ {
			f := b ^ c ^ d
			s := []uint{3, 9, 11, 15}[i%4]
			a = rotateLeft(a+f+x[order3[i]]+0x6ed9eba1, s)
			a, b, c, d = d, a, b, c
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
	}

	// Produce the final hash value (little-endian)
	result := make([]byte, 16)
	result[0], result[1], result[2], result[3] = byte(h0), byte(h0>>8), byte(h0>>16), byte(h0>>24)
	result[4], result[5], result[6], result[7] = byte(h1), byte(h1>>8), byte(h1>>16), byte(h1>>24)
	result[8], result[9], result[10], result[11] = byte(h2), byte(h2>>8), byte(h2>>16), byte(h2>>24)
	result[12], result[13], result[14], result[15] = byte(h3), byte(h3>>8), byte(h3>>16), byte(h3>>24)

	return hex.EncodeToString(result)
}

func rotateLeft(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// GetHasher returns the appropriate hash function for a type
func (h *HashEngine) GetHasher(hashType HashType) func(string) string {
	switch hashType {
	case HashTypeMD5:
		return h.MD5
	case HashTypeSHA1:
		return h.SHA1
	case HashTypeSHA256:
		return h.SHA256
	case HashTypeSHA512:
		return h.SHA512
	case HashTypeNTLM:
		return h.NTLM
	default:
		return h.MD5
	}
}

// =============================================================================
// Hash Type Detection
// =============================================================================

// DetectHashType attempts to detect hash type based on length and format
func DetectHashType(hashValue string) *HashType {
	hashValue = strings.ToLower(strings.TrimSpace(hashValue))
	length := len(hashValue)

	// Check if valid hex
	for _, c := range hashValue {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil
		}
	}

	// Detect by length
	var ht HashType
	switch length {
	case 32:
		ht = HashTypeMD5 // Could also be NTLM
	case 40:
		ht = HashTypeSHA1
	case 64:
		ht = HashTypeSHA256
	case 128:
		ht = HashTypeSHA512
	default:
		return nil
	}
	return &ht
}

// =============================================================================
// Word Generation
// =============================================================================

// WordGenerator generates candidate passwords
type WordGenerator struct {
	Config  *CrackConfig
	Charset string
}

// NewWordGenerator creates a new word generator
func NewWordGenerator(config *CrackConfig) *WordGenerator {
	charset, ok := Charsets[config.Charset]
	if !ok {
		charset = Charsets["lowercase"]
	}
	return &WordGenerator{
		Config:  config,
		Charset: charset,
	}
}

// FromWordlist generates words from wordlist file
func (w *WordGenerator) FromWordlist() <-chan string {
	ch := make(chan string, 10000)

	go func() {
		defer close(ch)

		if w.Config.Wordlist == "" {
			return
		}

		file, err := os.Open(w.Config.Wordlist)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				ch <- word
				// Apply rules
				for _, mutated := range w.applyRules(word) {
					ch <- mutated
				}
			}
		}
	}()

	return ch
}

// applyRules applies mutation rules to a word
func (w *WordGenerator) applyRules(word string) []string {
	var results []string

	for _, rule := range w.Config.Rules {
		switch rule {
		case "capitalize":
			if len(word) > 0 {
				results = append(results, strings.ToUpper(string(word[0]))+word[1:])
			}
		case "uppercase":
			results = append(results, strings.ToUpper(word))
		case "reverse":
			runes := []rune(word)
			for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
				runes[i], runes[j] = runes[j], runes[i]
			}
			results = append(results, string(runes))
		case "append_numbers":
			for i := 0; i < 100; i++ {
				results = append(results, fmt.Sprintf("%s%d", word, i))
			}
		case "append_year":
			for year := 2020; year <= 2027; year++ {
				results = append(results, fmt.Sprintf("%s%d", word, year))
			}
		case "leet":
			results = append(results, w.leetspeak(word))
		}
	}

	return results
}

// leetspeak converts word to leetspeak
func (w *WordGenerator) leetspeak(word string) string {
	leetMap := map[rune]rune{
		'a': '4', 'A': '4',
		'e': '3', 'E': '3',
		'i': '1', 'I': '1',
		'o': '0', 'O': '0',
		's': '5', 'S': '5',
		't': '7', 'T': '7',
	}

	var result strings.Builder
	for _, c := range word {
		if replacement, ok := leetMap[c]; ok {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// Bruteforce generates words via bruteforce
func (w *WordGenerator) Bruteforce() <-chan string {
	ch := make(chan string, 10000)

	go func() {
		defer close(ch)

		chars := []rune(w.Charset)

		for length := w.Config.MinLength; length <= w.Config.MaxLength; length++ {
			w.generateCombinations(chars, length, ch)
		}
	}()

	return ch
}

// generateCombinations generates all combinations of given length
func (w *WordGenerator) generateCombinations(chars []rune, length int, ch chan<- string) {
	indices := make([]int, length)

	for {
		// Generate current combination
		var sb strings.Builder
		for _, idx := range indices {
			sb.WriteRune(chars[idx])
		}
		ch <- sb.String()

		// Increment indices
		i := length - 1
		for i >= 0 {
			indices[i]++
			if indices[i] < len(chars) {
				break
			}
			indices[i] = 0
			i--
		}

		if i < 0 {
			break
		}
	}
}

// =============================================================================
// Hash Cracker Core
// =============================================================================

// HashCracker coordinates hash cracking operations
type HashCracker struct {
	Config       *CrackConfig
	Result       *CrackResult
	hashLookup   map[string]*HashTarget
	attempts     int64
	stopEvent    chan struct{}
	mu           sync.Mutex
	successFound bool
}

// NewHashCracker creates a new hash cracker
func NewHashCracker(config *CrackConfig) *HashCracker {
	return &HashCracker{
		Config:     config,
		Result:     &CrackResult{Results: make([]*HashTarget, 0)},
		hashLookup: make(map[string]*HashTarget),
		stopEvent:  make(chan struct{}),
	}
}

// prepareHashes builds hash lookup table
func (c *HashCracker) prepareHashes() {
	for _, target := range c.Config.Hashes {
		hashLower := strings.ToLower(target.HashValue)
		c.hashLookup[hashLower] = target

		// Detect type if not specified
		if target.HashType == nil {
			if c.Config.HashType != nil {
				target.HashType = c.Config.HashType
			} else {
				target.HashType = DetectHashType(target.HashValue)
			}
		}
	}
}

// checkWord checks a word against all uncracked hashes
func (c *HashCracker) checkWord(word string, hasher func(string) string) string {
	computed := strings.ToLower(hasher(word))

	if target, ok := c.hashLookup[computed]; ok {
		if !target.Cracked {
			return computed
		}
	}
	return ""
}

// crackWorker worker function to check batches of words
func (c *HashCracker) crackWorker(words <-chan string, results chan<- struct {
	hash      string
	plaintext string
}, hasher func(string) string, wg *sync.WaitGroup) {
	defer wg.Done()

	for word := range words {
		select {
		case <-c.stopEvent:
			return
		default:
		}

		c.mu.Lock()
		if c.successFound && c.Config.Hashes[0].Cracked {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		atomic.AddInt64(&c.attempts, 1)

		crackedHash := c.checkWord(word, hasher)
		if crackedHash != "" {
			results <- struct {
				hash      string
				plaintext string
			}{crackedHash, word}
		}
	}
}

// Crack executes hash cracking
func (c *HashCracker) Crack() *CrackResult {
	c.prepareHashes()
	c.Result.TotalHashes = len(c.Config.Hashes)

	if c.Config.Verbose {
		fmt.Printf("[*] Loaded %d hashes\n", c.Result.TotalHashes)
	}

	startTime := time.Now()

	// Get hasher for first hash type
	engine := &HashEngine{}
	var hashType HashType = HashTypeMD5
	if len(c.Config.Hashes) > 0 && c.Config.Hashes[0].HashType != nil {
		hashType = *c.Config.Hashes[0].HashType
	}
	hasher := engine.GetHasher(hashType)

	// Generate words
	generator := NewWordGenerator(c.Config)

	var wordChan <-chan string
	if c.Config.Wordlist != "" {
		wordChan = generator.FromWordlist()
		if c.Config.Verbose {
			fmt.Println("[*] Loading wordlist...")
		}
	} else {
		wordChan = generator.Bruteforce()
		if c.Config.Verbose {
			fmt.Println("[*] Starting bruteforce...")
		}
	}

	// Create result channel
	results := make(chan struct {
		hash      string
		plaintext string
	}, 100)

	// Start workers
	var wg sync.WaitGroup
	numWorkers := c.Config.Threads
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go c.crackWorker(wordChan, results, hasher, &wg)
	}

	// Close results channel when workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	for result := range results {
		target := c.hashLookup[result.hash]
		if target != nil {
			c.mu.Lock()
			target.Cracked = true
			target.Plaintext = &result.plaintext
			c.Result.CrackedCount++
			c.successFound = true
			c.mu.Unlock()

			if c.Config.Verbose {
				fmt.Printf("[+] Cracked: %s... = %s\n", result.hash[:16], result.plaintext)
			}
		}
	}

	c.Result.Duration = time.Since(startTime).Seconds()
	c.Result.Attempts = c.attempts
	if c.Result.Duration > 0 {
		c.Result.Rate = float64(c.attempts) / c.Result.Duration
	}
	c.Result.Results = c.Config.Hashes

	return c.Result
}

// Stop stops cracking operation
func (c *HashCracker) Stop() {
	close(c.stopEvent)
}

// =============================================================================
// Planning Mode
// =============================================================================

// printPlan displays execution plan without performing actions
func printPlan(config *CrackConfig) {
	fmt.Println(`
[PLAN MODE] Tool: hash-cracker
================================================================================
`)

	fmt.Println("HASH TARGETS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Total Hashes:    %d\n", len(config.Hashes))
	for i, target := range config.Hashes {
		if i >= 5 {
			break
		}
		hashType := "auto-detect"
		if target.HashType != nil {
			hashType = string(*target.HashType)
		}
		hashDisplay := target.HashValue
		if len(hashDisplay) > 32 {
			hashDisplay = hashDisplay[:32] + "..."
		}
		fmt.Printf("  [%d] %s (%s)\n", i+1, hashDisplay, hashType)
	}
	if len(config.Hashes) > 5 {
		fmt.Printf("  ... and %d more\n", len(config.Hashes)-5)
	}
	fmt.Println()

	fmt.Println("ATTACK CONFIGURATION")
	fmt.Println(strings.Repeat("-", 40))
	if config.Wordlist != "" {
		fmt.Println("  Mode:            Dictionary Attack")
		fmt.Printf("  Wordlist:        %s\n", config.Wordlist)
	} else {
		fmt.Println("  Mode:            Bruteforce Attack")
		fmt.Printf("  Charset:         %s\n", config.Charset)
		fmt.Printf("  Length Range:    %d - %d\n", config.MinLength, config.MaxLength)
	}

	if len(config.Rules) > 0 {
		fmt.Printf("  Rules:           %s\n", strings.Join(config.Rules, ", "))
	}
	fmt.Printf("  Threads:         %d\n", config.Threads)
	fmt.Println()

	fmt.Println("ACTIONS TO BE PERFORMED")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  1. Load and validate target hashes")
	fmt.Println("  2. Auto-detect hash types (if not specified)")
	if config.Wordlist != "" {
		fmt.Println("  3. Load wordlist into memory")
		if len(config.Rules) > 0 {
			fmt.Println("  4. Apply mutation rules to each word")
		}
		fmt.Println("  5. Compute hashes and compare (multi-threaded)")
	} else {
		fmt.Println("  3. Generate bruteforce candidates")
		fmt.Println("  4. Compute hashes and compare (multi-threaded)")
	}
	fmt.Println("  6. Report cracked hashes")
	fmt.Println()

	fmt.Println("SUPPORTED ALGORITHMS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - MD5 (32 characters)")
	fmt.Println("  - SHA1 (40 characters)")
	fmt.Println("  - SHA256 (64 characters)")
	fmt.Println("  - SHA512 (128 characters)")
	fmt.Println("  - NTLM (32 characters)")
	fmt.Println()

	fmt.Println("OPSEC CONSIDERATIONS")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("  - All operations are in-memory")
	fmt.Println("  - No network activity")
	fmt.Println("  - No disk writes for hash computations")
	fmt.Println("  - Results can be exported to file if needed")
	fmt.Println()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("No actions will be taken. Remove --plan flag to execute.")
	fmt.Println(strings.Repeat("=", 80))
}

// =============================================================================
// CLI Interface
// =============================================================================

func loadHashes(hashArg string, hashFile string) []*HashTarget {
	var hashes []*HashTarget

	// Single hash
	if hashArg != "" {
		hashes = append(hashes, &HashTarget{HashValue: hashArg})
	}

	// Hash file
	if hashFile != "" {
		file, err := os.Open(hashFile)
		if err != nil {
			fmt.Printf("[!] Error loading hash file: %v\n", err)
			return hashes
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Support username:hash format
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				username := parts[0]
				hashes = append(hashes, &HashTarget{
					HashValue: parts[1],
					Username:  &username,
				})
			} else {
				hashes = append(hashes, &HashTarget{HashValue: line})
			}
		}
	}

	return hashes
}

func main() {
	// Command line flags
	hashFile := flag.String("f", "", "File containing hashes (one per line)")
	wordlist := flag.String("w", "", "Wordlist for dictionary attack")
	hashTypeStr := flag.String("t", "", "Hash type (md5, sha1, sha256, sha512, ntlm)")
	rules := flag.String("r", "", "Comma-separated rules: capitalize,uppercase,reverse,append_numbers,append_year,leet")
	bruteforce := flag.Bool("b", false, "Enable bruteforce mode (if no wordlist)")
	charset := flag.String("c", "lowercase", "Charset for bruteforce (lowercase, uppercase, digits, alpha, alphanumeric, all)")
	minLength := flag.Int("min-length", 1, "Minimum length for bruteforce")
	maxLength := flag.Int("max-length", 6, "Maximum length for bruteforce")
	threads := flag.Int("T", DefaultThreads, "Number of threads")
	planMode := flag.Bool("plan", false, "Show execution plan without cracking")
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFile := flag.String("o", "", "Output file for results")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Hash Cracker - Multi-Algorithm Hash Cracking Utility

Usage: %s [options] [hash]

Examples:
  %s 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
  %s --file hashes.txt -w rockyou.txt --type md5
  %s 5f4dcc3b5aa765d61d8327deb882cf99 -b -c alphanumeric

WARNING: Only crack hashes you have permission to test.

Options:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Get hash argument
	hashArg := ""
	if flag.NArg() > 0 {
		hashArg = flag.Arg(0)
	}

	// Load hashes
	hashes := loadHashes(hashArg, *hashFile)

	if len(hashes) == 0 && !*planMode {
		fmt.Println("[!] No hashes specified")
		fmt.Println("[*] Use a hash argument or --file option")
		os.Exit(1)
	}

	// Parse hash type
	var hashType *HashType
	if *hashTypeStr != "" {
		ht := HashType(*hashTypeStr)
		hashType = &ht
	}

	// Parse rules
	var rulesList []string
	if *rules != "" {
		rulesList = strings.Split(*rules, ",")
		for i, r := range rulesList {
			rulesList[i] = strings.TrimSpace(r)
		}
	}

	// Build configuration
	config := &CrackConfig{
		Hashes:     hashes,
		Wordlist:   *wordlist,
		HashType:   hashType,
		Threads:    *threads,
		Rules:      rulesList,
		MinLength:  *minLength,
		MaxLength:  *maxLength,
		Charset:    *charset,
		Verbose:    *verbose,
		PlanMode:   *planMode,
		OutputFile: *outputFile,
		BruteForce: *bruteforce,
	}

	// Use example hash for planning mode if no hashes provided
	if config.PlanMode && len(config.Hashes) == 0 {
		config.Hashes = []*HashTarget{{HashValue: "example"}}
	}

	// Planning mode
	if config.PlanMode {
		printPlan(config)
		os.Exit(0)
	}

	// Execute cracking
	fmt.Println("[*] Hash Cracker starting...")
	fmt.Printf("[*] Hashes: %d\n", len(config.Hashes))
	mode := "Dictionary"
	if config.Wordlist == "" {
		mode = "Bruteforce"
	}
	fmt.Printf("[*] Mode: %s\n", mode)

	cracker := NewHashCracker(config)

	result := cracker.Crack()

	// Display results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("CRACKING RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total hashes:     %d\n", result.TotalHashes)
	fmt.Printf("Cracked:          %d\n", result.CrackedCount)
	fmt.Printf("Attempts:         %d\n", result.Attempts)
	fmt.Printf("Duration:         %.2fs\n", result.Duration)
	fmt.Printf("Rate:             %.0f H/s\n", result.Rate)
	fmt.Println()

	if result.CrackedCount > 0 {
		fmt.Println("CRACKED HASHES:")
		fmt.Println(strings.Repeat("-", 60))
		for _, target := range result.Results {
			if target.Cracked {
				userStr := ""
				if target.Username != nil {
					userStr = *target.Username + ":"
				}
				hashDisplay := target.HashValue
				if len(hashDisplay) > 32 {
					hashDisplay = hashDisplay[:32] + "..."
				}
				fmt.Printf("  %s%s = %s\n", userStr, hashDisplay, *target.Plaintext)
			}
		}
	}

	// Output to file if requested
	if config.OutputFile != "" {
		outputData := struct {
			TotalHashes  int            `json:"total_hashes"`
			CrackedCount int            `json:"cracked_count"`
			Attempts     int64          `json:"attempts"`
			Duration     float64        `json:"duration"`
			Rate         float64        `json:"rate"`
			Results      []*HashTarget  `json:"results"`
		}{
			TotalHashes:  result.TotalHashes,
			CrackedCount: result.CrackedCount,
			Attempts:     result.Attempts,
			Duration:     result.Duration,
			Rate:         result.Rate,
			Results:      make([]*HashTarget, 0),
		}

		for _, target := range result.Results {
			if target.Cracked {
				outputData.Results = append(outputData.Results, target)
			}
		}

		jsonData, err := json.MarshalIndent(outputData, "", "  ")
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
