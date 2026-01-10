// file_info.go - Go port of file_info.py
// Converts Python file information utility to idiomatic Go
//
// Build instructions:
//   go build -o file_info file_info.go
//
// Usage:
//   ./file_info <filename>
//
// Output: JSON object containing file metadata

package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// FileInfo represents the structure of file information to be returned as JSON
type FileInfo struct {
	Filename      string `json:"filename"`
	MD5Sum        string `json:"md5sum"`
	FileSize      int64  `json:"file_size"`
	FileType      string `json:"file_type"`
	Base64Encoded string `json:"base64_encoded"`
}

// ErrorResponse represents an error message to be returned as JSON
type ErrorResponse struct {
	Error string `json:"error"`
}

// getFileInfo retrieves file metadata and returns it as a JSON string
// Equivalent to Python's get_file_info function
func getFileInfo(filename string) string {
	// Check if file exists
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return formatError(fmt.Sprintf("File not found: %s", filename))
	}
	if err != nil {
		return formatError(err.Error())
	}

	// Get file size
	fileSize := fileInfo.Size()

	// Read file content
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		return formatError(err.Error())
	}

	// Calculate MD5 hash
	md5Hash := md5.Sum(fileContent)
	md5String := hex.EncodeToString(md5Hash[:])

	// Calculate base64 encoding
	base64String := base64.StdEncoding.EncodeToString(fileContent)

	// Get file type using 'file' command
	fileType := getFileType(filename)

	// Create result structure
	result := FileInfo{
		Filename:      filename,
		MD5Sum:        md5String,
		FileSize:      fileSize,
		FileType:      fileType,
		Base64Encoded: base64String,
	}

	// Marshal to JSON with indentation (equivalent to Python's indent=2)
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return formatError(err.Error())
	}

	return string(jsonBytes)
}

// getFileType uses the system 'file' command to determine file type
// Equivalent to Python's subprocess.check_output(['file', '-b', filename])
func getFileType(filename string) string {
	cmd := exec.Command("file", "-b", filename)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

// formatError creates a JSON error response
// Equivalent to Python's json.dumps({"error": msg}, indent=2)
func formatError(message string) string {
	errResponse := ErrorResponse{Error: message}
	jsonBytes, err := json.MarshalIndent(errResponse, "", "  ")
	if err != nil {
		// Fallback if JSON marshaling fails
		return fmt.Sprintf(`{"error": "%s"}`, message)
	}
	return string(jsonBytes)
}

func main() {
	// Check command line arguments
	if len(os.Args) != 2 {
		fmt.Println(formatError("Usage: file_info <filename>"))
		os.Exit(1)
	}

	filename := os.Args[1]
	fmt.Println(getFileInfo(filename))
}
