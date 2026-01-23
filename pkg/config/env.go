package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable prefix for all Lightning settings
const envPrefix = "LIGHTNING_"

// HTTPClientConfig contains configurable HTTP client settings
type HTTPClientConfig struct {
	// DoH response size limit (bytes)
	MaxDoHResponseSize int64

	// HTTP client connection pool settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration

	// HTTP client timeouts
	DialTimeout    time.Duration
	RequestTimeout time.Duration
	KeepAlive      time.Duration
}

// ScannerConfig contains configurable scanner settings
type ScannerConfig struct {
	// Channel buffer sizes
	IPChannelBuffer     int
	ResultChannelBuffer int

	// Output buffer sizes
	MarkdownBufferSize int

	// Advanced CLI defaults (overridable via CLI)
	DefaultRateLimit     int
	DefaultDNSConcurrency int
	DefaultScanPorts     bool
	DefaultTestDomains   string
}

// DNSConfig contains DNS validation and security settings
type DNSConfig struct {
	// Validation settings (for security vs speed trade-offs)
	ValidateResponseID bool // Default: false for speed, enable for security
}

// DefaultHTTPClientConfig returns default HTTP client configuration
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		MaxDoHResponseSize:  getEnvInt64("MAX_DOH_RESPONSE_SIZE", 64*1024),           // 64KB
		MaxIdleConns:        getEnvInt("HTTP_MAX_IDLE_CONNS", 100),                   // 100 connections
		MaxIdleConnsPerHost: getEnvInt("HTTP_MAX_IDLE_CONNS_PER_HOST", 10),           // 10 per host
		IdleConnTimeout:     getEnvDuration("HTTP_IDLE_CONN_TIMEOUT", 90*time.Second), // 90s
		DialTimeout:         getEnvDuration("HTTP_DIAL_TIMEOUT", 5*time.Second),       // 5s
		RequestTimeout:      getEnvDuration("HTTP_REQUEST_TIMEOUT", 10*time.Second),   // 10s
		KeepAlive:           getEnvDuration("HTTP_KEEPALIVE", 30*time.Second),         // 30s
	}
}

// DefaultScannerConfig returns default scanner configuration
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		IPChannelBuffer:       getEnvInt("SCANNER_IP_BUFFER", 1000),                               // 1000 IPs
		ResultChannelBuffer:   getEnvInt("SCANNER_RESULT_BUFFER", 1000),                           // 1000 results
		MarkdownBufferSize:    getEnvInt("MARKDOWN_BUFFER_SIZE", 8*1024),                          // 8KB
		DefaultRateLimit:      getEnvInt("DEFAULT_RATE_LIMIT", 1000),                              // 1000 IPs/sec
		DefaultDNSConcurrency: getEnvInt("DEFAULT_DNS_CONCURRENCY", 4),                            // 4 concurrent tests
		DefaultScanPorts:      getEnvBool("DEFAULT_SCAN_PORTS", true),                             // Scan ports by default
		DefaultTestDomains:    getEnvString("DEFAULT_TEST_DOMAINS", "chatgpt.com,google.com,microsoft.com"), // Test domains
	}
}

// DefaultDNSConfig returns default DNS configuration
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		// Validation OFF by default for speed (we're detecting servers, not implementing RFC-compliant client)
		// Enable with LIGHTNING_DNS_VALIDATE_RESPONSE_ID=true for security-focused scanning
		ValidateResponseID: getEnvBool("DNS_VALIDATE_RESPONSE_ID", false),
	}
}

// getEnvInt retrieves an integer environment variable with a default value
func getEnvInt(key string, defaultValue int) int {
	if val := os.Getenv(envPrefix + key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}

// getEnvInt64 retrieves an int64 environment variable with a default value
func getEnvInt64(key string, defaultValue int64) int64 {
	if val := os.Getenv(envPrefix + key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

// getEnvDuration retrieves a duration environment variable with a default value
// Accepts values like "5s", "10m", "1h"
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if val := os.Getenv(envPrefix + key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultValue
}

// getEnvBool retrieves a boolean environment variable with a default value
// Accepts: "true", "false", "1", "0", "yes", "no" (case-insensitive)
func getEnvBool(key string, defaultValue bool) bool {
	if val := os.Getenv(envPrefix + key); val != "" {
		val = strings.ToLower(strings.TrimSpace(val))
		switch val {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultValue
}

// getEnvString retrieves a string environment variable with a default value
func getEnvString(key string, defaultValue string) string {
	if val := os.Getenv(envPrefix + key); val != "" {
		return val
	}
	return defaultValue
}

// Global configuration instances (initialized once at startup)
var (
	HTTP    = DefaultHTTPClientConfig()
	Scanner = DefaultScannerConfig()
	DNS     = DefaultDNSConfig()
)

// Init initializes all configuration from environment variables
// Call this at application startup
func Init() {
	HTTP = DefaultHTTPClientConfig()
	Scanner = DefaultScannerConfig()
	DNS = DefaultDNSConfig()
}
