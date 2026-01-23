package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/velemoonkon/lightning/pkg/config"
)

var (
	// Shared HTTP client for DoH requests to enable connection reuse
	sharedDoHClient     *http.Client
	sharedDoHClientOnce sync.Once
)

// getSharedDoHClient returns a shared HTTP client optimized for DoH requests
// Configuration is loaded from environment variables with LIGHTNING_ prefix
func getSharedDoHClient() *http.Client {
	sharedDoHClientOnce.Do(func() {
		cfg := config.HTTP

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
				// Post-quantum key exchange enabled by default in Go 1.25
				// Explicit configuration documents intent for quantum resistance
				CurvePreferences: []tls.CurveID{
					tls.X25519MLKEM768, // Post-quantum hybrid
					tls.X25519,         // Classical fallback
				},
			},
			MaxIdleConns:        cfg.MaxIdleConns,
			MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
			IdleConnTimeout:     cfg.IdleConnTimeout,
			DisableKeepAlives:   false,
			ForceAttemptHTTP2:   true,
			DialContext: (&net.Dialer{
				Timeout:   cfg.DialTimeout,
				KeepAlive: cfg.KeepAlive,
			}).DialContext,
		}

		sharedDoHClient = &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		}
	})
	return sharedDoHClient
}

// DoHEndpoint represents a DNS over HTTPS endpoint
type DoHEndpoint struct {
	Path   string
	Method string // GET or POST
}

// Common DoH endpoints to test (POST only, GET not implemented)
var CommonDoHEndpoints = []DoHEndpoint{
	{Path: "/dns-query", Method: "POST"}, // RFC 8484 standard
	{Path: "/dns", Method: "POST"},       // Alternative endpoint
}

// QueryDoH performs a DNS over HTTPS query
func QueryDoH(ctx context.Context, server string, domain string, qtype uint16, endpoint DoHEndpoint, opts QueryOptions) (*dns.Msg, time.Duration, error) {
	// Construct DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = opts.RecursionDesired

	// Add EDNS if requested
	if opts.UseEDNS {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(opts.EDNSBufferSize)
		msg.Extra = append(msg.Extra, opt)
	}

	// Pack DNS message to wire format
	wireMsg, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("https://%s%s", server, endpoint.Path)

	// Use shared HTTP client for connection reuse
	client := getSharedDoHClient()

	var req *http.Request
	start := time.Now()

	if endpoint.Method == "POST" {
		req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(wireMsg))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create POST request: %w", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
	} else {
		// GET method (less common, but some servers support it)
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create GET request: %w", err)
		}
		// For GET, DNS message typically goes in query parameter
		// This is less standard, so we'll focus on POST
		return nil, 0, fmt.Errorf("GET method not fully implemented")
	}

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	rtt := time.Since(start)

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	// Check content type (case-insensitive, handles charset parameters)
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/dns-message") {
		return nil, 0, fmt.Errorf("unexpected content type: %s", contentType)
	}

	// Read response body with size limit to prevent DoS attacks
	// DNS messages are typically <4KB, default 64KB limit is generous but safe
	// Configurable via LIGHTNING_MAX_DOH_RESPONSE_SIZE environment variable
	maxSize := config.HTTP.MaxDoHResponseSize
	limitedReader := io.LimitReader(resp.Body, maxSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Check if response was truncated (reached size limit)
	if int64(len(body)) == maxSize {
		// Try to read one more byte to confirm truncation
		var buf [1]byte
		n, _ := resp.Body.Read(buf[:])
		if n > 0 {
			return nil, 0, fmt.Errorf("DoH response exceeds maximum size of %d bytes (LIGHTNING_MAX_DOH_RESPONSE_SIZE)", maxSize)
		}
	}

	// Unpack DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	// Optional: Validate response ID (disabled by default for speed)
	if config.DNS.ValidateResponseID && dnsResp.Id != msg.Id {
		return nil, 0, fmt.Errorf("DNS response ID mismatch: expected %d, got %d (possible spoofing)", msg.Id, dnsResp.Id)
	}

	return dnsResp, rtt, nil
}

// TestDoH tests DNS over HTTPS functionality for a server
func TestDoH(ctx context.Context, server string) (bool, string, time.Duration, string) {
	opts := DefaultQueryOptions()
	opts.Timeout = 5 * time.Second

	// Try each common endpoint
	for _, endpoint := range CommonDoHEndpoints {
		resp, rtt, err := QueryDoH(ctx, server, "google.com", dns.TypeA, endpoint, opts)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess {
			return true, endpoint.Path, rtt, ""
		}
	}

	return false, "", 0, "no working DoH endpoint found"
}
