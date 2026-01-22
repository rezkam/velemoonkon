package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHEndpoint represents a DNS over HTTPS endpoint
type DoHEndpoint struct {
	Path   string
	Method string // GET or POST
}

// Common DoH endpoints to test
var CommonDoHEndpoints = []DoHEndpoint{
	{Path: "/dns-query", Method: "POST"},    // RFC 8484 standard
	{Path: "/resolve", Method: "GET"},       // Google DNS format
	{Path: "/dns", Method: "POST"},          // Alternative endpoint
	{Path: "/dns-query", Method: "GET"},     // RFC 8484 GET variant
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

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: opts.Timeout,
	}

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

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		return nil, 0, fmt.Errorf("unexpected content type: %s", contentType)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	// Unpack DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("failed to unpack DNS response: %w", err)
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
