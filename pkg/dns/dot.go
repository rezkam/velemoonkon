package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/velemoonkon/lightning/pkg/config"
)

// QueryDoT performs a DNS over TLS query
func QueryDoT(ctx context.Context, server string, domain string, qtype uint16, opts QueryOptions) (*dns.Msg, time.Duration, error) {
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

	// Create DNS client with TLS
	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: opts.Timeout,
		TLSConfig: &tls.Config{
			ServerName:         server, // Use IP as ServerName initially
			InsecureSkipVerify: false,  // Verify certificates
		},
	}

	// Ensure server has port
	serverAddr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		serverAddr = net.JoinHostPort(server, "853")
	}

	// Perform query with context
	resp, rtt, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil {
		// Try with InsecureSkipVerify if certificate validation fails
		client.TLSConfig.InsecureSkipVerify = true
		resp, rtt, err = client.ExchangeContext(ctx, msg, serverAddr)
		if err != nil {
			return nil, 0, fmt.Errorf("DoT query failed: %w", err)
		}
	}

	if resp == nil {
		return nil, 0, fmt.Errorf("empty response")
	}

	// Optional: Validate response ID (disabled by default for speed)
	if config.DNS.ValidateResponseID && resp.Id != msg.Id {
		return nil, 0, fmt.Errorf("DNS response ID mismatch: expected %d, got %d (possible spoofing)", msg.Id, resp.Id)
	}

	return resp, rtt, nil
}

// TestDoT tests DNS over TLS functionality for a server
func TestDoT(ctx context.Context, server string) (bool, time.Duration, string) {
	opts := DefaultQueryOptions()
	opts.Timeout = 5 * time.Second

	resp, rtt, err := QueryDoT(ctx, server, "google.com", dns.TypeA, opts)
	if err != nil {
		return false, 0, err.Error()
	}

	if resp.Rcode == dns.RcodeSuccess {
		return true, rtt, ""
	}

	return false, 0, fmt.Sprintf("query failed with rcode: %s", dns.RcodeToString[resp.Rcode])
}
