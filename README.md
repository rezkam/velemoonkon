# Lightning

A DNS scanner and tunnel detector designed to identify security vulnerabilities in DNS configurations.

## What It Does

Lightning scans DNS servers across multiple protocols (UDP, TCP, DoT, DoH) and detects potential DNS tunneling activities. The detector helps verify if your DNS infrastructure is properly secured against tunneling attacks used for data exfiltration and command-and-control communications.

## Supported DNS Protocols

- UDP (port 53)
- TCP (port 53)
- DNS-over-TLS (DoT, port 853)
- DNS-over-HTTPS (DoH, port 443)

## Detected Tunnel Protocols

- **Iodine**: IP-over-DNS tunneling
- **dnscat2**: Encrypted DNS tunnel for C2
- **DNSTT**: DNS tunnel over TXT records
- **dns2tcp**: TCP-over-DNS tunneling

## Usage

### Basic Scanning

```bash
# Scan a single DNS server
lightning 8.8.8.8

# Scan multiple IPs (comma-separated)
lightning 8.8.8.8,1.1.1.1

# Scan CIDR range
lightning 192.168.1.0/24

# Scan from file (one IP/CIDR per line)
lightning -f targets.txt
```

### DNS Protocol Selection

```bash
# Test all DNS protocols (default)
lightning 8.8.8.8 --scanner all

# Test only UDP and TCP
lightning 8.8.8.8 --scanner udp,tcp

# Test only DNS-over-TLS and DNS-over-HTTPS
lightning 1.1.1.1 --scanner dot,doh

# Use custom test domains for resolution checks
lightning 8.8.8.8 --test-domains example.com,test.org
```

### Tunnel Detection

```bash
# Enable all tunnel detectors
lightning 1.1.1.1 --detector all

# Detect specific tunnel types
lightning 1.1.1.1 --detector dnstt,iodine

# Detect tunnels with specific domain
lightning 1.1.1.1 --detector all --tunnel-domain tunnel.example.com

# Combine DNS scanning with tunnel detection
lightning 8.8.8.8 --scanner all --detector all
```

### Performance Tuning

```bash
# High-performance scan of large CIDR
lightning 5.62.160.0/19 -w 500 --rate-limit 2000

# Adjust timeout for slow networks
lightning 192.168.1.0/24 --timeout 10

# Control concurrent DNS tests per IP
lightning 8.8.8.8 --dns-concurrency 8
```

### Output Options

```bash
# JSON output (default)
lightning 8.8.8.8 --output-format json

# Markdown report
lightning 8.8.8.8 --output-format md

# Both JSON and Markdown
lightning 8.8.8.8 --output-format json,md

# Custom output file prefix
lightning 8.8.8.8 -o my-scan

# Quiet mode (suppress progress)
lightning 8.8.8.8 -q

# Verbose logging
lightning 8.8.8.8 -v
```

## Output Formats

- JSON: Machine-readable results
- Markdown: Human-readable reports

## Purpose

This tool is intended to help administrators verify their DNS configurations are secure and not susceptible to tunneling attacks. Use responsibly and only on networks you own or have permission to test.
