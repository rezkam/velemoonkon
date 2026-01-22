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

```bash
# Scan a single DNS server
lightning 8.8.8.8

# Scan multiple IPs or CIDR ranges
lightning 192.168.1.0/24,8.8.8.8

# Scan with custom test domains
lightning 1.1.1.1 --test-domains example.com,test.org

# Specify DNS protocols to test
lightning 8.8.8.8 --protocols udp,tcp,dot

# Enable tunnel detection
lightning 8.8.8.8 --detect-tunnels
```

## Output Formats

- JSON: Machine-readable results
- Markdown: Human-readable reports

## Purpose

This tool is intended to help administrators verify their DNS configurations are secure and not susceptible to tunneling attacks. Use responsibly and only on networks you own or have permission to test.
