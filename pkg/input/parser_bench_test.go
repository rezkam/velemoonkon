package input

import (
	"net"
	"testing"
)

// BenchmarkExpandCIDR_Small benchmarks /24 CIDR expansion (256 IPs)
func BenchmarkExpandCIDR_Small(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ips, err := ExpandCIDR("192.168.1.0/24")
		if err != nil {
			b.Fatal(err)
		}
		if len(ips) != 256 {
			b.Fatalf("Expected 256 IPs, got %d", len(ips))
		}
	}
}

// BenchmarkExpandCIDR_Medium benchmarks /20 CIDR expansion (4096 IPs)
func BenchmarkExpandCIDR_Medium(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ips, err := ExpandCIDR("10.0.0.0/20")
		if err != nil {
			b.Fatal(err)
		}
		if len(ips) != 4096 {
			b.Fatalf("Expected 4096 IPs, got %d", len(ips))
		}
	}
}

// BenchmarkExpandCIDR_Large benchmarks /16 CIDR expansion (65536 IPs)
func BenchmarkExpandCIDR_Large(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ips, err := ExpandCIDR("172.16.0.0/16")
		if err != nil {
			b.Fatal(err)
		}
		if len(ips) != 65536 {
			b.Fatalf("Expected 65536 IPs, got %d", len(ips))
		}
	}
}

// BenchmarkIPRange_Small benchmarks /24 IP iteration (256 IPs) without materialization
func BenchmarkIPRange_Small(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ipSeq, err := IPRange("192.168.1.0/24")
		if err != nil {
			b.Fatal(err)
		}

		count := 0
		for range ipSeq {
			count++
		}

		if count != 256 {
			b.Fatalf("Expected 256 IPs, got %d", count)
		}
	}
}

// BenchmarkIPRange_Medium benchmarks /20 IP iteration (4096 IPs) without materialization
func BenchmarkIPRange_Medium(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ipSeq, err := IPRange("10.0.0.0/20")
		if err != nil {
			b.Fatal(err)
		}

		count := 0
		for range ipSeq {
			count++
		}

		if count != 4096 {
			b.Fatalf("Expected 4096 IPs, got %d", count)
		}
	}
}

// BenchmarkIPRange_Large benchmarks /16 IP iteration (65536 IPs) without materialization
func BenchmarkIPRange_Large(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ipSeq, err := IPRange("172.16.0.0/16")
		if err != nil {
			b.Fatal(err)
		}

		count := 0
		for range ipSeq {
			count++
		}

		if count != 65536 {
			b.Fatalf("Expected 65536 IPs, got %d", count)
		}
	}
}

// BenchmarkIPRange_Processing_Small benchmarks /24 with processing (256 IPs)
// Simulates real-world use where each IP is processed
func BenchmarkIPRange_Processing_Small(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ipSeq, err := IPRange("192.168.1.0/24")
		if err != nil {
			b.Fatal(err)
		}

		var lastIP net.IP
		for ip := range ipSeq {
			// Simulate minimal processing
			lastIP = ip
		}
		_ = lastIP
	}
}

// BenchmarkExpandCIDR_Processing_Small benchmarks /24 with slice + processing (256 IPs)
// Comparison to IPRange_Processing to measure overhead
func BenchmarkExpandCIDR_Processing_Small(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		ips, err := ExpandCIDR("192.168.1.0/24")
		if err != nil {
			b.Fatal(err)
		}

		var lastIP net.IP
		for _, ip := range ips {
			// Simulate minimal processing
			lastIP = ip
		}
		_ = lastIP
	}
}

// BenchmarkIPRange_StreamingVsSlice_Medium compares memory usage
// This benchmark demonstrates the memory advantage of iterators
func BenchmarkIPRange_StreamingVsSlice_Medium(b *testing.B) {
	b.Run("Streaming", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			ipSeq, err := IPRange("10.0.0.0/20")
			if err != nil {
				b.Fatal(err)
			}

			// Process IPs one at a time (constant memory)
			count := 0
			for range ipSeq {
				count++
			}
		}
	})

	b.Run("Slice", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			ips, err := ExpandCIDR("10.0.0.0/20")
			if err != nil {
				b.Fatal(err)
			}

			// Process all IPs (O(n) memory)
			count := 0
			for range ips {
				count++
			}
		}
	})
}

// BenchmarkIncrementIP benchmarks the IP increment operation
func BenchmarkIncrementIP(b *testing.B) {
	b.ReportAllocs()
	ip := net.ParseIP("192.168.1.1").To4()
	for range b.N {
		incrementIP(ip)
	}
}
