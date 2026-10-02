package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/netip"

	"github.com/rokkerruslan/tuntap"
)

func main() {
	name := flag.String("i", "tun0", "interface name")
	reflect := flag.Bool("nat", false, "swap source and destination addresses and send packets back to the kernel")
	proxyMode := flag.Bool("proxy", false, "accept TCP connections and open them back to the kernel")
	flag.Parse()

	iface, err := tuntap.New(tuntap.Opts{Name: *name, Mode: tuntap.Tun})
	if err != nil {
		log.Fatalf("open %s: %v", *name, err)
	}
	defer iface.Close()

	log.Printf("listening on %s", iface.Name())

	var px *proxy
	if *proxyMode {
		px = newProxy(iface)
	}

	// Big enough for any packet.
	buf := make([]byte, 65535)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		p := buf[:n]

		if px != nil {
			seg, err := parseSegment(p)
			if err != nil {
				fmt.Println(describe(p))
				continue
			}
			fmt.Println("<-", seg)
			px.handle(seg)
			continue
		}

		if !*reflect {
			fmt.Println(describe(p))
			continue
		}

		fmt.Println("<-", describe(p))
		if !nat(p) {
			continue
		}
		fmt.Println("->", describe(p))
		if _, err := iface.Write(p); err != nil {
			log.Printf("write: %v", err)
		}
	}
}

// nat swaps source and destination addresses of an IPv4 packet.
// It returns false if the packet is not IPv4.
//
// IPv4 header (RFC 791), byte offsets on the left:
//
//	    0       1       2       3
//	 0 |Ver|IHL|  TOS  |  Total Length  |
//	 4 | Identification|Flags| Fragment |
//	 8 |  TTL  | Proto |    Checksum    |
//	12 |       Source Address           |  p[12:16]
//	16 |     Destination Address        |  p[16:20]
//	20 | Options (if IHL > 5) / Data    |
//
// Version is the high 4 bits of p[0]. The header is at least 20 bytes.
//
// Checksums stay valid: the IPv4 header checksum and the TCP/UDP
// checksums (whose pseudo-header includes both addresses) are
// one's complement sums of 16-bit words (RFC 1071), and swapping
// two addresses only reorders the words being summed.
func nat(p []byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 {
		return false
	}

	var buf [4]byte
	copy(buf[:], p[12:16])
	copy(p[12:16], p[16:20])
	copy(p[16:20], buf[:])

	return true
}

// describe returns a short description of an IP packet.
func describe(p []byte) string {
	if len(p) < 1 {
		return "empty packet"
	}

	switch version := p[0] >> 4; version {
	case 4:
		if len(p) < 20 {
			return fmt.Sprintf("ipv4: truncated packet, %d bytes", len(p))
		}
		src := netip.AddrFrom4([4]byte(p[12:16]))
		dst := netip.AddrFrom4([4]byte(p[16:20]))
		total := binary.BigEndian.Uint16(p[2:4])
		return fmt.Sprintf("ipv4 %s -> %s proto=%s len=%d", src, dst, protoName(p[9]), total)
	case 6:
		if len(p) < 40 {
			return fmt.Sprintf("ipv6: truncated packet, %d bytes", len(p))
		}
		src := netip.AddrFrom16([16]byte(p[8:24]))
		dst := netip.AddrFrom16([16]byte(p[24:40]))
		payload := binary.BigEndian.Uint16(p[4:6])
		return fmt.Sprintf("ipv6 %s -> %s next=%s payload=%d", src, dst, protoName(p[6]), payload)
	default:
		return fmt.Sprintf("unknown ip version %d, %d bytes", version, len(p))
	}
}

func protoName(proto byte) string {
	switch proto {
	case 0:
		return "hopopt"
	case 1:
		return "icmp"
	case 2:
		return "igmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}
