package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// TCP flags.
const (
	flagFIN = 1 << 0
	flagSYN = 1 << 1
	flagRST = 1 << 2
	flagPSH = 1 << 3
	flagACK = 1 << 4
)

// defaultMSS is used when the peer does not send the MSS option (RFC 9293, 3.7.1).
const defaultMSS = 536

// segment is a parsed TCP segment inside an IPv4 packet.
type segment struct {
	src     netip.AddrPort
	dst     netip.AddrPort
	seq     uint32
	ack     uint32
	flags   uint8
	wnd     uint16
	mss     uint16 // 0 if there is no MSS option
	payload []byte
}

// parseSegment parses an IPv4 packet with a TCP segment.
// Checksums are not checked: packets come from the local kernel.
//
// TCP header (RFC 9293), byte offsets on the left:
//
//	    0       1       2       3
//	 0 |  Source Port  |   Dest Port    |
//	 4 |        Sequence Number         |
//	 8 |     Acknowledgment Number      |
//	12 |Off|Rsv| Flags |     Window     |
//	16 |   Checksum    | Urgent Pointer |
//	20 | Options (if Off > 5) / Data    |
//
// Off is the header length in 4-byte words, the high 4 bits of byte 12.
func parseSegment(p []byte) (segment, error) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return segment{}, errors.New("not ipv4")
	}
	if p[9] != 6 {
		return segment{}, errors.New("not tcp")
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || total < ihl || total > len(p) {
		return segment{}, errors.New("bad ipv4 header")
	}

	src := netip.AddrFrom4([4]byte(p[12:16]))
	dst := netip.AddrFrom4([4]byte(p[16:20]))

	t := p[ihl:total]
	if len(t) < 20 {
		return segment{}, errors.New("short tcp header")
	}
	off := int(t[12]>>4) * 4
	if off < 20 || off > len(t) {
		return segment{}, errors.New("bad tcp header length")
	}

	return segment{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(t[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(t[2:4])),
		seq:     binary.BigEndian.Uint32(t[4:8]),
		ack:     binary.BigEndian.Uint32(t[8:12]),
		flags:   t[13],
		wnd:     binary.BigEndian.Uint16(t[14:16]),
		mss:     parseMSS(t[20:off]),
		payload: t[off:],
	}, nil
}

// parseMSS returns the MSS option value, or 0 if there is none.
func parseMSS(opts []byte) uint16 {
	for len(opts) > 0 {
		switch kind := opts[0]; kind {
		case 0: // end of options
			return 0
		case 1: // no-op
			opts = opts[1:]
		default:
			if len(opts) < 2 || int(opts[1]) < 2 || int(opts[1]) > len(opts) {
				return 0
			}
			if kind == 2 && opts[1] == 4 {
				return binary.BigEndian.Uint16(opts[2:4])
			}
			opts = opts[opts[1]:]
		}
	}
	return 0
}

func (s segment) String() string {
	var f strings.Builder
	for _, x := range []struct {
		bit  uint8
		name byte
	}{{flagSYN, 'S'}, {flagFIN, 'F'}, {flagRST, 'R'}, {flagPSH, 'P'}, {flagACK, '.'}} {
		if s.flags&x.bit != 0 {
			f.WriteByte(x.name)
		}
	}
	out := fmt.Sprintf("tcp %s -> %s [%s] seq=%d ack=%d wnd=%d len=%d", s.src, s.dst, f.String(), s.seq, s.ack, s.wnd, len(s.payload))
	if s.mss != 0 {
		out += fmt.Sprintf(" mss=%d", s.mss)
	}
	return out
}

// marshal builds an IPv4 packet with this TCP segment.
// The TCP header has no options.
func (s segment) marshal() []byte {
	const ipLen, tcpLen = 20, 20
	p := make([]byte, ipLen+tcpLen+len(s.payload))

	ip := p[:ipLen]
	ip[0] = 4<<4 | ipLen/4
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // don't fragment
	ip[8] = 64                                  // TTL
	ip[9] = 6                                   // TCP
	src, dst := s.src.Addr().As4(), s.dst.Addr().As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(0, ip))

	t := p[ipLen:]
	binary.BigEndian.PutUint16(t[0:2], s.src.Port())
	binary.BigEndian.PutUint16(t[2:4], s.dst.Port())
	binary.BigEndian.PutUint32(t[4:8], s.seq)
	binary.BigEndian.PutUint32(t[8:12], s.ack)
	t[12] = tcpLen / 4 << 4
	t[13] = s.flags
	binary.BigEndian.PutUint16(t[14:16], s.wnd)
	copy(t[tcpLen:], s.payload)

	// Pseudo-header: src, dst, zero, protocol, TCP length.
	var ph [12]byte
	copy(ph[0:4], src[:])
	copy(ph[4:8], dst[:])
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(t)))
	binary.BigEndian.PutUint16(t[16:18], checksum(sum(0, ph[:]), t))

	return p
}

// checksum returns the Internet checksum (RFC 1071) of b,
// starting from a partial sum.
func checksum(start uint32, b []byte) uint16 {
	s := sum(start, b)
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// sum adds b to s as 16-bit big-endian words.
func sum(s uint32, b []byte) uint32 {
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}
