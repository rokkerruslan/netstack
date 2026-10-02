package main

import "net/netip"

// Limits of this prototype:
//   - no retransmissions and no timers: packets are never lost;
//   - no reordering: a segment with seq != rcvNxt is dropped (we reply with ACK);
//   - no TCP options in our segments: then the kernel does not use SACK,
//     timestamps or window scale, so windows are at most 65535 bytes,
//     and it sends us segments of at most 536 bytes (default MSS);
//   - no TIME-WAIT: the TCB is deleted right after close;
//   - no congestion control.

// state is a TCP connection state (RFC 9293, 3.3.2).
// There is no LISTEN (we accept any SYN) and no TIME-WAIT.
type state int

const (
	closed state = iota
	synSent
	synReceived
	established
	finWait1
	finWait2
	closeWait
	closing
	lastAck
)

func (s state) String() string {
	switch s {
	case closed:
		return "CLOSED"
	case synSent:
		return "SYN-SENT"
	case synReceived:
		return "SYN-RECEIVED"
	case established:
		return "ESTABLISHED"
	case finWait1:
		return "FIN-WAIT-1"
	case finWait2:
		return "FIN-WAIT-2"
	case closeWait:
		return "CLOSE-WAIT"
	case closing:
		return "CLOSING"
	case lastAck:
		return "LAST-ACK"
	default:
		return "UNKNOWN"
	}
}

// key identifies a connection. local is always our side.
type key struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

// tcb is a Transmission Control Block (RFC 9293, 3.3.1).
type tcb struct {
	key   key
	state state

	// Send sequence space:
	//
	//	     1         2          3          4
	//	----------|----------|----------|----------
	//	       sndUna     sndNxt    sndUna+sndWnd
	//
	//	1 - sent and acknowledged
	//	2 - sent, not acknowledged
	//	3 - allowed to send
	//	4 - not allowed yet
	iss    uint32 // initial send sequence number
	sndUna uint32 // oldest unacknowledged seq
	sndNxt uint32 // next seq to send
	sndWnd uint16 // peer receive window
	sndWl1 uint32 // seq of the segment used for the last window update
	sndWl2 uint32 // ack of the segment used for the last window update

	// Receive sequence space:
	//
	//	     1          2          3
	//	----------|----------|----------
	//	       rcvNxt    rcvNxt+rcvWnd
	//
	//	1 - received and acknowledged
	//	2 - allowed to receive
	//	3 - not allowed yet
	irs    uint32 // initial receive sequence number
	rcvNxt uint32 // next seq we expect
	rcvWnd uint16 // our receive window

	mss uint16 // peer max segment size

	// peer is the other side of the proxy.
	peer *tcb

	// out holds data from peer that does not fit into sndWnd yet.
	out []byte
}
