package main

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"

	"github.com/rokkerruslan/tuntap"
)

// proxy accepts TCP connections from the kernel and opens
// the same connection back to the kernel with swapped addresses:
//
//	in   curl 10.0.0.1:X -> 10.0.0.2:P   incoming, we are the server
//	out  us   10.0.0.2:X -> 10.0.0.1:P   outgoing, we are the client
//
// Data received on one side is sent on the other.
type proxy struct {
	iface *tuntap.Interface
	conns map[key]*tcb
}

func newProxy(iface *tuntap.Interface) *proxy {
	return &proxy{iface: iface, conns: make(map[key]*tcb)}
}

// handle processes one incoming segment.
func (p *proxy) handle(seg segment) {
	t, ok := p.conns[key{local: seg.dst, remote: seg.src}]
	if !ok {
		if seg.flags&flagSYN != 0 && seg.flags&flagACK == 0 {
			p.accept(seg)
			return
		}
		// TODO: reply with RST.
		return
	}

	switch t.state {
	case synSent:
		p.synSent(t, seg)
		return
	case synReceived:
		p.synReceived(t, seg)
		return
	case established:
		p.established(t, seg)
		return
	case finWait1, finWait2, closeWait, closing, lastAck:
		// TODO: connection close.
	}
	log.Printf("%s %s: not implemented", t.key.remote, t.state)
}

// accept creates the in TCB for a SYN and opens
// the out connection back to the kernel.
// We answer in with SYN-ACK only after out
// is established.
func (p *proxy) accept(seg segment) {
	in := &tcb{
		key:    key{local: seg.dst, remote: seg.src},
		state:  synReceived,
		irs:    seg.seq,
		rcvNxt: seg.seq + 1,
		rcvWnd: 65535,
		sndWnd: seg.wnd,
		mss:    peerMSS(seg),
	}
	in.iss = rand.Uint32()
	in.sndUna = in.iss
	in.sndNxt = in.iss

	out := &tcb{
		key: key{
			local:  netip.AddrPortFrom(seg.dst.Addr(), seg.src.Port()),
			remote: netip.AddrPortFrom(seg.src.Addr(), seg.dst.Port()),
		},
		state:  synSent,
		rcvWnd: 65535,
	}
	out.iss = rand.Uint32()
	out.sndUna = out.iss
	out.sndNxt = out.iss

	in.peer = out
	out.peer = in
	p.conns[in.key] = in
	p.conns[out.key] = out

	log.Printf("new connection %s -> %s, opening %s -> %s",
		in.key.remote, in.key.local, out.key.local, out.key.remote)

	p.send(out, flagSYN, nil)
}

// synSent handles a segment on out while we wait for SYN-ACK
// (RFC 9293, 3.10.7.3).
func (p *proxy) synSent(t *tcb, seg segment) {
	// The segment must acknowledge our SYN.
	//
	// TODO: simultaneous open. A SYN without ACK means the other side
	// also opens the connection. RFC says: go to SYN-RECEIVED and send
	// SYN-ACK. The other side of out is a listening socket, it never
	// sends a SYN without ACK, so we drop it for now.
	if seg.flags&flagACK == 0 || seg.ack != t.sndNxt {
		log.Printf("%s %s: unexpected segment, dropped", t.key.remote, t.state)
		return
	}

	if seg.flags&flagRST != 0 {
		// TODO: nobody listens on out, refuse in with RST.
		return
	}

	if seg.flags&flagSYN == 0 {
		return
	}

	t.irs = seg.seq
	t.rcvNxt = seg.seq + 1
	t.sndUna = seg.ack
	t.sndWnd = seg.wnd
	t.sndWl1 = seg.seq
	t.sndWl2 = seg.ack
	t.mss = peerMSS(seg)
	p.send(t, flagACK, nil)
	t.state = established

	// out is ready, answer in. in stays in SYN-RECEIVED until its ACK.
	p.send(t.peer, flagSYN|flagACK, nil)
}

// synReceived handles a segment on in while we wait for the ACK
// of our SYN-ACK (RFC 9293, 3.10.7.4).
func (p *proxy) synReceived(t *tcb, seg segment) {
	// The segment must be next in order and acknowledge our SYN.
	if seg.seq != t.rcvNxt || seg.flags&flagACK == 0 || seg.ack != t.sndNxt {
		log.Printf("%s %s: unexpected segment, dropped", t.key.remote, t.state)
		return
	}

	t.sndUna = seg.ack
	t.sndWnd = seg.wnd
	t.sndWl1 = seg.seq
	t.sndWl2 = seg.ack
	t.state = established

	// TODO: the ACK can carry data, process it as in ESTABLISHED.
}

// established handles a segment in ESTABLISHED (RFC 9293, 3.10.7.4).
func (p *proxy) established(t *tcb, seg segment) {
	// Accept only the next segment in order (no reordering).
	// Otherwise drop it and send ACK to tell the peer which byte
	// we expect (RFC 9293, 3.10.7.4).
	//
	// TODO: RFC says do not send this ACK if the segment has RST.
	if seg.seq != t.rcvNxt {
		p.send(t, flagACK, nil)
		return
	}

	// TODO: RST, SYN, ACK processing (sndUna, window), FIN.

	if len(seg.payload) == 0 {
		return
	}
	t.rcvNxt += uint32(len(seg.payload))
	p.send(t, flagACK, nil)

	// Send data to peer as is. It always fits peer MSS: the kernel
	// sends us at most 536 bytes, because we send no MSS option.
	//
	// TODO: respect peer window (sndUna, sndWnd), keep the rest in peer.out.
	p.send(t.peer, flagACK|flagPSH, seg.payload)
}

// peerMSS returns the MSS from a SYN segment, or the default.
func peerMSS(seg segment) uint16 {
	if seg.mss == 0 {
		return defaultMSS
	}
	return seg.mss
}

// send builds a segment from t and writes it to the interface.
// It moves sndNxt forward by the data length, plus one for SYN and FIN.
func (p *proxy) send(t *tcb, flags uint8, payload []byte) {
	seg := segment{
		src:     t.key.local,
		dst:     t.key.remote,
		seq:     t.sndNxt,
		flags:   flags,
		wnd:     t.rcvWnd,
		payload: payload,
	}
	if flags&flagACK != 0 {
		seg.ack = t.rcvNxt
	}

	fmt.Println("->", seg)
	if _, err := p.iface.Write(seg.marshal()); err != nil {
		log.Printf("write: %v", err)
		return
	}

	t.sndNxt += uint32(len(payload))
	if flags&(flagSYN|flagFIN) != 0 {
		t.sndNxt++
	}
}
