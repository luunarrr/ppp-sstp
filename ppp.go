package main

import (
	"encoding/binary"
)

// PPP protocol numbers
const (
	pppProtoLCP  uint16 = 0xC021
	pppProtoPAP  uint16 = 0xC023
	pppProtoCHAP uint16 = 0xC223
	pppProtoEAP  uint16 = 0xC227
)

// LCP code values
const (
	lcpConfigRequest uint8 = 1
	lcpConfigAck     uint8 = 2
	lcpConfigNak     uint8 = 3
	lcpConfigReject  uint8 = 4
	lcpTermRequest   uint8 = 5
	lcpTermAck       uint8 = 6
	lcpEchoRequest   uint8 = 9
	lcpEchoReply     uint8 = 10
)

// LCP option types
const (
	lcpOptMRU                   uint8 = 1
	lcpOptAuthProtocol          uint8 = 3
	lcpOptMagicNumber           uint8 = 5
	lcpOptPFC                   uint8 = 7
	lcpOptACFC                  uint8 = 8
	lcpOptCallback              uint8 = 13
	lcpOptMRRU                  uint8 = 17
	lcpOptShortSeqNum           uint8 = 18
	lcpOptEndpointDiscriminator uint8 = 19
)

// parsePPPFrame extracts the PPP protocol and payload from a raw PPP frame.
// Handles both with and without FF 03 address/control bytes.
func parsePPPFrame(rawPPP []byte) (proto uint16, payload []byte) {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return 0, nil
	}
	if rawPPP[off]&0x01 == 1 {
		return uint16(rawPPP[off]), rawPPP[off+1:]
	}
	if off+2 > len(rawPPP) {
		return 0, nil
	}
	proto = binary.BigEndian.Uint16(rawPPP[off : off+2])
	return proto, rawPPP[off+2:]
}

func buildLCPPacket(code uint8, id byte, options []byte) []byte {
	pktLen := 4 + len(options)
	pkt := make([]byte, pktLen)
	pkt[0] = code
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	copy(pkt[4:], options)
	return pkt
}

func stripAuthProto(opts []byte) (authProto uint16, stripped []byte) {
	for len(opts) >= 2 {
		optType := opts[0]
		optLen := int(opts[1])
		if optLen < 2 || optLen > len(opts) {
			break
		}
		if optType == lcpOptAuthProtocol && optLen >= 4 {
			authProto = binary.BigEndian.Uint16(opts[2:4])
		} else {
			stripped = append(stripped, opts[:optLen]...)
		}
		opts = opts[optLen:]
	}
	return
}

type rewrittenServerLCP struct {
	UpstreamAuthProto uint16
	OriginalOpts      []byte
	WindowsOpts       []byte
	NakOpts           []byte
}

var lcpOptPAP = []byte{lcpOptAuthProtocol, 4, 0xC0, 0x23}

func rewriteServerLCPForWindows(opts []byte) rewrittenServerLCP {
	authProto, stripped := stripAuthProto(opts)
	windowsOpts := append([]byte(nil), stripped...)
	windowsOpts = append(windowsOpts, lcpOptPAP...)
	return rewrittenServerLCP{
		UpstreamAuthProto: authProto,
		OriginalOpts:      append([]byte(nil), opts...),
		WindowsOpts:       windowsOpts,
	}
}

func mediateServerLCPForBridge(opts []byte, maxMRU uint16) rewrittenServerLCP {
	authProto, stripped := stripAuthProto(opts)
	var nakOpts []byte
	if maxMRU > 0 {
		nakOpts = append(nakOpts, buildMRUNak(opts, maxMRU)...)
	}
	if authProto != 0 && authProto != pppProtoPAP {
		nakOpts = append(nakOpts, lcpOptPAP...)
	}
	if len(nakOpts) > 0 {
		return rewrittenServerLCP{
			UpstreamAuthProto: authProto,
			OriginalOpts:      append([]byte(nil), opts...),
			NakOpts:           nakOpts,
		}
	}

	windowsOpts := append([]byte(nil), stripped...)
	windowsOpts = append(windowsOpts, lcpOptPAP...)
	return rewrittenServerLCP{
		UpstreamAuthProto: authProto,
		OriginalOpts:      append([]byte(nil), opts...),
		WindowsOpts:       windowsOpts,
	}
}

func buildPAPResponse(code uint8, id byte, msg string) []byte {
	pktLen := 5 + len(msg)
	rawPPP := make([]byte, 4+pktLen)
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], pppProtoPAP)
	rawPPP[4] = code
	rawPPP[5] = id
	binary.BigEndian.PutUint16(rawPPP[6:8], uint16(pktLen))
	rawPPP[8] = byte(len(msg))
	copy(rawPPP[9:], msg)
	return rawPPP
}
