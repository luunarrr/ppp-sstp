package main

import (
	"encoding/binary"

	"go.uber.org/zap"
)

const (
	mssProtoIPv4 uint16 = 0x0021
	mssProtoIPv6 uint16 = 0x0057

	ipProtoTCP = 6

	tcpFlagSYN = 0x02

	tcpOptEnd    = 0
	tcpOptNOP    = 1
	tcpOptMSS    = 2
	tcpOptMSSLen = 4

	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40
	tcpMinHeaderLen  = 20

	ipv4TCPOverhead = 40 // 20 (IPv4) + 20 (TCP minimum)
	ipv6TCPOverhead = 60 // 40 (IPv6) + 20 (TCP minimum)
)

// ClampTCPMSS inspects a raw PPP frame and, if it contains a TCP SYN packet
// with an MSS option exceeding the limit implied by pppMTU, clamps the MSS
// in-place and fixes the TCP checksum. Returns true if the frame was modified.
//
// Handles both Protocol Field Compression (PFC, 1-byte protocol) and
// uncompressed (2-byte protocol) frames, with or without the FF 03 ACFC prefix.
func ClampTCPMSS(rawPPP []byte, pppMTU int, direction string, logger *zap.Logger) bool {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return false
	}

	var proto uint16
	if rawPPP[off]&0x01 == 1 {
		proto = uint16(rawPPP[off])
		off += 1
	} else {
		if off+2 > len(rawPPP) {
			return false
		}
		proto = binary.BigEndian.Uint16(rawPPP[off : off+2])
		off += 2
	}

	ip := rawPPP[off:]
	switch proto {
	case mssProtoIPv4:
		return clampIPv4(ip, pppMTU, direction, logger)
	case mssProtoIPv6:
		return clampIPv6(ip, pppMTU, direction, logger)
	default:
		return false
	}
}

func clampIPv4(ip []byte, pppMTU int, direction string, logger *zap.Logger) bool {
	if len(ip) < ipv4MinHeaderLen {
		return false
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < ipv4MinHeaderLen || len(ip) < ihl {
		return false
	}
	if ip[9] != ipProtoTCP {
		return false
	}
	tcp := ip[ihl:]
	maxMSS := uint16(pppMTU - ipv4TCPOverhead)
	return clampTCPOptions(tcp, maxMSS, direction, "IPv4", logger)
}

func clampIPv6(ip []byte, pppMTU int, direction string, logger *zap.Logger) bool {
	if len(ip) < ipv6HeaderLen {
		return false
	}
	if ip[6] != ipProtoTCP {
		return false
	}
	tcp := ip[ipv6HeaderLen:]
	maxMSS := uint16(pppMTU - ipv6TCPOverhead)
	return clampTCPOptions(tcp, maxMSS, direction, "IPv6", logger)
}

func clampTCPOptions(tcp []byte, maxMSS uint16, direction, proto string, logger *zap.Logger) bool {
	if len(tcp) < tcpMinHeaderLen {
		return false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < tcpMinHeaderLen || len(tcp) < dataOff {
		return false
	}
	flags := tcp[13]
	if flags&tcpFlagSYN == 0 {
		return false
	}

	opts := tcp[tcpMinHeaderLen:dataOff]
	for len(opts) > 0 {
		kind := opts[0]
		if kind == tcpOptEnd {
			break
		}
		if kind == tcpOptNOP {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 || int(opts[1]) < 2 || len(opts) < int(opts[1]) {
			break
		}
		if kind == tcpOptMSS && opts[1] == tcpOptMSSLen {
			oldMSS := binary.BigEndian.Uint16(opts[2:4])
			if oldMSS > maxMSS {
				binary.BigEndian.PutUint16(opts[2:4], maxMSS)
				updateTCPChecksum(tcp, oldMSS, maxMSS)
				logger.Info("MSS clamped",
					zap.String("direction", direction),
					zap.String("proto", proto),
					zap.Uint16("oldMSS", oldMSS),
					zap.Uint16("newMSS", maxMSS))
				return true
			}
			return false
		}
		opts = opts[int(opts[1]):]
	}
	return false
}

// updateTCPChecksum performs an RFC 1624 incremental checksum update after
// replacing oldMSS with newMSS. The TCP checksum is at bytes 16-17.
func updateTCPChecksum(tcp []byte, oldMSS, newMSS uint16) {
	cksum := uint32(^binary.BigEndian.Uint16(tcp[16:18]))
	cksum += uint32(^oldMSS)
	cksum += uint32(newMSS)
	for cksum>>16 != 0 {
		cksum = (cksum & 0xFFFF) + (cksum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(cksum))
}
