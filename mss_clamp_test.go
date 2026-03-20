package main

import (
	"encoding/binary"
	"testing"

	"go.uber.org/zap"
)

var testLogger = zap.NewNop()

// --- helpers ---

func buildIPv4TCPSYNNoPFC(mss uint16) []byte {
	ipHdrLen := 20
	tcpHdrLen := 24
	totalIPLen := ipHdrLen + tcpHdrLen

	ppp := make([]byte, 4+totalIPLen) // FF 03 + 2-byte proto + IP
	ppp[0] = 0xFF
	ppp[1] = 0x03
	binary.BigEndian.PutUint16(ppp[2:4], mssProtoIPv4)

	ip := ppp[4:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	ip[8] = 64
	ip[9] = 6
	ip[12] = 10; ip[15] = 1
	ip[16] = 10; ip[19] = 2

	tcp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = tcpFlagSYN
	tcp[20] = tcpOptMSS
	tcp[21] = tcpOptMSSLen
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	computeTCPChecksumV4(ip, tcp)
	return ppp
}

func buildIPv4TCPSYNPFC(mss uint16) []byte {
	ipHdrLen := 20
	tcpHdrLen := 24
	totalIPLen := ipHdrLen + tcpHdrLen

	// PFC: 1-byte proto 0x21
	ppp := make([]byte, 3+totalIPLen) // FF 03 + 1-byte proto + IP
	ppp[0] = 0xFF
	ppp[1] = 0x03
	ppp[2] = 0x21

	ip := ppp[3:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	ip[8] = 64
	ip[9] = 6
	ip[12] = 10; ip[15] = 1
	ip[16] = 10; ip[19] = 2

	tcp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = tcpFlagSYN
	tcp[20] = tcpOptMSS
	tcp[21] = tcpOptMSSLen
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	computeTCPChecksumV4(ip, tcp)
	return ppp
}

func buildIPv6TCPSYNNoPFC(mss uint16) []byte {
	tcpHdrLen := 24

	ppp := make([]byte, 4+ipv6HeaderLen+tcpHdrLen) // FF 03 + 2-byte proto
	ppp[0] = 0xFF
	ppp[1] = 0x03
	binary.BigEndian.PutUint16(ppp[2:4], mssProtoIPv6)

	ip := ppp[4:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(tcpHdrLen))
	ip[6] = 6
	ip[7] = 64
	ip[24] = 0xFE; ip[25] = 0x80; ip[39] = 1
	ip[40] = 0xFE; ip[41] = 0x80; ip[55] = 2

	tcp := ip[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = tcpFlagSYN
	tcp[20] = tcpOptMSS
	tcp[21] = tcpOptMSSLen
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	computeTCPChecksumV6(ip, tcp)
	return ppp
}

func buildIPv6TCPSYNPFC(mss uint16) []byte {
	tcpHdrLen := 24

	// PFC: 1-byte proto 0x57
	ppp := make([]byte, 3+ipv6HeaderLen+tcpHdrLen) // FF 03 + 1-byte proto
	ppp[0] = 0xFF
	ppp[1] = 0x03
	ppp[2] = 0x57

	ip := ppp[3:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(tcpHdrLen))
	ip[6] = 6
	ip[7] = 64
	ip[24] = 0xFE; ip[25] = 0x80; ip[39] = 1
	ip[40] = 0xFE; ip[41] = 0x80; ip[55] = 2

	tcp := ip[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = tcpFlagSYN
	tcp[20] = tcpOptMSS
	tcp[21] = tcpOptMSSLen
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	computeTCPChecksumV6(ip, tcp)
	return ppp
}

func buildIPv4TCPSYNPFC_NoACFC(mss uint16) []byte {
	ipHdrLen := 20
	tcpHdrLen := 24
	totalIPLen := ipHdrLen + tcpHdrLen

	// No ACFC (no FF 03), PFC: 1-byte proto
	ppp := make([]byte, 1+totalIPLen)
	ppp[0] = 0x21

	ip := ppp[1:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	ip[8] = 64
	ip[9] = 6
	ip[12] = 10; ip[15] = 1
	ip[16] = 10; ip[19] = 2

	tcp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = tcpFlagSYN
	tcp[20] = tcpOptMSS
	tcp[21] = tcpOptMSSLen
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	computeTCPChecksumV4(ip, tcp)
	return ppp
}

func buildIPv4TCPACK(pfc bool) []byte {
	ipHdrLen := 20
	tcpHdrLen := 20
	totalIPLen := ipHdrLen + tcpHdrLen

	var ppp []byte
	var ipStart int
	if pfc {
		ppp = make([]byte, 3+totalIPLen)
		ppp[0] = 0xFF; ppp[1] = 0x03; ppp[2] = 0x21
		ipStart = 3
	} else {
		ppp = make([]byte, 4+totalIPLen)
		ppp[0] = 0xFF; ppp[1] = 0x03
		binary.BigEndian.PutUint16(ppp[2:4], mssProtoIPv4)
		ipStart = 4
	}

	ip := ppp[ipStart:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalIPLen))
	ip[8] = 64
	ip[9] = 6
	ip[12] = 10; ip[15] = 1
	ip[16] = 10; ip[19] = 2

	tcp := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = byte(tcpHdrLen/4) << 4
	tcp[13] = 0x10 // ACK
	computeTCPChecksumV4(ip, tcp)
	return ppp
}

func computeTCPChecksumV4(ip, tcp []byte) {
	tcpLen := len(tcp)
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(ip[12:14]))
	sum += uint32(binary.BigEndian.Uint16(ip[14:16]))
	sum += uint32(binary.BigEndian.Uint16(ip[16:18]))
	sum += uint32(binary.BigEndian.Uint16(ip[18:20]))
	sum += uint32(ipProtoTCP)
	sum += uint32(tcpLen)
	tcp[16] = 0; tcp[17] = 0
	for i := 0; i+1 < tcpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(tcp[tcpLen-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
}

func computeTCPChecksumV6(ip, tcp []byte) {
	tcpLen := len(tcp)
	var sum uint32
	for i := 8; i < 24; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for i := 24; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	sum += uint32(tcpLen)
	sum += uint32(ipProtoTCP)
	tcp[16] = 0; tcp[17] = 0
	for i := 0; i+1 < tcpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(tcp[tcpLen-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
}

func extractMSS(ppp []byte) uint16 {
	off := 0
	if len(ppp) >= 2 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		off = 2
	}
	if ppp[off]&0x01 == 1 {
		off += 1
	} else {
		off += 2
	}
	ip := ppp[off:]
	var ipHdrLen int
	if ip[0]>>4 == 4 {
		ipHdrLen = int(ip[0]&0x0F) * 4
	} else {
		ipHdrLen = ipv6HeaderLen
	}
	tcp := ip[ipHdrLen:]
	return binary.BigEndian.Uint16(tcp[22:24])
}

func extractTCPCksum(ppp []byte) uint16 {
	off := 0
	if len(ppp) >= 2 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		off = 2
	}
	if ppp[off]&0x01 == 1 {
		off += 1
	} else {
		off += 2
	}
	ip := ppp[off:]
	var ipHdrLen int
	if ip[0]>>4 == 4 {
		ipHdrLen = int(ip[0]&0x0F) * 4
	} else {
		ipHdrLen = ipv6HeaderLen
	}
	tcp := ip[ipHdrLen:]
	return binary.BigEndian.Uint16(tcp[16:18])
}

func getIPAndTCP(ppp []byte) (ip, tcp []byte, isV6 bool) {
	off := 0
	if len(ppp) >= 2 && ppp[0] == 0xFF && ppp[1] == 0x03 {
		off = 2
	}
	if ppp[off]&0x01 == 1 {
		isV6 = ppp[off] == 0x57
		off += 1
	} else {
		proto := binary.BigEndian.Uint16(ppp[off : off+2])
		isV6 = proto == mssProtoIPv6
		off += 2
	}
	ip = ppp[off:]
	var ipHdrLen int
	if isV6 {
		ipHdrLen = ipv6HeaderLen
	} else {
		ipHdrLen = int(ip[0]&0x0F) * 4
	}
	tcp = ip[ipHdrLen:]
	return
}

// --- tests ---

func TestClampTCPMSS_PFC_IPv4_SYN_Clamped(t *testing.T) {
	pppMTU := 1400
	maxMSS := uint16(pppMTU - ipv4TCPOverhead)

	pkt := buildIPv4TCPSYNPFC(1460)
	modified := ClampTCPMSS(pkt, pppMTU, "tx", testLogger)
	if !modified {
		t.Fatal("expected clamping for PFC IPv4 SYN")
	}
	if got := extractMSS(pkt); got != maxMSS {
		t.Fatalf("MSS = %d, want %d", got, maxMSS)
	}
	verifyChecksum(t, pkt)
}

func TestClampTCPMSS_PFC_IPv6_SYN_Clamped(t *testing.T) {
	pppMTU := 1400
	maxMSS := uint16(pppMTU - ipv6TCPOverhead)

	pkt := buildIPv6TCPSYNPFC(1440)
	modified := ClampTCPMSS(pkt, pppMTU, "rx", testLogger)
	if !modified {
		t.Fatal("expected clamping for PFC IPv6 SYN")
	}
	if got := extractMSS(pkt); got != maxMSS {
		t.Fatalf("MSS = %d, want %d", got, maxMSS)
	}
	verifyChecksum(t, pkt)
}

func TestClampTCPMSS_NoPFC_IPv4_SYN_Clamped(t *testing.T) {
	pppMTU := 1400
	maxMSS := uint16(pppMTU - ipv4TCPOverhead)

	pkt := buildIPv4TCPSYNNoPFC(1460)
	modified := ClampTCPMSS(pkt, pppMTU, "tx", testLogger)
	if !modified {
		t.Fatal("expected clamping for non-PFC IPv4 SYN")
	}
	if got := extractMSS(pkt); got != maxMSS {
		t.Fatalf("MSS = %d, want %d", got, maxMSS)
	}
	verifyChecksum(t, pkt)
}

func TestClampTCPMSS_NoPFC_IPv6_SYN_Clamped(t *testing.T) {
	pppMTU := 1400
	maxMSS := uint16(pppMTU - ipv6TCPOverhead)

	pkt := buildIPv6TCPSYNNoPFC(1440)
	modified := ClampTCPMSS(pkt, pppMTU, "rx", testLogger)
	if !modified {
		t.Fatal("expected clamping for non-PFC IPv6 SYN")
	}
	if got := extractMSS(pkt); got != maxMSS {
		t.Fatalf("MSS = %d, want %d", got, maxMSS)
	}
	verifyChecksum(t, pkt)
}

func TestClampTCPMSS_PFC_NoACFC_IPv4_Clamped(t *testing.T) {
	pppMTU := 1400
	maxMSS := uint16(pppMTU - ipv4TCPOverhead)

	pkt := buildIPv4TCPSYNPFC_NoACFC(1460)
	modified := ClampTCPMSS(pkt, pppMTU, "tx", testLogger)
	if !modified {
		t.Fatal("expected clamping for PFC+no-ACFC IPv4 SYN")
	}
	if got := extractMSS(pkt); got != maxMSS {
		t.Fatalf("MSS = %d, want %d", got, maxMSS)
	}
	verifyChecksum(t, pkt)
}

func TestClampTCPMSS_PFC_NonSYN_Passthrough(t *testing.T) {
	pkt := buildIPv4TCPACK(true)
	origCksum := extractTCPCksum(pkt)
	modified := ClampTCPMSS(pkt, 1400, "tx", testLogger)
	if modified {
		t.Fatal("expected no clamping for non-SYN packet")
	}
	if extractTCPCksum(pkt) != origCksum {
		t.Fatal("checksum changed for non-SYN")
	}
}

func TestClampTCPMSS_NoPFC_NonSYN_Passthrough(t *testing.T) {
	pkt := buildIPv4TCPACK(false)
	origCksum := extractTCPCksum(pkt)
	modified := ClampTCPMSS(pkt, 1400, "tx", testLogger)
	if modified {
		t.Fatal("expected no clamping for non-SYN packet")
	}
	if extractTCPCksum(pkt) != origCksum {
		t.Fatal("checksum changed for non-SYN")
	}
}

func TestClampTCPMSS_MSS_BelowMax(t *testing.T) {
	pppMTU := 1400
	pkt := buildIPv4TCPSYNPFC(1300)
	origMSS := extractMSS(pkt)
	origCksum := extractTCPCksum(pkt)

	modified := ClampTCPMSS(pkt, pppMTU, "tx", testLogger)
	if modified {
		t.Fatal("expected no clamping when MSS below max")
	}
	if extractMSS(pkt) != origMSS {
		t.Fatal("MSS changed unexpectedly")
	}
	if extractTCPCksum(pkt) != origCksum {
		t.Fatal("checksum changed unexpectedly")
	}
}

func TestClampTCPMSS_NonIPProtocol(t *testing.T) {
	pkt := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x00, 0x00, 0x04}
	modified := ClampTCPMSS(pkt, 1400, "tx", testLogger)
	if modified {
		t.Fatal("expected no clamping for LCP frame")
	}
}

func TestClampTCPMSS_ExactMSS_NoClamp(t *testing.T) {
	pppMTU := 1400
	exactMSS := uint16(pppMTU - ipv4TCPOverhead)

	pkt := buildIPv4TCPSYNPFC(exactMSS)
	modified := ClampTCPMSS(pkt, pppMTU, "tx", testLogger)
	if modified {
		t.Fatal("expected no clamping when MSS equals max exactly")
	}
}

func verifyChecksum(t *testing.T, ppp []byte) {
	t.Helper()
	ip, tcp, isV6 := getIPAndTCP(ppp)
	savedCksum := binary.BigEndian.Uint16(tcp[16:18])
	if isV6 {
		computeTCPChecksumV6(ip, tcp)
	} else {
		computeTCPChecksumV4(ip, tcp)
	}
	recomputed := binary.BigEndian.Uint16(tcp[16:18])
	if savedCksum != recomputed {
		t.Fatalf("checksum mismatch: got 0x%04x, recomputed 0x%04x", savedCksum, recomputed)
	}
}
