package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var stdoutMu sync.Mutex

func writeToStdout(b []byte) (int, error) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	return os.Stdout.Write(b)
}

func sendLCPTerminate(logger *zap.Logger) {
	termReq := buildLCPPacket(lcpTermRequest, 1, nil)
	frame := makePPPFrame(pppProtoLCP, termReq)
	if _, err := writeToStdout(EncodeHDLC(frame)); err != nil {
		logger.Debug("failed to send LCP Terminate-Request", zap.Error(err))
		return
	}
	logger.Info("sent LCP Terminate-Request to server")
	time.Sleep(200 * time.Millisecond)
}

// PPP protocols used by MLPPP
const (
	pppProtoMP     uint16 = 0x003D
	pppProtoCCP    uint16 = 0x80FD
	pppProtoIPCP   uint16 = 0x8021
	pppProtoIPv6CP uint16 = 0x8057
)

// MP fragment header flags (short sequence number format, 12-bit)
const (
	mpFlagBegin uint8 = 0x80
	mpFlagEnd   uint8 = 0x40
	mpSeqMask         = 0x0FFF
)

func encodeMPFragment(begin, end bool, seq uint16, payload []byte) []byte {
	frame := make([]byte, 4+2+len(payload))
	frame[0] = 0xFF
	frame[1] = 0x03
	binary.BigEndian.PutUint16(frame[2:4], pppProtoMP)

	var flags uint8
	if begin {
		flags |= mpFlagBegin
	}
	if end {
		flags |= mpFlagEnd
	}
	frame[4] = flags | uint8((seq>>8)&0x0F)
	frame[5] = uint8(seq & 0xFF)
	copy(frame[6:], payload)
	return frame
}

func decodeMPFragment(rawPPP []byte) (begin, end bool, seq uint16, payload []byte, err error) {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return false, false, 0, nil, errors.New("mp: frame too short for protocol")
	}
	var proto uint16
	if rawPPP[off]&0x01 == 1 {
		proto = uint16(rawPPP[off])
		off += 1
	} else {
		if off+2 > len(rawPPP) {
			return false, false, 0, nil, errors.New("mp: frame too short for protocol")
		}
		proto = binary.BigEndian.Uint16(rawPPP[off : off+2])
		off += 2
	}
	if proto != pppProtoMP {
		return false, false, 0, nil, fmt.Errorf("mp: unexpected protocol 0x%04x", proto)
	}
	if off+2 > len(rawPPP) {
		return false, false, 0, nil, errors.New("mp: header too short")
	}
	begin = rawPPP[off]&mpFlagBegin != 0
	end = rawPPP[off]&mpFlagEnd != 0
	seq = uint16(rawPPP[off]&0x0F)<<8 | uint16(rawPPP[off+1])
	payload = rawPPP[off+2:]
	return begin, end, seq, payload, nil
}

type mpFragment struct {
	begin bool
	end   bool
	data  []byte
	ts    time.Time
}

type mpReassembler struct {
	mu        sync.Mutex
	fragments map[uint16]mpFragment
}

func newMPReassembler() *mpReassembler {
	return &mpReassembler{fragments: make(map[uint16]mpFragment)}
}

func (r *mpReassembler) AddFragment(rawPPP []byte) []byte {
	begin, end, seq, payload, err := decodeMPFragment(rawPPP)
	if err != nil || len(payload) == 0 {
		return nil
	}

	if begin && end {
		frame := make([]byte, 2+len(payload))
		frame[0] = 0xFF
		frame[1] = 0x03
		copy(frame[2:], payload)
		return frame
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.fragments[seq] = mpFragment{begin: begin, end: end, data: append([]byte(nil), payload...), ts: now}

	for startSeq, frag := range r.fragments {
		if !frag.begin {
			continue
		}
		assembled := append([]byte(nil), frag.data...)
		cur := startSeq
		complete := false
		for {
			next := (cur + 1) & mpSeqMask
			nf, ok := r.fragments[next]
			if !ok {
				break
			}
			assembled = append(assembled, nf.data...)
			if nf.end {
				complete = true
				delete(r.fragments, startSeq)
				for c := startSeq; ; {
					c = (c + 1) & mpSeqMask
					delete(r.fragments, c)
					if c == next {
						break
					}
				}
				break
			}
			cur = next
		}
		if complete {
			frame := make([]byte, 2+len(assembled))
			frame[0] = 0xFF
			frame[1] = 0x03
			copy(frame[2:], assembled)
			return frame
		}
	}

	if len(r.fragments) > 16 {
		for k, f := range r.fragments {
			if now.Sub(f.ts) > 5*time.Second {
				delete(r.fragments, k)
			}
		}
	}

	return nil
}

type mlpppLCPState struct {
	ourMagic      uint32
	mru           uint16
	mrru          uint16
	discriminator []byte
	authPAP       bool
	open          bool
	weAccepted    bool
	peerAccepted  bool
	sentRequest   bool
	nextID        uint8
	lastReqID     uint8

	wantShortSeq          bool
	shortSeqRejected      bool
	peerRequestedShortSeq bool
}

type bridgeAuthState struct {
	upstreamProto uint16
	windowsDone   bool
	upstreamDone  bool
	nakCount      int
}

func (s *bridgeAuthState) resetForLCP() {
	s.windowsDone = false
	s.upstreamDone = false
}

func (s *bridgeAuthState) setUpstreamProto(proto uint16) {
	s.upstreamProto = proto
	s.nakCount = 0
	s.resetForLCP()
}

func (s *bridgeAuthState) noteUnsupportedProposal() error {
	s.nakCount++
	if s.nakCount > 10 {
		return fmt.Errorf("upstream peer refused PAP fallback after %d Config-Nak attempts", s.nakCount-1)
	}
	return nil
}

func (s *bridgeAuthState) onWindowsPAPSuccess() (bool, error) {
	s.windowsDone = true
	switch s.upstreamProto {
	case 0:
		return false, nil
	case pppProtoPAP:
		return true, nil
	default:
		return false, fmt.Errorf("unsupported upstream auth method 0x%04x", s.upstreamProto)
	}
}

func (s *bridgeAuthState) markUpstreamPAPDone() {
	s.upstreamDone = true
}

func (s *bridgeAuthState) ready() bool {
	if !s.windowsDone {
		return false
	}
	switch s.upstreamProto {
	case 0:
		return true
	case pppProtoPAP:
		return s.upstreamDone
	default:
		return false
	}
}

func newMLPPPLCPState(magic uint32, mru uint16, mrru uint16, discriminator []byte) *mlpppLCPState {
	return &mlpppLCPState{
		ourMagic:      magic,
		mru:           mru,
		mrru:          mrru,
		discriminator: discriminator,
	}
}

func (s *mlpppLCPState) InitialRequest() []byte {
	req := s.buildConfigRequest()
	s.sentRequest = true
	return makePPPFrame(pppProtoLCP, req)
}

func (s *mlpppLCPState) HandleLCP(payload []byte) [][]byte {
	if len(payload) < 4 {
		return nil
	}
	code := payload[0]
	id := payload[1]

	switch code {
	case lcpConfigRequest:
		opts := payload[4:]
		for len(opts) >= 2 {
			optType := opts[0]
			optLen := int(opts[1])
			if optLen < 2 || optLen > len(opts) {
				break
			}
			if optType == lcpOptShortSeqNum {
				s.peerRequestedShortSeq = true
			}
			opts = opts[optLen:]
		}
		ack := buildLCPPacket(lcpConfigAck, id, payload[4:])
		resp := [][]byte{makePPPFrame(pppProtoLCP, ack)}
		s.weAccepted = true
		if !s.sentRequest {
			req := s.buildConfigRequest()
			resp = append(resp, makePPPFrame(pppProtoLCP, req))
			s.sentRequest = true
		}
		s.checkOpen()
		return resp

	case lcpConfigAck:
		if id != s.lastReqID {
			return nil
		}
		s.peerAccepted = true
		s.checkOpen()
		return nil

	case lcpConfigNak:
		if id != s.lastReqID {
			return nil
		}
		s.peerAccepted = false
		if len(payload) > 4 {
			options := payload[4:]
			for len(options) >= 2 {
				optType := options[0]
				optLen := int(options[1])
				if optLen < 2 || optLen > len(options) {
					break
				}
				if optType == lcpOptMRRU && optLen >= 4 {
					s.mrru = binary.BigEndian.Uint16(options[2:4])
				}
				options = options[optLen:]
			}
		}
		req := s.buildConfigRequest()
		return [][]byte{makePPPFrame(pppProtoLCP, req)}

	case lcpConfigReject:
		if id != s.lastReqID {
			return nil
		}
		s.peerAccepted = false
		if len(payload) > 4 {
			rejected := payload[4:]
			for len(rejected) >= 2 {
				optType := rejected[0]
				optLen := int(rejected[1])
				if optLen < 2 || optLen > len(rejected) {
					break
				}
				if optType == lcpOptMRRU {
					s.mrru = 0
				}
				if optType == lcpOptEndpointDiscriminator {
					s.discriminator = nil
				}
				if optType == lcpOptShortSeqNum {
					s.shortSeqRejected = true
				}
				rejected = rejected[optLen:]
			}
		}
		req := s.buildConfigRequest()
		return [][]byte{makePPPFrame(pppProtoLCP, req)}

	case lcpEchoRequest:
		reply := make([]byte, 8)
		reply[0] = lcpEchoReply
		reply[1] = id
		binary.BigEndian.PutUint16(reply[2:4], 8)
		binary.BigEndian.PutUint32(reply[4:8], s.ourMagic)
		return [][]byte{makePPPFrame(pppProtoLCP, reply)}

	case lcpTermRequest:
		termAck := buildLCPPacket(lcpTermAck, id, nil)
		return [][]byte{makePPPFrame(pppProtoLCP, termAck)}
	}

	return nil
}

func (s *mlpppLCPState) IsOpen() bool { return s.open }

func (s *mlpppLCPState) checkOpen() {
	if s.weAccepted && s.peerAccepted {
		s.open = true
	}
}

func splitOptions(options []byte) (mlppp, rest []byte) {
	for len(options) >= 2 {
		optType := options[0]
		optLen := int(options[1])
		if optLen < 2 || optLen > len(options) {
			break
		}
		if optType == lcpOptMRRU || optType == lcpOptShortSeqNum || optType == lcpOptEndpointDiscriminator {
			mlppp = append(mlppp, options[:optLen]...)
		} else {
			rest = append(rest, options[:optLen]...)
		}
		options = options[optLen:]
	}
	return
}

// splitRejectableOptions separates options that the bridge should Config-Reject
// (unsupported by typical LNS implementations) from options to keep.
func splitRejectableOptions(options []byte) (reject, keep []byte) {
	for len(options) >= 2 {
		optType := options[0]
		optLen := int(options[1])
		if optLen < 2 || optLen > len(options) {
			break
		}
		switch optType {
		case lcpOptCallback:
			reject = append(reject, options[:optLen]...)
		default:
			keep = append(keep, options[:optLen]...)
		}
		options = options[optLen:]
	}
	return
}

const mlpppOverhead = 4

// extractMRU scans LCP options for the MRU option (type 1, length 4) and returns
// its value. Returns 0 if no MRU option is present.
func extractMRU(opts []byte) uint16 {
	for i := 0; i+1 < len(opts); {
		optType := opts[i]
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if optType == lcpOptMRU && optLen == 4 {
			return binary.BigEndian.Uint16(opts[i+2 : i+4])
		}
		i += optLen
	}
	return 0
}

// buildMRUNak checks opts for an MRU option: if present and > maxMRU, returns a
// NAK containing MRU=maxMRU. If MRU is absent and maxMRU < 1500 (the default),
// returns a NAK containing MRU=maxMRU per RFC 1661 (advising desired value for
// missing options). Returns nil when no NAK is needed.
func buildMRUNak(opts []byte, maxMRU uint16) []byte {
	found := false
	for i := 0; i+1 < len(opts); {
		optType := opts[i]
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if optType == lcpOptMRU && optLen == 4 {
			found = true
			val := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if val > maxMRU {
				buf := [4]byte{lcpOptMRU, 4}
				binary.BigEndian.PutUint16(buf[2:4], maxMRU)
				return buf[:]
			}
		}
		i += optLen
	}
	if !found && maxMRU < 1500 {
		buf := [4]byte{lcpOptMRU, 4}
		binary.BigEndian.PutUint16(buf[2:4], maxMRU)
		return buf[:]
	}
	return nil
}

func buildMLPPPOptions(mrru uint16, discriminator []byte, shortSeq bool) []byte {
	var opts []byte
	if mrru > 0 {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, mrru)
		opts = append(opts, lcpOptMRRU, 4)
		opts = append(opts, buf...)
	}
	if shortSeq {
		opts = append(opts, lcpOptShortSeqNum, 2)
	}
	if len(discriminator) > 0 {
		edLen := byte(3 + len(discriminator))
		opts = append(opts, lcpOptEndpointDiscriminator, edLen)
		opts = append(opts, 1) // Class 1 = Locally Assigned Address
		opts = append(opts, discriminator...)
	}
	return opts
}

func (s *mlpppLCPState) buildConfigRequest() []byte {
	s.nextID++
	s.lastReqID = s.nextID
	var opts []byte

	opts = append(opts, lcpOptMRU, 4)
	mruBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(mruBuf, s.mru)
	opts = append(opts, mruBuf...)

	if s.authPAP {
		opts = append(opts, lcpOptAuthProtocol, 4, 0xC0, 0x23)
	}

	opts = append(opts, lcpOptMagicNumber, 6)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, s.ourMagic)
	opts = append(opts, buf...)

	if s.mrru > 0 {
		opts = append(opts, buildMLPPPOptions(s.mrru, s.discriminator, s.wantShortSeq && !s.shortSeqRejected)...)
	}

	return buildLCPPacket(lcpConfigRequest, s.nextID, opts)
}

func makePPPFrame(proto uint16, payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	frame[0] = 0xFF
	frame[1] = 0x03
	binary.BigEndian.PutUint16(frame[2:4], proto)
	copy(frame[4:], payload)
	return frame
}

const (
	papLocalUser = "hysteria"
	papLocalPass = "hysteria"
)

type SSTPBridge struct {
	ListenAddr    string
	CertDir       string
	Logger        *zap.Logger
	Discriminator string
	PAPUser       string
	PAPPass       string
	MTU           int
	MSSClamp      *int // nil=auto, 0=off, >0=forced
	IPCServer     *IPCServer
	ServerRouteIP string
}

func (b *SSTPBridge) Run() error {
	if b.Discriminator != "" && b.PAPUser == "" {
		return errors.New("PAPUser is required when Discriminator is set (MLPPP workers need credentials)")
	}

	if err := GenerateCerts(b.CertDir); err != nil {
		return fmt.Errorf("failed to generate certs: %w", err)
	}

	certPath := filepath.Join(b.CertDir, "server.crt")
	keyPath := filepath.Join(b.CertDir, "server.key")
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load cert: %w", err)
	}
	certHash := sha256.Sum256(serverCert.Certificate[0])

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	rawLn, err := net.Listen("tcp", b.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer rawLn.Close()

	numLinks := 1
	if b.IPCServer != nil {
		numLinks = b.IPCServer.NumLinks()
	}
	b.Logger.Info("SSTP bridge listening",
		zap.String("addr", b.ListenAddr),
		zap.String("certDir", b.CertDir),
		zap.String("discriminator", b.Discriminator),
		zap.Int("numLinks", numLinks))

	stdinCh := make(chan []byte, 64)
	stdinClosed := make(chan struct{})
	go func() {
		defer close(stdinClosed)
		defer close(stdinCh)
		buf := make([]byte, 16384)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				stdinCh <- chunk
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		<-stdinClosed
		rawLn.Close()
	}()

	if b.IPCServer != nil {
		go b.IPCServer.AcceptWorkers(b.Logger)
		defer b.IPCServer.Close()
	}

	rawConn, err := rawLn.Accept()
	if err != nil {
		return fmt.Errorf("accept failed: %w", err)
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn := tls.Server(rawConn, tlsConfig)
	defer conn.Close()
	rawLn.Close()

	var rs *routeState
	if b.ServerRouteIP != "" {
		rs = captureRouteState(b.ServerRouteIP, b.Logger)
		if rs != nil {
			defer rs.Cleanup()
		}
	}

	b.Logger.Info("SSTP client connected", zap.String("remoteAddr", conn.RemoteAddr().String()))

	reader := bufio.NewReader(conn)
	method, path, err := readSSTPHTTPRequest(reader)
	if err != nil {
		return fmt.Errorf("HTTP handshake failed: %w", err)
	}
	if !strings.HasSuffix(path, sstpDuplexURI) || method != "SSTP_DUPLEX_POST" {
		return fmt.Errorf("unexpected request: %s %s", method, path)
	}

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nServer: Microsoft-HTTPAPI/2.0\r\nDate: %s\r\n\r\n",
		time.Now().UTC().Format(http.TimeFormat))
	if _, err := conn.Write([]byte(resp)); err != nil {
		return fmt.Errorf("HTTP response failed: %w", err)
	}

	nonce, err := sstpHandshake(conn, reader)
	if err != nil {
		return fmt.Errorf("SSTP handshake failed: %w", err)
	}

	return b.bridgeLoop(conn, reader, nonce, certHash, stdinCh, rs)
}

func (b *SSTPBridge) bridgeLoop(sstpConn net.Conn, sstpReader *bufio.Reader, nonce [32]byte, certHash [32]byte, stdinCh <-chan []byte, rs *routeState) error {
	mlpppMode := b.IPCServer != nil
	var vpnMTU uint16
	var relayMRRU uint16
	var discriminator []byte

	if mlpppMode {
		linkMTU := b.IPCServer.MinMTU(b.MTU)
		if linkMTU > mlpppOverhead {
			vpnMTU = uint16(linkMTU - mlpppOverhead)
			relayMRRU = vpnMTU
		}
		discriminator = []byte(b.Discriminator)
	} else if b.MTU > 0 {
		vpnMTU = uint16(b.MTU)
	}
	var mpNegotiated atomic.Bool

	var mssClampMTU int
	if b.MSSClamp == nil {
		mssClampMTU = int(vpnMTU) // auto: use negotiated VPN MTU
	} else if *b.MSSClamp == 0 {
		mssClampMTU = 0 // disabled
	} else {
		mssClampMTU = *b.MSSClamp // forced value
	}
	if mssClampMTU > 0 {
		b.Logger.Info("MSS clamping active",
			zap.Int("mssClampMTU", mssClampMTU),
			zap.Int("maxMSS_IPv4", mssClampMTU-ipv4TCPOverhead),
			zap.Int("maxMSS_IPv6", mssClampMTU-ipv6TCPOverhead))
	} else {
		b.Logger.Info("MSS clamping disabled")
	}

	b.Logger.Info("LCP negotiation starting",
		zap.Int("masterMTU", b.MTU),
		zap.Uint16("vpnMTU", vpnMTU),
		zap.Uint16("relayMRRU", relayMRRU),
		zap.Bool("mlpppMode", mlpppMode),
		zap.String("discriminator", b.Discriminator))

	var wg sync.WaitGroup
	errCh := make(chan error, 6)
	done := make(chan struct{})
	toWindows := make(chan []byte, 64)
	var sstpMu sync.Mutex
	var fragSeq atomic.Uint32
	sstpBuf := bufio.NewWriterSize(sstpConn, 16384)
	var negMu sync.Mutex

	var injectedOpts []byte
	var strippedOpts []byte
	var serverReqOpts []byte
	var shortSeqRejected bool
	var peerRequestedShortSeq bool
	var serverAcked bool
	var windowsAcked bool
	var lastToServerReqID uint8
	var lastToWindowsReqID uint8
	var authState bridgeAuthState
	var startBroadcasted bool
	var windowsMRU uint16

	reassembly := newMPReassembler()

	sendToWindows := func(pppFrame []byte) error {
		sstpMu.Lock()
		defer sstpMu.Unlock()
		if err := writeSSTPData(sstpBuf, pppFrame); err != nil {
			return err
		}
		return sstpBuf.Flush()
	}

	sendToServer := func(pppFrame []byte) error {
		_, err := writeToStdout(EncodeHDLC(pppFrame))
		return err
	}

	authReady := func() bool {
		negMu.Lock()
		ready := authState.ready()
		negMu.Unlock()
		return ready
	}

	tryBroadcastStart := func() {
		if b.IPCServer == nil {
			return
		}
		if startBroadcasted {
			return
		}
		if !serverAcked || !windowsAcked {
			return
		}
		if !authState.ready() {
			return
		}
		if shortSeqRejected {
			errCh <- errors.New("server rejected short-seq, cannot continue")
			return
		}
		if !peerRequestedShortSeq {
			errCh <- errors.New("server did not request short-seq, cannot use short format")
			return
		}
		if relayMRRU == 0 {
			b.Logger.Warn("MRRU rejected by server, falling back to single-link (no MP)")
			return
		}
		startBroadcasted = true
		mpNegotiated.Store(true)
		b.Logger.Info("LCP relay complete, broadcasting start to workers",
			zap.Uint16("mrru", relayMRRU),
			zap.Bool("shortSeq", true),
			zap.Int("numLinks", b.IPCServer.NumLinks()))
		payload := make([]byte, 3)
		binary.BigEndian.PutUint16(payload[0:2], relayMRRU)
		payload[2] = 1
		b.IPCServer.Broadcast(IPCMessage{Type: ipcMsgStart, Payload: payload})
	}

	distributeFragment := func(pppPayload []byte) {
		seq := uint16(fragSeq.Add(1) & uint32(mpSeqMask))
		mpFrame := encodeMPFragment(true, true, seq, pppPayload)
		numLinks := b.IPCServer.ActiveNumLinks()
		linkIdx := int(seq) % numLinks

		if ce := b.Logger.Check(zap.DebugLevel, "MP distribute"); ce != nil {
			ce.Write(zap.Uint16("seq", seq), zap.Int("link", linkIdx),
				zap.Int("totalLinks", numLinks), zap.Int("bytes", len(pppPayload)))
		}

		if linkIdx == 0 {
			_ = sendToServer(mpFrame)
		} else {
			workers := b.IPCServer.ActiveWorkers()
			wIdx := linkIdx - 1
			if wIdx < len(workers) {
				_ = workers[wIdx].SendTo(IPCMessage{Type: ipcMsgTXFragment, Payload: mpFrame})
			} else {
				_ = sendToServer(mpFrame)
			}
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pppFrame, isData, err := readSSTPPacket(sstpReader)
			if err != nil {
				errCh <- err
				return
			}
			if !isData {
				if len(pppFrame) < 4 {
					continue
				}
				mt := binary.BigEndian.Uint16(pppFrame[0:2])
				switch mt {
				case sstpMsgCallConnected:
					if err := verifyCryptoBinding(pppFrame, nonce, certHash); err != nil {
						b.Logger.Error("SSTP CryptoBinding verification failed, aborting", zap.Error(err))
						sstpMu.Lock()
						_ = writeSSTPControl(sstpBuf, sstpMsgCallAbort, nil)
						_ = sstpBuf.Flush()
						sstpMu.Unlock()
						errCh <- fmt.Errorf("CryptoBinding verification failed: %w", err)
						return
					}
					b.Logger.Info("SSTP CALL_CONNECTED verified")
					if rs != nil {
						go rs.ApplyRoutes()
					}
			case sstpMsgEchoRequest:
				sstpMu.Lock()
				_ = writeSSTPControl(sstpBuf, sstpMsgEchoResponse, nil)
				_ = sstpBuf.Flush()
				sstpMu.Unlock()
			case sstpMsgCallDisconnect:
				errCh <- errors.New("SSTP client disconnected")
				sstpMu.Lock()
				_ = writeSSTPControl(sstpBuf, sstpMsgCallDisconnectAck, nil)
				_ = sstpBuf.Flush()
				sstpMu.Unlock()
					return
				case sstpMsgCallAbort:
					errCh <- errors.New("SSTP client aborted")
					return
				}
				continue
			}

			proto, payload := parsePPPFrame(pppFrame)
			switch {
			case proto == pppProtoLCP:
				if len(payload) < 4 {
					continue
				}
				code := payload[0]
				id := payload[1]
				opts := payload[4:]
				switch code {
			case lcpConfigRequest:
				negMu.Lock()
				if mru := extractMRU(opts); mru > 0 {
					windowsMRU = mru
					if windowsMRU < vpnMTU {
						vpnMTU = windowsMRU
					}
				}
				rejOpts, cleanOpts := splitRejectableOptions(opts)
				if len(rejOpts) > 0 {
					negMu.Unlock()
					b.Logger.Info("LCP Config-Reject (Bridge->Windows)",
						zap.Int("rejectedLen", len(rejOpts)))
					pkt := buildLCPPacket(lcpConfigReject, id, rejOpts)
					if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
						errCh <- err
						return
					}
					continue
				}
				var outFrame []byte
				if mlpppMode {
					injectedOpts = buildMLPPPOptions(relayMRRU, discriminator, !shortSeqRejected)
					augmented := append(append([]byte(nil), cleanOpts...), injectedOpts...)
					outFrame = makePPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, id, augmented))
				}
				authState.resetForLCP()
				serverAcked = false
				lastToServerReqID = id
				logMRRU := relayMRRU
				negMu.Unlock()
				if mlpppMode {
					if err := sendToServer(outFrame); err != nil {
						errCh <- err
						return
					}
					b.Logger.Info("LCP Config-Request (Windows->Server)",
						zap.Int("injectedOptsLen", len(injectedOpts)),
						zap.Uint16("relayMRRU", logMRRU))
				} else {
					if err := sendToServer(pppFrame); err != nil {
						errCh <- err
						return
					}
				}
				case lcpConfigAck:
					negMu.Lock()
					var outFrame []byte
					if len(serverReqOpts) > 0 {
						outFrame = makePPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, id, serverReqOpts))
					}
					if id == lastToWindowsReqID {
						windowsAcked = true
						tryBroadcastStart()
					}
					logWinAcked := windowsAcked
					negMu.Unlock()
					b.Logger.Info("LCP Config-Ack (Windows->Server)", zap.Bool("windowsAcked", logWinAcked))
					if outFrame != nil {
						if err := sendToServer(outFrame); err != nil {
							errCh <- err
							return
						}
					} else {
						if err := sendToServer(pppFrame); err != nil {
							errCh <- err
							return
						}
					}
				case lcpConfigNak, lcpConfigReject:
					negMu.Lock()
					if id == lastToWindowsReqID {
						windowsAcked = false
					}
					negMu.Unlock()
					if err := sendToServer(pppFrame); err != nil {
						errCh <- err
						return
					}
				default:
					if err := sendToServer(pppFrame); err != nil {
						errCh <- err
						return
					}
				}

			case proto == pppProtoPAP:
				if len(payload) >= 4 && payload[0] == 1 {
					peerUser, peerPass := parsePAPAuthRequest(payload)
					if peerUser == papLocalUser && peerPass == papLocalPass {
						_ = sendToWindows(buildPAPResponse(2, payload[1], "OK"))
						negMu.Lock()
						sendUpstreamPAP, authErr := authState.onWindowsPAPSuccess()
						tryBroadcastStart()
						negMu.Unlock()
						if authErr != nil {
							errCh <- authErr
							return
						}
						b.Logger.Info("PAP authentication succeeded (Windows)")
						if sendUpstreamPAP {
							if b.PAPUser != "" {
								papReq := buildPAPAuthRequest(1, b.PAPUser, b.PAPPass)
								if err := sendToServer(papReq); err != nil {
									errCh <- err
									return
								}
							} else {
								papReq := buildPAPAuthRequest(1, peerUser, peerPass)
								if err := sendToServer(papReq); err != nil {
									errCh <- err
									return
								}
							}
						}
					} else {
						_ = sendToWindows(buildPAPResponse(3, payload[1], "bad credentials"))
						errCh <- errors.New("Windows PAP auth failed")
						return
					}
				}

			default:
				if !authReady() {
					b.Logger.Debug("dropping pre-auth PPP frame from Windows", zap.Uint16("proto", proto))
					continue
				}
				if mpNegotiated.Load() {
					off := 0
					if len(pppFrame) >= 2 && pppFrame[0] == 0xFF && pppFrame[1] == 0x03 {
						off = 2
					}
					if off < len(pppFrame) {
						if proto == pppProtoIPCP || proto == pppProtoIPv6CP || proto == pppProtoCCP {
							seq := uint16(fragSeq.Add(1) & uint32(mpSeqMask))
							mpFrame := encodeMPFragment(true, true, seq, pppFrame[off:])
							if err := sendToServer(mpFrame); err != nil {
								errCh <- err
								return
							}
						} else {
							distributeFragment(pppFrame[off:])
						}
					}
				} else {
					if mssClampMTU > 0 {
						ClampTCPMSS(pppFrame, mssClampMTU, "tx", b.Logger)
					}
					hdlcFrame := EncodeHDLC(pppFrame)
					if _, err := writeToStdout(hdlcFrame); err != nil {
						errCh <- fmt.Errorf("stdout write error: %w", err)
						return
					}
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var hdlcBuf []byte
		for {
			select {
			case chunk, ok := <-stdinCh:
				if !ok {
					errCh <- errors.New("stdin closed")
					return
				}
				hdlcBuf = append(hdlcBuf, chunk...)
				for {
					frame, rest, ok := extractHDLCFrame(hdlcBuf)
					if !ok {
						break
					}
					hdlcBuf = rest
					rawPPP, decErr := decodeHDLCFramePayload(frame)
					if decErr != nil {
						continue
					}
					proto, payload := parsePPPFrame(rawPPP)
					switch {
					case proto == pppProtoLCP:
						if len(payload) < 4 {
							continue
						}
						code := payload[0]
						id := payload[1]
						opts := payload[4:]
						if mlpppMode {
							switch code {
							case lcpConfigRequest:
								mlpppOpts, restOpts := splitOptions(opts)
								negMu.Lock()
								serverReqOpts = nil
								windowsAcked = false
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptShortSeqNum {
										peerRequestedShortSeq = true
									}
									scan = scan[optLen:]
								}
								decision := mediateServerLCPForBridge(restOpts, vpnMTU)
								if len(decision.NakOpts) > 0 {
									if decision.UpstreamAuthProto != 0 && decision.UpstreamAuthProto != pppProtoPAP {
										if err := authState.noteUnsupportedProposal(); err != nil {
											negMu.Unlock()
											errCh <- err
											return
										}
									}
									logVpnMTU := vpnMTU
									negMu.Unlock()
									b.Logger.Info("LCP Config-Nak (Bridge->Server)",
										zap.Int("nakOptsLen", len(decision.NakOpts)),
										zap.Uint16("vpnMTU", logVpnMTU))
									pkt := buildLCPPacket(lcpConfigNak, id, decision.NakOpts)
									if err := sendToServer(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								} else {
									rewrite := decision
									serverReqOpts = append([]byte(nil), opts...)
									strippedOpts = mlpppOpts
									authState.setUpstreamProto(rewrite.UpstreamAuthProto)
									logPeerShortSeq := peerRequestedShortSeq
									logVpnMTU := vpnMTU
									lastToWindowsReqID = id
									negMu.Unlock()
									b.Logger.Info("LCP Config-Request (Server->Windows)",
										zap.Int("strippedOptsLen", len(strippedOpts)),
										zap.Bool("peerRequestedShortSeq", logPeerShortSeq),
										zap.Uint16("vpnMTU", logVpnMTU),
										zap.Uint16("serverAuthProto", rewrite.UpstreamAuthProto))
									pkt := buildLCPPacket(lcpConfigRequest, id, rewrite.WindowsOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								}
							case lcpConfigAck:
								_, restOpts := splitOptions(opts)
								negMu.Lock()
								if id == lastToServerReqID {
									serverAcked = true
									tryBroadcastStart()
								}
								logSrvAcked := serverAcked
								negMu.Unlock()
								b.Logger.Info("LCP Config-Ack (Server->Windows)", zap.Bool("serverAcked", logSrvAcked))
								pkt := buildLCPPacket(lcpConfigAck, id, restOpts)
								if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
									errCh <- err
									return
								}
							case lcpConfigNak:
								mlpppOpts, restOpts := splitOptions(opts)
								negMu.Lock()
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptMRRU && optLen >= 4 {
										oldMRRU := relayMRRU
										relayMRRU = binary.BigEndian.Uint16(scan[2:4])
										b.Logger.Info("Server NAK'd MRRU",
											zap.Uint16("oldMRRU", oldMRRU),
											zap.Uint16("newMRRU", relayMRRU))
									}
									scan = scan[optLen:]
								}
								if id == lastToServerReqID {
									serverAcked = false
								}
								negMu.Unlock()
								if len(restOpts) > 0 {
									pkt := buildLCPPacket(lcpConfigNak, id, restOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								}
							case lcpConfigReject:
								mlpppOpts, restOpts := splitOptions(opts)
								negMu.Lock()
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptShortSeqNum {
										shortSeqRejected = true
										b.Logger.Info("Server Rejected ShortSeq")
									}
									if scan[0] == lcpOptMRRU {
										relayMRRU = 0
										b.Logger.Info("Server Rejected MRRU, degrading to single-link")
									}
									scan = scan[optLen:]
								}
								if id == lastToServerReqID {
									serverAcked = false
								}
								negMu.Unlock()
								if len(restOpts) > 0 {
									pkt := buildLCPPacket(lcpConfigReject, id, restOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								}
							default:
								if err := sendToWindows(rawPPP); err != nil {
									errCh <- err
									return
								}
							}
						} else {
							switch code {
							case lcpConfigRequest:
								negMu.Lock()
								serverReqOpts = nil
								windowsAcked = false
								decision := mediateServerLCPForBridge(opts, vpnMTU)
								if len(decision.NakOpts) > 0 {
									if decision.UpstreamAuthProto != 0 && decision.UpstreamAuthProto != pppProtoPAP {
										if err := authState.noteUnsupportedProposal(); err != nil {
											negMu.Unlock()
											errCh <- err
											return
										}
									}
									logVpnMTU := vpnMTU
									negMu.Unlock()
									b.Logger.Info("LCP Config-Nak (Bridge->Server)",
										zap.Int("nakOptsLen", len(decision.NakOpts)),
										zap.Uint16("vpnMTU", logVpnMTU))
									pkt := buildLCPPacket(lcpConfigNak, id, decision.NakOpts)
									if err := sendToServer(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
									break
								}
								rewrite := decision
								serverReqOpts = rewrite.OriginalOpts
								authState.setUpstreamProto(rewrite.UpstreamAuthProto)
								lastToWindowsReqID = id
								negMu.Unlock()
								pkt := buildLCPPacket(lcpConfigRequest, id, rewrite.WindowsOpts)
								if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
									errCh <- err
									return
								}
							case lcpConfigAck:
								negMu.Lock()
								if id == lastToServerReqID {
									serverAcked = true
									tryBroadcastStart()
								}
								logSrvAcked := serverAcked
								negMu.Unlock()
								b.Logger.Info("LCP Config-Ack (Server->Windows)", zap.Bool("serverAcked", logSrvAcked))
								if err := sendToWindows(rawPPP); err != nil {
									errCh <- err
									return
								}
							default:
								if err := sendToWindows(rawPPP); err != nil {
									errCh <- err
									return
								}
							}
						}

					case proto == pppProtoPAP:
						if len(payload) >= 1 {
							if payload[0] == 2 {
								negMu.Lock()
								authState.markUpstreamPAPDone()
								logWinPAP := authState.windowsDone
								tryBroadcastStart()
								negMu.Unlock()
								b.Logger.Info("PAP authentication succeeded (server)")
								b.Logger.Info("PAP completed",
									zap.Bool("windowsAuthDone", logWinPAP),
									zap.Bool("serverAuthDone", true))
							} else if payload[0] == 3 {
								errCh <- errors.New("PAP authentication rejected by server")
								return
							}
						}

				case proto == pppProtoCHAP || proto == pppProtoEAP:
					errCh <- fmt.Errorf("received unsupported auth protocol 0x%04x from server", proto)
					return

				case proto == pppProtoMP:
					if !authReady() {
						b.Logger.Debug("dropping pre-auth PPP frame from server", zap.Uint16("proto", proto))
						continue
					}
					if assembled := reassembly.AddFragment(rawPPP); assembled != nil {
						select {
						case toWindows <- assembled:
						default:
							b.Logger.Warn("toWindows buffer full, backpressure active")
							select {
							case toWindows <- assembled:
							case <-done:
								return
							}
						}
					}

				default:
					if !authReady() {
						b.Logger.Debug("dropping pre-auth PPP frame from server", zap.Uint16("proto", proto))
						continue
					}
					if mpNegotiated.Load() {
						select {
						case toWindows <- rawPPP:
						default:
							b.Logger.Warn("toWindows buffer full, backpressure active")
							select {
							case toWindows <- rawPPP:
							case <-done:
								return
							}
						}
					} else {
						if mssClampMTU > 0 {
							ClampTCPMSS(rawPPP, mssClampMTU, "rx", b.Logger)
						}
						sstpMu.Lock()
						writeErr := writeSSTPData(sstpBuf, rawPPP)
						sstpMu.Unlock()
						if writeErr != nil {
							errCh <- fmt.Errorf("SSTP data write error: %w", writeErr)
							return
						}
					}
				}
				}
				// Flush buffered SSTP writes after processing all frames from this chunk
				sstpMu.Lock()
				flushErr := sstpBuf.Flush()
				sstpMu.Unlock()
				if flushErr != nil {
					errCh <- fmt.Errorf("SSTP flush error: %w", flushErr)
					return
				}
			case <-done:
				return
			}
		}
	}()

	if b.IPCServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
			case msg, ok := <-b.IPCServer.RxCh:
				if !ok {
					return
				}
				if msg.Type == ipcMsgRXFragment {
					if assembled := reassembly.AddFragment(msg.Payload); assembled != nil {
						select {
						case toWindows <- assembled:
						default:
							b.Logger.Warn("toWindows buffer full, backpressure active (IPC)")
							select {
							case toWindows <- assembled:
							case <-done:
								return
							}
						}
					}
				}
			case <-done:
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case frame, ok := <-toWindows:
				if !ok {
					return
				}
				if err := sendToWindows(frame); err != nil {
					errCh <- err
					return
				}
			case <-done:
				return
			}
		}
	}()

	err := <-errCh
	close(done)
	_ = sstpConn.Close()
	if b.IPCServer != nil {
		b.IPCServer.Close()
	}
	wg.Wait()

	sendLCPTerminate(b.Logger)

	if !mpNegotiated.Load() && relayMRRU == 0 && b.Discriminator == "" {
		b.Logger.Info("Single-link PPP mode")
	}

	b.Logger.Info("SSTP session ended", zap.Error(err))
	return err
}

type MLPPPWorker struct {
	ListenAddr    string
	CertDir       string
	Discriminator string
	PAPUser       string
	PAPPass       string
	MTU           int
	Logger        *zap.Logger
	ServerRouteIP string
}

func (w *MLPPPWorker) Run() error {
	for {
		client, err := DialMaster(w.Discriminator)
		if err != nil {
			isMaster, ipcServer, tryErr := TryBecomeMaster(w.Discriminator)
			if tryErr != nil {
				return tryErr
			}
			if isMaster {
				w.Logger.Info("MLPPP worker promoted to master")
				m := &SSTPBridge{
					ListenAddr:    w.ListenAddr,
					CertDir:       w.CertDir,
					Discriminator: w.Discriminator,
					PAPUser:       w.PAPUser,
					PAPPass:       w.PAPPass,
					MTU:           w.MTU,
					IPCServer:     ipcServer,
					Logger:        w.Logger,
					ServerRouteIP: w.ServerRouteIP,
				}
				return m.Run()
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if regErr := client.SendRegister(w.MTU); regErr != nil {
			client.Close()
			w.Logger.Warn("MLPPP registration send failed, retrying", zap.Error(regErr))
			continue
		}
		linkIndex, totalLinks, welcomeErr := client.ReadWelcome()
		if welcomeErr != nil {
			client.Close()
			w.Logger.Warn("MLPPP welcome read failed, retrying", zap.Error(welcomeErr))
			continue
		}
		w.Logger.Info("MLPPP bridge: worker",
			zap.Int("linkIndex", linkIndex),
			zap.Int("totalLinks", totalLinks),
			zap.String("discriminator", w.Discriminator))

		err = w.runWorker(client)
		if err != nil {
			w.Logger.Info("MLPPP worker IPC lost, attempting promotion", zap.Error(err))
			continue
		}
		return nil
	}
}

func (w *MLPPPWorker) runWorker(client *IPCClient) error {
	defer client.Close()

	w.Logger.Info("Worker waiting for master start signal")
	startMRRU, startShortSeq, err := client.WaitForStart()
	if err != nil {
		return fmt.Errorf("failed to receive start signal: %w", err)
	}
	w.Logger.Info("Worker received start signal",
		zap.Uint16("mrru", startMRRU),
		zap.Bool("shortSeq", startShortSeq))

	srvLCP := newMLPPPLCPState(0xCAFEBABE, uint16(w.MTU), startMRRU, []byte(w.Discriminator))
	srvLCP.wantShortSeq = startShortSeq
	errCh := make(chan error, 3)

	initFrame := srvLCP.InitialRequest()
	if _, err := writeToStdout(EncodeHDLC(initFrame)); err != nil {
		return fmt.Errorf("failed to send initial LCP to server: %w", err)
	}

	go func() {
		buf := make([]byte, 16384)
		var hdlcBuf []byte
		papSent := false
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				hdlcBuf = append(hdlcBuf, buf[:n]...)
				for {
					frame, rest, ok := extractHDLCFrame(hdlcBuf)
					if !ok {
						break
					}
					hdlcBuf = rest
					rawPPP, decErr := decodeHDLCFramePayload(frame)
					if decErr != nil {
						continue
					}
					proto, payload := parsePPPFrame(rawPPP)
					switch {
					case proto == pppProtoLCP:
						responses := srvLCP.HandleLCP(payload)
						for _, resp := range responses {
							if _, werr := writeToStdout(EncodeHDLC(resp)); werr != nil {
								errCh <- werr
								return
							}
						}
						if srvLCP.shortSeqRejected {
							errCh <- errors.New("server rejected short-seq, aborting worker")
							return
						}
						if srvLCP.wantShortSeq && srvLCP.open && !srvLCP.peerRequestedShortSeq {
							errCh <- errors.New("server did not request short-seq, aborting worker")
							return
						}
						if srvLCP.mrru == 0 && startMRRU > 0 {
							errCh <- errors.New("server rejected MRRU, aborting worker")
							return
						}
						if srvLCP.IsOpen() && w.PAPUser != "" && !papSent {
							papReq := buildPAPAuthRequest(1, w.PAPUser, w.PAPPass)
							if _, werr := writeToStdout(EncodeHDLC(papReq)); werr != nil {
								errCh <- werr
								return
							}
							papSent = true
						}
					case proto == pppProtoPAP:
						if len(payload) >= 1 {
							if payload[0] == 2 {
								w.Logger.Info("PAP authentication succeeded (worker)")
								if sendErr := client.Send(IPCMessage{Type: ipcMsgLinkReady}); sendErr != nil {
									errCh <- fmt.Errorf("IPC link-ready send failed: %w", sendErr)
									return
								}
							} else if payload[0] == 3 {
								errCh <- errors.New("PAP authentication rejected by server")
								return
							}
						}
					case proto == pppProtoMP:
						if err := client.Send(IPCMessage{Type: ipcMsgRXFragment, Payload: rawPPP}); err != nil {
							errCh <- fmt.Errorf("IPC send failed: %w", err)
							return
						}
					}
				}
			}
			if err != nil {
				errCh <- fmt.Errorf("stdin closed: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			msg, err := client.Read()
			if err != nil {
				errCh <- fmt.Errorf("IPC read failed: %w", err)
				return
			}
			if msg.Type == ipcMsgTXFragment {
				if _, err := writeToStdout(EncodeHDLC(msg.Payload)); err != nil {
					errCh <- fmt.Errorf("stdout write failed: %w", err)
					return
				}
			}
		}
	}()

	workerErr := <-errCh
	sendLCPTerminate(w.Logger)
	return workerErr
}

func buildPAPAuthRequest(id byte, user, pass string) []byte {
	pktLen := 4 + 1 + len(user) + 1 + len(pass)
	rawPPP := make([]byte, 4+pktLen)
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], pppProtoPAP)
	rawPPP[4] = 1 // Authenticate-Request
	rawPPP[5] = id
	binary.BigEndian.PutUint16(rawPPP[6:8], uint16(pktLen))
	rawPPP[8] = byte(len(user))
	copy(rawPPP[9:9+len(user)], user)
	rawPPP[9+len(user)] = byte(len(pass))
	copy(rawPPP[10+len(user):], pass)
	return rawPPP
}

func parsePAPAuthRequest(payload []byte) (user, pass string) {
	if len(payload) < 6 {
		return "", ""
	}
	userLen := int(payload[4])
	if 5+userLen >= len(payload) {
		return "", ""
	}
	user = string(payload[5 : 5+userLen])
	passLen := int(payload[5+userLen])
	if 6+userLen+passLen > len(payload) {
		return user, ""
	}
	pass = string(payload[6+userLen : 6+userLen+passLen])
	return user, pass
}
