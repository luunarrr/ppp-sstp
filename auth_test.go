package main

import (
	"encoding/binary"
	"testing"
)

func TestRewriteServerLCPForWindows(t *testing.T) {
	t.Run("pap auth preserved for upstream and rewritten for windows", func(t *testing.T) {
		opts := []byte{
			lcpOptMRU, 4, 0x05, 0xdc,
			lcpOptAuthProtocol, 4, 0xC0, 0x23,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := rewriteServerLCPForWindows(opts)
		if got.UpstreamAuthProto != pppProtoPAP {
			t.Fatalf("upstream auth proto = 0x%04x, want PAP", got.UpstreamAuthProto)
		}
		if binary.BigEndian.Uint16(got.OriginalOpts[6:8]) != pppProtoPAP {
			t.Fatalf("original opts auth proto = 0x%04x, want PAP", binary.BigEndian.Uint16(got.OriginalOpts[6:8]))
		}
		if len(got.WindowsOpts) != len(opts) {
			t.Fatalf("windows opts len = %d, want %d", len(got.WindowsOpts), len(opts))
		}
		if binary.BigEndian.Uint16(got.WindowsOpts[len(got.WindowsOpts)-2:]) != pppProtoPAP {
			t.Fatalf("windows opts do not end with PAP auth option: %x", got.WindowsOpts)
		}
	})

	t.Run("noauth injects local pap only", func(t *testing.T) {
		opts := []byte{
			lcpOptMRU, 4, 0x05, 0xdc,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := rewriteServerLCPForWindows(opts)
		if got.UpstreamAuthProto != 0 {
			t.Fatalf("upstream auth proto = 0x%04x, want none", got.UpstreamAuthProto)
		}
		if len(got.WindowsOpts) != len(opts)+len(lcpOptPAP) {
			t.Fatalf("windows opts len = %d, want %d", len(got.WindowsOpts), len(opts)+len(lcpOptPAP))
		}
		if binary.BigEndian.Uint16(got.WindowsOpts[len(got.WindowsOpts)-2:]) != pppProtoPAP {
			t.Fatalf("windows opts do not end with PAP auth option: %x", got.WindowsOpts)
		}
	})

	t.Run("unsupported upstream auth is recorded but not forwarded", func(t *testing.T) {
		opts := []byte{
			lcpOptAuthProtocol, 4, 0xC2, 0x23,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := rewriteServerLCPForWindows(opts)
		if got.UpstreamAuthProto != pppProtoCHAP {
			t.Fatalf("upstream auth proto = 0x%04x, want CHAP", got.UpstreamAuthProto)
		}
		if len(got.WindowsOpts) < len(lcpOptPAP) {
			t.Fatalf("windows opts unexpectedly short: %x", got.WindowsOpts)
		}
		if binary.BigEndian.Uint16(got.WindowsOpts[len(got.WindowsOpts)-2:]) != pppProtoPAP {
			t.Fatalf("windows opts do not end with PAP auth option: %x", got.WindowsOpts)
		}
	})
}

func TestMediateServerLCPForBridge(t *testing.T) {
	t.Run("pap request is forwarded to windows with local pap and preserved upstream", func(t *testing.T) {
		opts := []byte{
			lcpOptMRU, 4, 0x05, 0x79,
			lcpOptAuthProtocol, 4, 0xC0, 0x23,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := mediateServerLCPForBridge(opts, 1401)
		if len(got.NakOpts) != 0 {
			t.Fatalf("unexpected NakOpts: %x", got.NakOpts)
		}
		if got.UpstreamAuthProto != pppProtoPAP {
			t.Fatalf("upstream auth proto = 0x%04x, want PAP", got.UpstreamAuthProto)
		}
		if string(got.OriginalOpts) != string(opts) {
			t.Fatalf("original opts changed: got %x want %x", got.OriginalOpts, opts)
		}
		if binary.BigEndian.Uint16(got.WindowsOpts[len(got.WindowsOpts)-2:]) != pppProtoPAP {
			t.Fatalf("windows opts do not end with PAP auth option: %x", got.WindowsOpts)
		}
	})

	t.Run("noauth request is forwarded with injected local pap", func(t *testing.T) {
		opts := []byte{
			lcpOptMRU, 4, 0x05, 0x79,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := mediateServerLCPForBridge(opts, 1401)
		if len(got.NakOpts) != 0 {
			t.Fatalf("unexpected NakOpts: %x", got.NakOpts)
		}
		if got.UpstreamAuthProto != 0 {
			t.Fatalf("upstream auth proto = 0x%04x, want none", got.UpstreamAuthProto)
		}
		if binary.BigEndian.Uint16(got.WindowsOpts[len(got.WindowsOpts)-2:]) != pppProtoPAP {
			t.Fatalf("windows opts do not end with PAP auth option: %x", got.WindowsOpts)
		}
	})

	t.Run("unsupported auth is nacked to pap before windows sees it", func(t *testing.T) {
		opts := []byte{
			lcpOptMRU, 4, 0x05, 0xdc,
			lcpOptAuthProtocol, 5, 0xC2, 0x23, 0x05,
			lcpOptMagicNumber, 6, 0, 0, 0, 1,
		}
		got := mediateServerLCPForBridge(opts, 1401)
		if len(got.WindowsOpts) != 0 {
			t.Fatalf("unsupported auth should not be forwarded to windows: %x", got.WindowsOpts)
		}
		if len(got.NakOpts) == 0 {
			t.Fatal("expected auth Config-Nak")
		}
		if binary.BigEndian.Uint16(got.NakOpts[len(got.NakOpts)-2:]) != pppProtoPAP {
			t.Fatalf("nak opts do not end with PAP auth suggestion: %x", got.NakOpts)
		}
	})
}

func TestBridgeAuthState(t *testing.T) {
	t.Run("pap upstream requires upstream pap completion", func(t *testing.T) {
		var s bridgeAuthState
		s.setUpstreamProto(pppProtoPAP)
		sendPAP, err := s.onWindowsPAPSuccess()
		if err != nil {
			t.Fatalf("onWindowsPAPSuccess error = %v", err)
		}
		if !sendPAP {
			t.Fatal("expected upstream PAP request")
		}
		if s.ready() {
			t.Fatal("auth state should not be ready before upstream PAP completes")
		}
		s.markUpstreamPAPDone()
		if !s.ready() {
			t.Fatal("auth state should be ready after upstream PAP completes")
		}
	})

	t.Run("noauth upstream is ready after windows auth", func(t *testing.T) {
		var s bridgeAuthState
		s.setUpstreamProto(0)
		sendPAP, err := s.onWindowsPAPSuccess()
		if err != nil {
			t.Fatalf("onWindowsPAPSuccess error = %v", err)
		}
		if sendPAP {
			t.Fatal("did not expect upstream PAP request")
		}
		if !s.ready() {
			t.Fatal("auth state should be ready for noauth upstream")
		}
	})

	t.Run("unsupported upstream auth fails on windows auth success", func(t *testing.T) {
		var s bridgeAuthState
		s.setUpstreamProto(pppProtoCHAP)
		sendPAP, err := s.onWindowsPAPSuccess()
		if err == nil {
			t.Fatal("expected unsupported auth error")
		}
		if sendPAP {
			t.Fatal("did not expect upstream PAP request for unsupported auth")
		}
		if s.ready() {
			t.Fatal("unsupported auth must not become ready")
		}
	})

	t.Run("single link regression chap then pap renegotiation reaches ready", func(t *testing.T) {
		var s bridgeAuthState
		first := mediateServerLCPForBridge([]byte{
			lcpOptMRU, 4, 0x05, 0x79,
			lcpOptAuthProtocol, 5, 0xC2, 0x23, 0x05,
		}, 1401)
		if len(first.NakOpts) == 0 {
			t.Fatal("expected CHAP proposal to be nacked to PAP")
		}

		second := mediateServerLCPForBridge([]byte{
			lcpOptMRU, 4, 0x05, 0x79,
			lcpOptAuthProtocol, 4, 0xC0, 0x23,
		}, 1401)
		if len(second.NakOpts) != 0 {
			t.Fatalf("unexpected renegotiated NakOpts: %x", second.NakOpts)
		}
		s.setUpstreamProto(second.UpstreamAuthProto)
		sendPAP, err := s.onWindowsPAPSuccess()
		if err != nil {
			t.Fatalf("onWindowsPAPSuccess error = %v", err)
		}
		if !sendPAP {
			t.Fatal("expected upstream PAP request after PAP renegotiation")
		}
		s.markUpstreamPAPDone()
		if !s.ready() {
			t.Fatal("auth state should be ready after renegotiated PAP completes")
		}
	})
}
