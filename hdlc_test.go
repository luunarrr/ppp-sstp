package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// computeFCSEntry computes a single FCS-16 table entry for the given byte
// value using the ITU-T/PPP polynomial 0x8408 (bit-reversed 0x1021).
func computeFCSEntry(index byte) uint16 {
	var crc uint16
	data := uint16(index)
	for bit := 0; bit < 8; bit++ {
		if (crc^data)&1 == 1 {
			crc = (crc >> 1) ^ 0x8408
		} else {
			crc >>= 1
		}
		data >>= 1
	}
	return crc
}

func TestHDLCFCSTable(t *testing.T) {
	for i := 0; i < 256; i++ {
		expected := computeFCSEntry(byte(i))
		got := hdlcFCSTable[i]
		if got != expected {
			t.Errorf("hdlcFCSTable[%d] (0x%02X) = 0x%04x, want 0x%04x", i, i, got, expected)
		}
	}
}

func TestHDLCKnownVector(t *testing.T) {
	// Payload that exercises the previously-corrupted table indices 125-127
	// (byte values 0x7D, 0x7E, 0x7F).
	payload := []byte{0xFF, 0x03, 0x7D, 0x7E, 0x7F, 0xAA}
	encoded := EncodeHDLC(payload)

	// Compute expected FCS independently using computeFCSEntry-based lookup.
	var table [256]uint16
	for i := 0; i < 256; i++ {
		table[i] = computeFCSEntry(byte(i))
	}
	fcs := uint16(0xFFFF)
	for _, b := range payload {
		fcs = (fcs >> 8) ^ table[(fcs^uint16(b))&0xFF]
	}
	fcs ^= 0xFFFF

	// Build expected HDLC frame manually.
	var expected []byte
	expected = append(expected, 0x7E)
	allBytes := append(payload, byte(fcs&0xFF), byte((fcs>>8)&0xFF))
	for _, b := range allBytes {
		if b < 0x20 || b == 0x7D || b == 0x7E {
			expected = append(expected, 0x7D, b^0x20)
		} else {
			expected = append(expected, b)
		}
	}
	expected = append(expected, 0x7E)

	if !bytes.Equal(encoded, expected) {
		t.Errorf("EncodeHDLC mismatch for payload containing 0x7D/0x7E/0x7F\ngot:  %s\nwant: %s",
			hex.EncodeToString(encoded), hex.EncodeToString(expected))
	}

	// Decode and verify round-trip.
	decoded, err := DecodeHDLC(encoded)
	if err != nil {
		t.Fatalf("DecodeHDLC failed: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("round-trip mismatch\ngot:  %x\nwant: %x", decoded, payload)
	}
}

func TestHDLCEncodeBasic(t *testing.T) {
	pppFrame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	encoded := EncodeHDLC(pppFrame)

	if encoded[0] != 0x7E {
		t.Errorf("must start with flag, got 0x%02x", encoded[0])
	}
	if encoded[len(encoded)-1] != 0x7E {
		t.Errorf("must end with flag, got 0x%02x", encoded[len(encoded)-1])
	}
	// After opening flag: 0xFF (not escaped, > 0x1F), then 0x03 (escaped, < 0x20)
	if encoded[1] != 0xFF {
		t.Errorf("address byte: got 0x%02x, want 0xFF", encoded[1])
	}
	if encoded[2] != 0x7D || encoded[3] != 0x23 {
		t.Errorf("escaped control: got 0x%02x 0x%02x, want 0x7D 0x23", encoded[2], encoded[3])
	}
}

func TestHDLCRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"single byte", 1},
		{"100 bytes", 100},
		{"1400 bytes", 1400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			for i := range data {
				data[i] = byte(i % 256)
			}
			encoded := EncodeHDLC(data)
			decoded, err := DecodeHDLC(encoded)
			if err != nil {
				t.Fatalf("DecodeHDLC error: %v", err)
			}
			if !bytes.Equal(decoded, data) {
				t.Errorf("round-trip mismatch for %d bytes", tt.size)
			}
		})
	}
}

func TestHDLCByteStuffing(t *testing.T) {
	pppFrame := []byte{0xFF, 0x03, 0x7E, 0x7D, 0x01, 0x02, 0x03}
	encoded := EncodeHDLC(pppFrame)

	decoded, err := DecodeHDLC(encoded)
	if err != nil {
		t.Fatalf("DecodeHDLC error: %v", err)
	}
	if !bytes.Equal(decoded, pppFrame) {
		t.Errorf("round-trip mismatch: got %x, want %x", decoded, pppFrame)
	}
	if len(encoded) <= len(pppFrame)+4 {
		t.Errorf("encoded should be longer due to escaping: %d <= %d", len(encoded), len(pppFrame)+4)
	}
}

func TestHDLCDecodeMultipleFrames(t *testing.T) {
	frame1 := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	frame2 := []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x06}

	enc1 := EncodeHDLC(frame1)
	enc2 := EncodeHDLC(frame2)

	// Concatenate: the closing flag of frame1 serves as opening flag of frame2
	combined := make([]byte, 0, len(enc1)+len(enc2)-1)
	combined = append(combined, enc1...)
	combined = append(combined, enc2[1:]...)

	frames, err := DecodeHDLCStream(combined)
	if err != nil {
		t.Fatalf("DecodeHDLCStream error: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if !bytes.Equal(frames[0], frame1) {
		t.Errorf("frame 0 mismatch: got %x, want %x", frames[0], frame1)
	}
	if !bytes.Equal(frames[1], frame2) {
		t.Errorf("frame 1 mismatch: got %x, want %x", frames[1], frame2)
	}
}

func TestHDLCDecodeMalformed(t *testing.T) {
	t.Run("bad FCS", func(t *testing.T) {
		pppFrame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
		encoded := EncodeHDLC(pppFrame)
		encoded[len(encoded)-2] ^= 0xFF
		_, err := DecodeHDLC(encoded)
		if err == nil {
			t.Error("expected error for corrupted FCS")
		}
	})

	t.Run("no closing flag", func(t *testing.T) {
		data := []byte{0x7E, 0xFF, 0x03, 0x00, 0x21}
		_, err := DecodeHDLC(data)
		if err == nil {
			t.Error("expected error for missing closing flag")
		}
	})

	t.Run("empty frame", func(t *testing.T) {
		data := []byte{0x7E, 0x7E}
		_, err := DecodeHDLC(data)
		if err == nil {
			t.Error("expected error for empty frame")
		}
	})
}
