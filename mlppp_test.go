package main

import (
	"encoding/binary"
	"testing"
)

func TestBuildMRUNak(t *testing.T) {
	makeMRUOpt := func(val uint16) []byte {
		buf := [4]byte{lcpOptMRU, 4}
		binary.BigEndian.PutUint16(buf[2:4], val)
		return buf[:]
	}

	tests := []struct {
		name    string
		opts    []byte
		maxMRU  uint16
		wantNak bool
		wantMRU uint16
	}{
		{
			name:    "MRU present above max",
			opts:    makeMRUOpt(1500),
			maxMRU:  1434,
			wantNak: true,
			wantMRU: 1434,
		},
		{
			name:    "MRU present at max",
			opts:    makeMRUOpt(1434),
			maxMRU:  1434,
			wantNak: false,
		},
		{
			name:    "MRU present below max",
			opts:    makeMRUOpt(1300),
			maxMRU:  1434,
			wantNak: false,
		},
		{
			name:    "MRU absent default exceeds max",
			opts:    nil,
			maxMRU:  1434,
			wantNak: true,
			wantMRU: 1434,
		},
		{
			name:    "MRU absent max at 1500",
			opts:    nil,
			maxMRU:  1500,
			wantNak: false,
		},
		{
			name:    "empty opts max below 1500",
			opts:    []byte{},
			maxMRU:  1400,
			wantNak: true,
			wantMRU: 1400,
		},
		{
			name: "MRU among other options above max",
			opts: func() []byte {
				magic := []byte{lcpOptMagicNumber, 6, 0, 0, 0, 1}
				mru := makeMRUOpt(1500)
				return append(magic, mru...)
			}(),
			maxMRU:  1434,
			wantNak: true,
			wantMRU: 1434,
		},
		{
			name:    "MRU among other options within max",
			opts:    append([]byte{lcpOptMagicNumber, 6, 0, 0, 0, 1}, makeMRUOpt(1434)...),
			maxMRU:  1434,
			wantNak: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMRUNak(tt.opts, tt.maxMRU)
			if tt.wantNak {
				if got == nil {
					t.Fatal("expected NAK, got nil")
				}
				if len(got) != 4 || got[0] != lcpOptMRU || got[1] != 4 {
					t.Fatalf("unexpected NAK format: %x", got)
				}
				gotMRU := binary.BigEndian.Uint16(got[2:4])
				if gotMRU != tt.wantMRU {
					t.Fatalf("NAK MRU = %d, want %d", gotMRU, tt.wantMRU)
				}
			} else {
				if got != nil {
					t.Fatalf("expected nil NAK, got %x", got)
				}
			}
		})
	}
}
