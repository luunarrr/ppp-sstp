package main

// extractHDLCFrame finds the first complete HDLC frame in the buffer.
func extractHDLCFrame(buf []byte) (frame, rest []byte, ok bool) {
	start := -1
	for i, b := range buf {
		if b == hdlcFlag {
			if start == -1 {
				start = i
			} else if i > start+1 {
				return buf[start : i+1], buf[i:], true
			} else {
				start = i
			}
		}
	}
	return nil, buf, false
}

// decodeHDLCFramePayload decodes a single HDLC frame (with flags) and returns the PPP payload.
func decodeHDLCFramePayload(frame []byte) ([]byte, error) {
	return DecodeHDLC(frame)
}
