// This codec is mirrored in the two core forks. Keep the wire contract/tests aligned.
// It changes TLS record boundaries, not TCP segment boundaries, and does not encrypt SNI.
package tf

import (
	"encoding/binary"
	"io"
)

// mirageParts only rewrites a complete first ClientHello record. Trailing records
// stay byte-identical; every additional cut is AFTER the complete SNI hostname.
func mirageParts(b []byte, offset, count int) ([][]byte, int, bool) {
	if len(b) < 5 || b[0] != 22 || b[1] != 3 {
		return nil, 0, false
	}
	end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if end > len(b) || end <= 5 || end > 5+16384 {
		return nil, 0, false
	}
	body := b[5:end]
	start, nameEnd, ok := mirageNameRange(body)
	if !ok {
		return nil, 0, false
	}
	if offset <= 0 || offset >= start {
		offset = 5
	}
	if offset >= start {
		return nil, 0, false
	}
	if count < 2 {
		count = 2
	}
	if count > 8 {
		count = 8
	}
	// A tiny hello may not have enough post-name bytes for the requested count.
	// Reduce the count instead of cutting the name or emitting empty records.
	extra := count - 2
	if extra > len(body)-nameEnd {
		extra = len(body) - nameEnd
	}
	cuts := []int{offset}
	if extra > 0 {
		cuts = append(cuts, nameEnd)
		tail := len(body) - nameEnd
		for i := 1; i < extra; i++ {
			cuts = append(cuts, nameEnd+tail*i/extra)
		}
	}
	cuts = append(cuts, len(body))
	parts := make([][]byte, 0, len(cuts)+1)
	prev := 0
	for _, cut := range cuts {
		record := make([]byte, 5+cut-prev)
		copy(record, b[:3])
		binary.BigEndian.PutUint16(record[3:5], uint16(cut-prev))
		copy(record[5:], body[prev:cut])
		parts = append(parts, record)
		prev = cut
	}
	fragments := len(parts)
	if end < len(b) {
		parts = append(parts, b[end:])
	}
	return parts, fragments, true
}

// Validate nested lengths, not merely the enclosing buffer, so fake bytes
// outside the extension/list/ClientHello cannot be interpreted as a name.
func mirageNameRange(h []byte) (int, int, bool) {
	if len(h) < 4 || h[0] != 1 {
		return 0, 0, false
	}
	end := 4 + (int(h[1])<<16 | int(h[2])<<8 | int(h[3]))
	if end > len(h) || end < 39 {
		return 0, 0, false
	}
	h = h[:end]
	p := 38
	takeVector := func(width int) bool {
		if p+width > len(h) {
			return false
		}
		n := int(h[p])
		if width == 2 {
			n = int(binary.BigEndian.Uint16(h[p : p+2]))
		}
		p += width
		if n > len(h)-p {
			return false
		}
		p += n
		return true
	}
	if !takeVector(1) || !takeVector(2) || !takeVector(1) || p+2 > len(h) {
		return 0, 0, false
	}
	extLen := int(binary.BigEndian.Uint16(h[p : p+2]))
	p += 2
	if extLen != len(h)-p {
		return 0, 0, false
	}
	foundStart, foundEnd := 0, 0
	for p < len(h) {
		if len(h)-p < 4 {
			return 0, 0, false
		}
		typ := binary.BigEndian.Uint16(h[p : p+2])
		n := int(binary.BigEndian.Uint16(h[p+2 : p+4]))
		p += 4
		if n > len(h)-p {
			return 0, 0, false
		}
		if typ == 0 {
			if foundStart != 0 || n < 5 {
				return 0, 0, false
			}
			e := h[p : p+n]
			if int(binary.BigEndian.Uint16(e[:2])) != n-2 || e[2] != 0 {
				return 0, 0, false
			}
			size := int(binary.BigEndian.Uint16(e[3:5]))
			if size == 0 || size != n-5 {
				return 0, 0, false
			}
			foundStart, foundEnd = p+5, p+n
		}
		p += n
	}
	return foundStart, foundEnd, foundStart != 0
}

// Return counts in the CALLER'S byte space, excluding inserted record headers.
// A short write poisons the wrapper: retrying the original hello after partial
// transmission would corrupt the stream, not recover the connection.
func writeMirage(w io.Writer, parts [][]byte, fragments int, coalesce bool) (int, error) {
	mapped := func(written int) int {
		out := 0
		for i, part := range parts {
			n := written
			if n > len(part) {
				n = len(part)
			}
			if n < 0 {
				n = 0
			}
			if i > 0 && i < fragments {
				n -= 5
				if n < 0 {
					n = 0
				}
			}
			out += n
			written -= len(part)
			if written <= 0 {
				break
			}
		}
		return out
	}
	written := 0
	if coalesce {
		var all []byte
		for _, part := range parts {
			all = append(all, part...)
		}
		n, err := w.Write(all)
		if n < 0 || n > len(all) {
			return 0, io.ErrShortWrite
		}
		if err == nil && n != len(all) {
			err = io.ErrShortWrite
		}
		return mapped(n), err
	}
	for _, part := range parts {
		n, err := w.Write(part)
		if n < 0 || n > len(part) {
			return mapped(written), io.ErrShortWrite
		}
		written += n
		if err == nil && n != len(part) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return mapped(written), err
		}
	}
	return mapped(written), nil
}
