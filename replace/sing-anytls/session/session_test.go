package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// TestStreamWriteOver64KiB verifies that a single Stream.Write call larger
// than the uint16 frame-length limit (65535 bytes) is correctly split into
// multiple data frames and the receiver reads back the exact same bytes.
// Before the fix, len(data) was cast to uint16, silently truncating the
// header length while the buffer.Write still copied all bytes — corrupting
// the wire and hanging the receiver.
func TestStreamWriteOver64KiB(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)

	clientSess := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return cli, nil
	}, &pad, 0, 0, 0, false)
	defer clientSess.Close()

	const N = 256 * 1024 // 4× max frame payload, forces splitting
	payload := make([]byte, N)
	for i := range payload {
		payload[i] = byte(i)
	}

	var got bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	serverSess := NewServerSession(srv, func(stream *Stream) {
		defer wg.Done()
		buf := make([]byte, N)
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Errorf("server ReadFull: %v", err)
			return
		}
		got.Write(buf)
	}, &pad, logger.NOP())
	go serverSess.Run()
	defer serverSess.Close()

	stream, err := clientSess.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	written, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("Stream.Write: %v", err)
	}
	if written != N {
		t.Fatalf("Stream.Write returned %d, want %d", written, N)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to read split frames")
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("server received %d bytes, want %d (and identical content)", got.Len(), N)
	}
}

// Writes leave in chunks of at most writeChunk, each noting the session's
// progress (writeInChunks), so a split frame sequence is no longer one Write
// on the connection. It is still one writeConn under connLock, which is what
// keeps it contiguous; TestControlFrameDoesNotLandBetweenChunks checks that.
func TestWriteDataFrameWritesSplitFramesContiguously(t *testing.T) {
	conn := &recordingConn{}
	sess := &Session{conn: conn}

	payload := make([]byte, maxFrameDataLen+1)
	written, err := sess.writeDataFrame(7, payload)
	if err != nil {
		t.Fatalf("writeDataFrame: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("writeDataFrame returned %d, want %d", written, len(payload))
	}
	for i, w := range conn.writes {
		if len(w) > writeChunk {
			t.Fatalf("write %d is %d bytes, more than a chunk", i, len(w))
		}
	}

	got := bytes.Join(conn.writes, nil)
	wantLen := len(payload) + 2*headerOverHeadSize
	if len(got) != wantLen {
		t.Fatalf("underlying write length = %d, want %d", len(got), wantLen)
	}
	if got[0] != cmdPSH || got[headerOverHeadSize+maxFrameDataLen] != cmdPSH {
		t.Fatal("split data frames were not serialized contiguously")
	}
}

// pacedRecordingConn records each write after a pause, signalling the first,
// and has no deadline to set.
type pacedRecordingConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	writes  [][]byte
}

func (c *pacedRecordingConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	time.Sleep(5 * time.Millisecond)
	c.mu.Lock()
	c.writes = append(c.writes, bytes.Clone(b))
	c.mu.Unlock()
	return len(b), nil
}

func (c *pacedRecordingConn) SetWriteDeadline(time.Time) error { return nil }

// A control frame sent while a split frame sequence is leaving waits for all
// of it: chunked writes hold connLock from the first chunk to the last.
func TestControlFrameDoesNotLandBetweenChunks(t *testing.T) {
	conn := &pacedRecordingConn{started: make(chan struct{})}
	sess := &Session{conn: conn}

	payload := make([]byte, 3*maxFrameDataLen)
	dataErr := make(chan error, 1)
	go func() {
		_, err := sess.writeDataFrame(7, payload)
		dataErr <- err
	}()
	<-conn.started // the data write holds the line
	if _, err := sess.writeControlFrame(newFrame(cmdFIN, 9)); err != nil {
		t.Fatalf("writeControlFrame: %v", err)
	}
	if err := <-dataErr; err != nil {
		t.Fatalf("writeDataFrame: %v", err)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	last := conn.writes[len(conn.writes)-1]
	if len(last) != headerOverHeadSize || last[0] != cmdFIN {
		t.Fatal("the control frame was not written after the whole data sequence")
	}
	data := bytes.Join(conn.writes[:len(conn.writes)-1], nil)
	if want := len(payload) + 3*headerOverHeadSize; len(data) != want {
		t.Fatalf("%d bytes before the control frame, want the %d of the data frames", len(data), want)
	}
	for off := 0; off < len(data); off += headerOverHeadSize + maxFrameDataLen {
		if data[off] != cmdPSH {
			t.Fatalf("byte %d is %d, want a PSH header: a frame landed inside the sequence", off, data[off])
		}
	}
}

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}
