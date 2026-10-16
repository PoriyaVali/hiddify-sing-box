# sing-anytls for Doctor Mobile

This directory is `github.com/anytls/sing-anytls` v0.0.13, vendored and
patched. `go.mod` here and in hiddify-core replaces the module with it. The
untouched copy is its own commit, so `git log -p -- replace/sing-anytls` shows
only the changes below.

The changes port the anytls client fixes made in PoriyaVali/mihomo#2 to the
sing-box core. They target weak and lossy mobile links. mihomo's copy of this
client is v0.0.13 with those fixes, so the code matches line for line where
the two clients match.

## Why v0.0.13, not the v0.0.11 go.mod asks for

v0.0.13 fixes three client bugs of its own:

- A single write over 64 KiB overflowed the frame's uint16 length and
  corrupted the stream.
- A closing stream returned its session to the pool before sending its FIN.
- Close did not unblock a stuck read or write.

Its API is v0.0.11's plus one optional `DisableReuse` field.

## Changes

- **Control frames no longer kill a session on a slow link.** The 5 s write
  deadline used to be set on the whole connection before a FIN waited for the
  write lock. An upload draining behind it inherited the deadline and failed,
  and the session closed. Now:
  - A control frame waits for the lock and sets its own 30 s deadline only once
    it holds it.
  - It closes the session only when the lock holder has handed nothing to the
    connection for 30 s.
  - Writes leave in 16 KiB chunks, each noting progress, so a slow but moving
    write is told apart from a stalled one.
  - (`session.go`: `writeConnWithin`, `lockConnWithin`, `writeInChunks`.)
- **The SYNACK watchdog follows the link.** It was a fixed 3 s. It is now twice
  the client's observed acknowledgement time plus 1 s, kept within [3 s, 12 s].
  A live reused session is no longer closed, with the user's request, because
  one SYNACK took longer than 3 s (`synrtt.go`).
- **The session clock is monotonic,** so a wall-clock correction neither
  stretches nor shrinks its timings (`clock.go`).
- **Pool:**
  - A session that closed is never pooled, or taken from the pool.
  - A request waiting on a handshake takes a session that joins the pool in
    the meantime.
  - A handshake its request no longer waits for - the request gave up, or
    took a pooled session instead - goes on for up to 20 s, and its session
    waits in the pool for the next request. While the request still waits,
    the dial has no new deadline: sing-box gives a dial no deadline past the
    TCP connect, and that is kept (`session/client.go`).
- **TCP_NOTSENT_LOWAT** is set to 16 KiB on the session's socket, reached
  through the TLS conn's `NetConn` and the dialers' `Upstream`. The rest of a
  cancelled upload then waits in the session, which drops it, instead of in
  the kernel ahead of the next request's SYN (`notsent_unix.go`).

## Evidence

- Behavioural copies of three tests, run against unmodified v0.0.11 (what the
  app shipped), fail:
  - An upload behind a FIN was cut with an i/o timeout, the FIN failed, and the
    session closed.
  - A live reused session was closed during a 4 s SYNACK.
  - A 100 KB write never reached the server.
- The tests here pass: `go test ./...` and `go test -race ./...`, plus three
  more race runs of the pool and session tests.
- Upstream's `TestWriteDataFrameWritesSplitFramesContiguously` counted the
  connection writes of a split frame sequence. It now checks the bytes instead,
  since chunked writes make several writes under one lock.
  `TestControlFrameDoesNotLandBetweenChunks` checks that no frame lands inside
  the sequence.
- The weak-link bench of 2026-10-15 measured the mihomo client with these fixes
  at 94.4% success on a bad link (440 ms RTT, loss, 1-3 s outages), against
  87.8% for sing-box with v0.0.11. This port has not been measured on that
  bench yet.
