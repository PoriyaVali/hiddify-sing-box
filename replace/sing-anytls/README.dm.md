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
  one SYNACK took longer than 3 s (`synrtt.go`). Each SYNACK is timed against
  its own stream's SYN: a late one for an earlier stream used to be timed
  against the next stream's SYN, a sample far too short.
- **The session clock is monotonic,** so a wall-clock correction neither
  stretches nor shrinks its timings (`clock.go`).
- **The peer's protocol version is read atomically.** The receive loop wrote
  it while OpenStream read it from other goroutines, an upstream data race
  that `go test -race` reports once a test opens a second stream on a session.
- **Pool:**
  - A session that closed is never pooled, or taken from the pool.
  - A request waiting on a handshake takes a session that joins the pool in
    the meantime. The pool is checked under the same lock that hands out its
    notification, so a session pooled just before the wait is not missed.
  - A request already cancelled when it reaches the dial dials nothing.
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
- The weak-link bench (a TUN link emulator, a V2bX 1.8.0 anytls server, and
  the sing-box 1.13.0 client built with and without this directory) measured
  this port on 2026-10-16. The phase that tells them apart is the requests
  made right after 2 MB uploads cancelled at 2 s:
  - Bad link (440 ms RTT, 384 kbit/s up, loss in bursts, a 1-3 s outage
    every 25 s), 7 seeds: 196 of 210 succeeded (93.3%), against 183 (87.1%)
    with v0.0.11. The mihomo client with the same fixes measured 94.4%.
  - Counting a failure as never finishing, the fixed client was no slower at
    any percentile on the 4 seeds with per-request times: median 6.1 s
    against 7.6 s, 90th percentile 17.9 s against a failure (Mann-Whitney
    p = 0.15). The median of the successful requests alone was higher (6.4 s
    against 4.7 s), because the slow requests the old client failed now
    complete.
  - Weak link (300 ms RTT, 1% loss in bursts), 2 seeds: 58 of 60 against 57,
    3 new sessions against 9, 90th percentile 5.9 s against 10.1 s.
  - Browsing (840 requests) and downloads showed no difference beyond the
    spread between runs. Bad-link downloads averaged 0.61 Mbit/s against
    0.67, lower in 5 of 7 seeds; weak-link downloads were faster in both.
