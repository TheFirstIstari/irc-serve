# Proposal: Multithreading (loop + writer threads)

## Why

One `poll()` loop does everything: framing, dispatch, fanout, `send()`, TLS
records, burst install. Any slow `send()` stalls every client and peer on the
node, and the 1024-fd ceiling caps vertical growth while horizontal growth
needs whole new nodes. Threading the write path raises both ceilings without
rewriting the server.

## What Changes

- **Loop thread keeps sole ownership** of poll, accept, framing, dispatch,
  registries, fanout, reap, tick. No lock added to any of these paths.
- **NEW: writer threads** (`--writers N`, default 0 = today's behavior) drain
  `conn_t` write queues via `conn_pump`/`transport_send` only. Per-connection
  mutex between `conn_queue` (producer) and `conn_pump` (consumer), plus a
  `close()` handoff so the reaper never frees a buffer a writer holds.
- **BREAKING (constraint reversal):** `openspec/config.yaml` "no threads" is
  replaced by "loop-single-writer; writers only." The single-writer registry
  invariant (SERVER_DESIGN §2, server.h:18-30) is preserved, not removed.
- Single `SSL*` per connection owned by one thread at a time; `SSL_CTX`
  frozen after init (already true, now enforced).
- TSan cell added to CI (mutually exclusive with ASan gate); `find_package
  (Threads)` replaces the bare `pthread` link; `want_read/write` and `state`
  become atomic with release/acquire publish-consume.
- Test mode: `--writers 0` runs writers inline — dispatch tests stay
  deterministic, zero harness rewrite.

Out of scope: worker-pool dispatch, per-connection threads, sharded loops
(assessed and rejected in design.md — lock surface 5-50x larger).

## Capabilities

### New Capabilities

- `threading/write-drain` — writer-thread ownership, per-conn lock, close
  handoff, TLS-per-conn serialization, ordered delivery per connection.

### Modified Capabilities

- `server-core` — event loop gains writer lifecycle; `state`/`want_*` atomic;
  mark-then-reap extends across the close handoff; per-node stop flag joins
  the process latch.
- `tls` — `SSL_CTX` freeze, per-`SSL*` single-thread ownership, pending-drain
  under the conn lock.
- `federation` — link FSM and burst stay loop-thread-affine; forward targets
  queue through the loop, never touch writers.
