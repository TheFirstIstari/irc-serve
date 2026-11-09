# Design: loop + writer threads

## Context

`src/` is strict single-threaded `poll()` with zero locking by design
(`server.h:18-30`). `server_t` owns every registry; #173 moved all module
globals onto it (proven complete — only `g_stop` remains, intentionally).
Five-scout assessment (2026-11-09) mapped every shared structure; key numbers:
2 file-static mutables, 0 non-reentrant calls, per-message mutations limited
to dedup insert (every relayed msg), `strtab`/`chan_t` only on NICK/JOIN/PART.

## Goals / Non-Goals

- Goals: (1) stop `send()`/`SSL_write()` from stalling the loop; (2) use N
  cores for write drain (vertical scaling); (3) keep every other path
  single-writer so the registry/fanout proofs still hold. Horizontal story
  (more nodes) is unchanged and untouched.
- Non-goals: parallel dispatch, parallel fanout, sharded loops, io_uring /
  epoll migration, lock-free registries.

## Decisions

1. **Model: (d) loop thread + dedicated writer threads.** Assessment ranked 4
   models: (d) narrow breakage (only `wbuf`+`SSL*`+close handoff), small lock
   surface (per-conn lock only), best test preservation (dispatch unchanged,
   `--writers 0` = today's code path). (a) worker pool needs global RWLock +
   per-conn + per-channel + dedup + atomics with `conn→chan→server` ordering —
   5 lock kinds, deadlock-prone PART/KICK, moderate test churn. (b) per-conn
   threads deletes the poll contract, violates `MSG_DONTWAIT`, needs full
   harness rewrite. (c) sharded loops still share channels across shards, so
   all of (a)'s locks plus an inter-loop queue.
2. **`pthread`, not C11 `threads.h`.** `threads.h` is optional in C11 and never
   probed here; bare `pthread` is already linked (`src/CMakeLists.txt:196`).
   Use `find_package(Threads)` (portable) instead of the bare link.
3. **Per-connection mutex, not lock-free ring.** `conn_queue` compacts/grows/
   `memcpy`s; `conn_pump` advances `woff`. A mutex serializes exactly the two
   existing functions; a ring rewrites both plus the TLS empty-pass. Cost: one
   `pthread_mutex_t` per active conn; contention is one producer + one
   consumer, never N-way.
4. **Close handoff: mark → writer-release → reap.** Loop marks CLOSING (as
   today); reaper does not `close()`/`free()` while a writer holds the conn
   lock — it either waits bounded or revokes and drains itself. `by_fd[fd]`
   cleared only after the writer releases, so fd reuse can't alias a live writer.
5. **`state`/`want_read`/`want_write` become `_Atomic int`** with
   release-publish / acquire-consume. Everything else stays plain — writers
   never touch it.
6. **TLS: conn lock serializes the `SSL*`; `SSL_CTX` frozen.** `tls_checked`
   latch + `staple` pointer become read-only post-init; pending-drain loop
   runs under the conn lock. No OpenSSL locking callbacks (1.1.1+ internal).
7. **TSan as a separate CI cell** (mutually exclusive with the ASan gate),
   not a flag addition. Plus `server_set_writer_threads(s,0)` test seam so
   all dispatch tests run inline-deterministic.

## Risks / Trade-offs

- [Writer holds conn lock across blocking `send`] → keep `MSG_DONTWAIT` +
  `POLLOUT` back-pressure; writers never block, they retry on RETRY. A wedged
  peer stalls only its own queue (already true via the 256 KiB cap → CLOSING).
- [Reaper waits on writer → tick latency] → bounded wait (one `send` slice),
  then revoke-and-drain-on-loop fallback. Tick budget stays ~50ms.
- [Per-conn mutex memory] → `sizeof(mutex)` × 1024 fds worst case; negligible
  vs 256 KiB queue caps.
- [`g_stop` still process-wide] → per-node stop flag added alongside; signal
  handler sets both (documented exception preserved, extended).
- [`file_secret` static in `node_main.c:1354`] → moved to stack/heap before
  any thread exists; startup is still single-threaded so no race, just hygiene.
- [Throughput still capped by single dispatch] → accepted: workload is
  idle-wait + burst; dispatch CPU is tiny (fanout precomputes to `memcpy`).
  Pool-dispatch is a later change with its own proposal if profiling demands it.

## Migration Plan

1. Land atomics + `find_package(Threads)` + TSan cell with `--writers 0`
   (no behavior change; CI proves it).
2. Land writer pool behind `--writers N`, default 0. Gate: TSan + full suite
   green with N=4.
3. Flip default only after soak + benchmark evidence. Rollback = `--writers 0`.

## Open Questions

- N writer threads vs one-per-N-conns striping: default N=2, tune by benchmark.
- Writer wakeup via `eventfd`/pipe vs condvar: pick by portability probe
  (Linux + macOS both needed); condvar is the fallback.
