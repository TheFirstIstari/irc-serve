# Threading: write-drain (delta)

## ADDED Requirements

### Requirement: Writer ownership

Writer threads SHALL drain write queues and nothing else.

#### Scenario: Send offload
- **WHEN** `--writers N` (N > 0) and a connection's write queue is non-empty
- **THEN** a writer thread performs the `send()`/`SSL_write()` calls, and the
  loop thread never calls `send()` on that connection while a writer owns it.

#### Scenario: Default unchanged
- **WHEN** `--writers 0` (the default)
- **THEN** the loop thread drains inline — byte-identical behavior to today.

### Requirement: Ordered delivery per connection

Pipelined replies SHALL arrive in queue order.

#### Scenario: FIFO per conn
- **WHEN** dispatch queues lines A then B on the same connection
- **THEN** the peer receives A before B, regardless of which writer drains.

### Requirement: Producer-consumer exclusion

Queueing and pumping the same connection SHALL be mutually exclusive.

#### Scenario: Grow vs drain
- **WHEN** dispatch appends to `wbuf` while a writer drains it
- **THEN** no byte is lost, duplicated, or reordered, and the buffer is freed
  exactly once (close handoff: loop marks CLOSING, writer releases, reaper frees).

### Requirement: TLS single ownership

One `SSL*` SHALL be driven by one thread at a time.

#### Scenario: Handshake vs record
- **WHEN** a writer performs `SSL_write` on a connection
- **THEN** no other thread calls `SSL_read`/`SSL_write`/`SSL_shutdown` on that
  `SSL*` concurrently; `SSL_CTX` is never mutated after init.

### Requirement: Failure containment

Writer failures SHALL NOT take down the loop or other connections.

#### Scenario: Send error on one conn
- **WHEN** a writer hits a fatal transport error
- **THEN** only that connection is marked CLOSING; the loop reaps it on the
  normal path and all other connections proceed.
