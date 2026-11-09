# Server core (delta: multithreading)

## ADDED Requirements

### Requirement: Writer lifecycle

The loop SHALL own writer startup, signaling, and join.

#### Scenario: Startup
- **WHEN** the node starts with `--writers N`
- **THEN** N writer threads start before listeners accept, and all join before
  `server_shutdown` frees any connection.

#### Scenario: Wakeup
- **WHEN** dispatch queues bytes on a connection with an empty queue
- **THEN** a writer is woken without waiting for the next POLLIN (no
  send-stall on idle sockets).

### Requirement: Atomic publish-consume

Cross-thread intent SHALL be atomic.

#### Scenario: Intent visibility
- **WHEN** the loop publishes `want_write`/`state` or a writer clears it
- **THEN** the other side observes it with release/acquire ordering — no lost
  wakeup, no POLLOUT storm, no torn `state` read in the poll-set build.

### Requirement: Close handoff

`close(fd)` + `free(conn)` SHALL happen exactly once, on the loop thread.

#### Scenario: Writer holds buffer
- **WHEN** the reaper reaches a CLOSING connection a writer is draining
- **THEN** the reaper waits for (or revokes and then performs) the writer's
  release before `close()` + free; the fd is never reused under a live writer.

### Requirement: Stop signalling

Shutdown SHALL reach every thread.

#### Scenario: Per-node stop
- **WHEN** the process latch or a per-node stop fires
- **THEN** the loop stops polling, writers drain-or-abandon boundedly, and all
  threads join before exit (no `pthread_cancel` mid-`send`).
