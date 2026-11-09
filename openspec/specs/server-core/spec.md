# Server core spec

Source of truth for the event loop, connections, and registries.
Derived from docs/SERVER_DESIGN.md §3.3–3.4, docs/ARCHITECTURE.md.

## Purpose

One process = one `poll()` loop. All state lives in `server_t`; there are no
threads. Adding a node is a configuration change, not a rewrite.

## Requirements

### Requirement: Event loop

The 8-step tick SHALL be the only path bytes take.

#### Scenario: Tick order
- **WHEN** the loop ticks
- **THEN** it runs build sets → poll → accept → read/frame/parse/dispatch →
  write-drain → dial-progress → reap → tick, in that order.

#### Scenario: Flood and budget
- **WHEN** a client sends malformed lines or exceeds its token bucket
- **THEN** each framed line is charged (including rejects), and the sender is
  answered 417 and closed — one sender never starves the loop.

#### Scenario: EOF with buffered data
- **WHEN** EOF or a read error arrives with complete lines still buffered
- **THEN** all buffered lines are drained across ticks before the connection closes.

### Requirement: Connection lifecycle

Connections SHALL never block the loop and never outlive their reaping.

#### Scenario: Over-cap accept
- **WHEN** file descriptors or peers exceed their caps (1024 fds / 16 peers)
- **THEN** the new connection is refused, never grown past the cap.

### Requirement: Registries

Nicks SHALL be scoped per server (`nick@server`); uniqueness is each peer's
business — no cluster-wide lock.

#### Scenario: Bounded growth
- **WHEN** any registry (channels, members, dedup LRU, nickreg, resume
  windows) reaches its cap
- **THEN** creation is refused with a numeric + observable, leaving no
  zero-member ghosts.

### Requirement: Privilege model

The daemon SHALL shed privilege fail-closed after binding.

#### Scenario: Root startup
- **WHEN** started as root with `--user NAME`
- **THEN** it resets supplementary groups and setgid/setuid to NAME, and
  refuses to start if any step fails.

#### Scenario: Secret files
- **WHEN** `--secret-file` or a key path names a non-regular file or FIFO
- **THEN** startup refuses it with a diagnostic instead of blocking or following it.
