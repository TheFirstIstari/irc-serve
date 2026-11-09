# TLS (delta: multithreading)

## ADDED Requirements

### Requirement: Context freeze

`SSL_CTX` SHALL be immutable after node init.

#### Scenario: Post-init mutation
- **WHEN** writers are running
- **THEN** no path calls any mutating `SSL_CTX_*` (cert, staple, verify flags);
  per-connection staple bytes are read-only snapshots.

### Requirement: Pending drain under lock

Decrypted-but-unread bytes SHALL NOT stall.

#### Scenario: SSL_pending with writers
- **WHEN** OpenSSL holds pending bytes for a connection
- **THEN** the owning thread drains them while the read buffer has room,
  holding the conn lock — POLLIN is not required to make progress.
