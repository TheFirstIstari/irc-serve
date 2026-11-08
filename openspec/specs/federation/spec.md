# Federation spec

Source of truth for node-to-node links, bursts, and loop safety.
Derived from docs/SERVER_DESIGN.md §4, docs/AUTO_SCALE_DESIGN.md.

## Purpose

Scale by adding nodes, not threads. Peers share the client dispatch path;
the only difference is a field on the connection.

## Requirements

### Requirement: Link lifecycle

Links SHALL authenticate fail-closed and recover with backoff.

#### Scenario: Weak secret
- **WHEN** `FEDERATE` arrives with a secret under 16 bytes (outside tests)
- **THEN** the link is refused — a warning alone is not enough.

#### Scenario: Plaintext peer auth
- **WHEN** a peer is TLS-required and `FEDERATE` arrives on plaintext
- **THEN** the handshake is refused rather than authenticating in the clear.

#### Scenario: Close/reopen
- **WHEN** `fed_close()` runs with any saved dispatch including NULL
- **THEN** dispatch is restored unconditionally, so reopening never wraps
  the hook in itself.

### Requirement: Burst resync

Bursts SHALL replace state atomically at SBURSTE.

#### Scenario: Two peers at once
- **WHEN** a second peer sends burst records while a transaction is open
- **THEN** every non-owner record and commit is refused with BUSY; the
  owner's transaction is untouched.

#### Scenario: Oversized roster
- **WHEN** a burst record would exceed a cap
- **THEN** the whole channel record is discarded before install (two-pass
  commit) — live state never shrinks from a failed re-add.

#### Scenario: Count mismatch
- **WHEN** the SBURSTE counts disagree with accepted records
- **THEN** the burst is discarded, nothing is installed.

### Requirement: Loop safety

Federation SHALL NOT circulate or amplify messages.

#### Scenario: Hop cap
- **WHEN** a message's `(origin, epoch, id)` is seen again or exceeds 10 hops
- **THEN** it is dropped by the dedup ring.
