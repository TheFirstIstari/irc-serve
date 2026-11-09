# TLS spec

Source of truth for encrypted client and peer transport.
`src/tls_openssl.c`, `src/tls_backend.h`. Off by default; OpenSSL is the only
optional dependency.

## Purpose

Encryption for clients (`--tls-port`) and peers (`--peer-tls`), with
fail-closed defaults.

## Requirements

### Requirement: Record flow

Decrypted bytes SHALL never stall for lack of a wakeup.

#### Scenario: Pending bytes
- **WHEN** OpenSSL holds decrypted bytes after a read (`SSL_pending`)
- **THEN** they are drained while the read buffer has room, without waiting
  for the next POLLIN.

### Requirement: Verification policy

TLS SHALL fail closed on anything untrusted.

#### Scenario: Revoked staple
- **WHEN** OCSP stapling reports REVOKED (or verification otherwise fails)
- **THEN** the handshake is refused — never log-and-continue in production.

#### Scenario: Unchecked setup
- **WHEN** any `SSL_set_*` call fails
- **THEN** the handshake is refused with a named reason, not misdiagnosed
  as a peer fault.
