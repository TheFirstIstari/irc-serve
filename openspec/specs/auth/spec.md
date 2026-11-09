# Auth spec

Source of truth for accounts, SASL, and credential handling.
Derived from docs/SERVER_DESIGN.md §10, `src/sasl_framework.c`, `src/account_store.c`.

## Purpose

Accounts grant visibility (WHOIS 330, account tags/notify), never operator
power. There is no operator flag to grant.

## Requirements

### Requirement: Password storage

Credential files SHALL resist offline attack if read.

#### Scenario: Hash strength
- **WHEN** a password is stored
- **THEN** it is hashed with a per-record random salt under a slow hash
  (PBKDF2/bcrypt/iterations class) — never plaintext, never one fast hash,
  never one salt per boot.

#### Scenario: Empty password
- **WHEN** a credential record has an empty password field
- **THEN** creation is refused.

### Requirement: Verification

Login SHALL fail closed on anything unexpected.

#### Scenario: Missing entropy
- **WHEN** no RNG is available at startup
- **THEN** the node aborts instead of falling back to `time+pid+stack` salts.

#### Scenario: Constant-time compare
- **WHEN** a password or name is compared
- **THEN** comparison runs in constant time over the folded form.

### Requirement: Credential files

Secrets SHALL NOT leak through files, listings, or logs.

#### Scenario: File shape
- **WHEN** a credential path is not a 0600 regular file (FIFO, symlink, dir)
- **THEN** it is refused with a diagnostic; heap copies are wiped via
  volatile after use.
