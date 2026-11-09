# Messaging spec

Source of truth for IRC message framing, parsing, and formatting on the wire.
Derived from docs/SERVER_DESIGN.md §3.2, docs/SPEC_TRACKING.md §1.1, RFC 1459 §2.3.

## Purpose

Every byte on every socket enters through this layer. It turns raw bytes into
`message_t` structs and renders structs back to wire lines.

## Requirements

### Requirement: Line framing

The layer SHALL bound every line it accepts.

#### Scenario: Over-long line
- **WHEN** a line exceeds 8192 bytes including CRLF
- **THEN** the line is refused and the connection is closed as a framing violation.

#### Scenario: Embedded control bytes
- **WHEN** a framed line contains an embedded CR, LF, or NUL
- **THEN** `message_parse_n()` rejects it (the only entry point the wire uses).

### Requirement: Tokenizer

The layer SHALL split `@tags :prefix command params` per RFC 1459 §2.3.1.

#### Scenario: Param absorption
- **WHEN** a line carries more than 15 parameters
- **THEN** the first 14 split normally and the 15th absorbs the remainder.

#### Scenario: Rejection hygiene
- **WHEN** parsing rejects a line
- **THEN** `*out` is left zeroed and `message_free()` is safe to call.

### Requirement: Tags (IRCv3)

Escaping SHALL follow the single table in `src/ircv3_tags.c`.

#### Scenario: Escape round-trip
- **WHEN** a value contains `;`, space, backslash, CR, or LF
- **THEN** it is escaped as `\:`, `\s`, `\\`, `\r`, `\n` (a colon stays raw)
  and unescapes back to the identical bytes.
#### Scenario: Raw forbidden bytes
- **WHEN** a tag value arrives with a raw SP, TAB, CR, or LF
- **THEN** the block is refused (raw bytes are never a legal encoding).

### Requirement: Formatter

The formatter SHALL render from fields only.

#### Scenario: No silent alteration
- **WHEN** any field contains CR/LF or the output would exceed the cap
- **THEN** formatting is refused — never truncated, never echoed from `raw`.
