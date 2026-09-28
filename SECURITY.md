# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

This is a network service: it accepts untrusted connections, parses untrusted
input, and manages file-descriptor and buffer lifetimes. A bug in any of those
is a vulnerability, not a bug report.

Report it privately via GitHub's
[private vulnerability reporting](https://github.com/TheFirstIstari/irc-serve/security/advisories/new),
or by email to the maintainer. Please include:

- what an attacker can do
- steps to reproduce, ideally against the current `main`
- the commit or release you tested

You can expect an acknowledgement within a few days. Fixes land through the
normal PR flow, with a credit unless you prefer otherwise.

## Threat model

Worth stating plainly, because a lot of IRC server security advice assumes
controls this project does not yet have.

**In scope for the current build:**

- Anything a remote client can send before registration completes
- Line framing and the 8192-byte limit
- Buffer and descriptor lifetime across the accept / read / write / reap cycle
- Command parsing for the implemented verb set

**Not yet implemented, and therefore not defended:**

- **No authentication.** `PASS` records a password and does not check it. SASL
  is Phase 8. Anyone who can reach the port can claim any nickname.
- **No TLS.** Traffic is plaintext, so credentials and messages are readable on
  the path.
- **No rate limiting or connection limits.** A client can open connections as
  fast as it likes.
- **No operator privileges are enforced beyond channel `+o`.** There is no
  server operator role.

**Bound on damage while unauthenticated:** a client can send commands and read
what it is sent. It cannot, by design of the current build, reach the filesystem
or execute anything — but that is a property of what has been implemented, not
an access control, and it should not be relied on as one.

Do not expose this build to the public internet. It is a development
milestone: Phases 1-4 of 9 are merged.
