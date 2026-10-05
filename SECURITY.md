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
- **No rate limiting or connection limits.** A client can open connections as
  fast as it likes.
- **No operator privileges are enforced beyond channel `+o`.** There is no
  server operator role.

## Control bytes in client-supplied fields

**What is defended.** A C0 control byte or DEL in a client-supplied field can
rewrite an operator's screen or ring every channel member's bell: `0x07` rings
a terminal, and ESC followed by `[` is a CSI sequence any terminal executes.
One byte test — `conn_byte_is_bad()` in `core/connection.c` — decides what such
a byte is, and each field's **consumer** decides what happens to it:

| Field | Consumer | Policy |
|---|---|---|
| `conn_t::realname` | every member of every channel, and peers | **refused** — `USER` empties it and says so, `SETNAME` answers `417` |
| `conn_t::away` (`AWAY`) | other members' terminals, via the announcement and `301` | **stripped**, and the strip is logged |
| `chan_t::topic` (`TOPIC`) | other members' terminals, on `332`/`333` — now and to every later joiner | **stripped**, and the strip is logged |
| `USER`'s `<servername>` | **nothing** — this node uses the observed peer address | **not printed**: its length, a well-formedness verdict and a bad-byte count are logged instead |

Stripping removes the bytes rather than escaping them, because nothing in this
node escapes and a reader would have to know which surface to un-escape. Bytes
at or above `0x80` are outside the set permanently, so UTF-8 is never touched —
a filter that reached them would corrupt non-ASCII text silently.

**What is not defended, and this is the list that matters.** The four fields
above are the ones this node stores or relays to a client *verbatim*. A
client-supplied string that this node puts only into **its own log** is still
printed raw, and several such paths exist — `QUIT`'s reason, and the command
word of an unrecognised verb. Both are reachable **before registration
completes** and need no credential. Treat this node's log as untrusted input if
you render it on a terminal, and see `docs/SERVER_DESIGN.md` §9.

**The trade you are accepting when a field is stripped rather than refused.** A
sender and a recipient can disagree about what was said, and the only record of
the difference is the log line. That is why every strip is announced.

## TLS

Available, and **off by default**. With `-DWITH_TLS=ON` this node can serve
implicit TLS on its own port (RFC 7194's 6697), upgrade a plaintext connection with
`STARTTLS`, require TLS on a peer link, and advertise an IRCv3 `sts` policy that a
conforming client acts on by refusing to make insecure connections at all.

Without it, nothing on the wire is encrypted — including SASL PLAIN — and the
startup line says `tls=absent`.

**What TLS protects.** Everything a passive or active network attacker can read or
alter on a connection this node is carrying: credentials sent over SASL after the
upgrade, messages, and the peer-link traffic that carries the shared federation
secret.

**What it does not protect, and this list is the point:**

- **A node built without `-DWITH_TLS=ON` encrypts nothing.** There is no runtime
  fallback. If TLS is not compiled in there is no `sts` capability and `STARTTLS` is
  answered `691`.
- **There is no client-certificate authentication.** A client is never asked for a
  certificate and one it offers is not verified against anything. SASL PLAIN over
  TLS is what a client has here.
- **There is no revocation checking.** No CRL and no OCSP. A revoked certificate
  that chains to the configured CA is accepted until it expires. This is the largest
  gap in the boundary.
- **No cipher or protocol pinning beyond the linked OpenSSL's defaults.** There is no
  operator-facing cipher-suite list, so the policy is whatever the library ships.
- **A peer link in the clear still carries the shared federation secret.** A mixed
  mesh — some links TLS, some not — is supported and is the only way to adopt TLS
  one link at a time, but the plaintext links widen the blast radius of that secret
  to everyone on their path. Do not use one secret for both kinds of link.
- **`--tls-insecure` accepts any peer certificate.** It is a flag, and every link it
  affects prints `mode=INSECURE` when it establishes.
- **STARTTLS cannot un-send what came before it.** A connection that has already
  carried a `PASS` value or an `AUTHENTICATE` payload is refused, because upgrading
  it does not retract the credential that already crossed the wire in the clear.

**Bound on damage while unauthenticated:** a client can send commands and read
what it is sent. It cannot, by design of the current build, reach the filesystem
or execute anything — but that is a property of what has been implemented, not
an access control, and it should not be relied on as one.

Do not expose this build to the public internet. It is a development
milestone: Phases 1-4 of 9 are merged.
