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

A C0 control byte or DEL in a client-supplied field can rewrite an operator's
screen or ring every channel member's bell: `0x07` rings a terminal, and ESC
followed by `[` is a CSI sequence any terminal executes. One byte test —
`conn_byte_is_bad()` in `core/connection.c` — decides what such a byte is, and
each field's **consumer** decides what happens to it.

**Defended, and how.** Both halves of this are asserted rather than claimed:
`test_control_bytes.c` pins the wire lines a member receives, and
`test_log_injection.c` puts a control byte into every position a client can put
one and requires that **none** of them reaches this node's own stdout.

| Field | Consumer | Policy |
|---|---|---|
| `conn_t::realname` | every member of every channel, and peers | **refused** — `USER` empties it and says so, `SETNAME` answers `417` |
| `conn_t::away` (`AWAY`) | other members' terminals, via the announcement and `301` | **stripped**, and logged |
| `chan_t::topic` (`TOPIC`) | other members' terminals, on `332`/`333` — now and to every later joiner | **stripped**, and logged |
| `KICK`'s `<reason>` | every remaining member of the channel | **stripped**, and logged |
| `PART`'s `<reason>` | every remaining member, and the channel's origin | **stripped**, and logged |
| `MODE +b`'s mask | every member, **and** the stored ban list | **stripped**, and logged — the stored and the announced copy are the same bytes |
| `USER`'s `<servername>` | **nothing** — this node uses the observed peer address | **not printed**: its length, a well-formedness verdict and a bad-byte count are logged instead |

Stripping removes the bytes rather than escaping them, because nothing in this
node escapes and a reader would have to know which surface to un-escape. Bytes
at or above `0x80` are outside the set permanently, so UTF-8 is never touched —
a filter that reached them would corrupt non-ASCII text silently.

**Log-only fields are MEASURED, not filtered.** A command word, a `PING`/`PONG`
token, a `QUIT` reason, a server mask, a rejected nickname, a SASL mechanism or
authcid, a capability name, a batch reference, and a `WHO` mask reach **only**
this node's own stdout — nothing downstream of it reads them. They are printed
verbatim when every byte is printable ASCII and withheld (as `-`) when one is
not, with the value's true length and bad-byte count beside them. A strip would
be wrong there rather than merely unsafe: `cmd_unknown: command=NICK` is the
entire diagnostic, and printed with a byte removed it would name a verb the
client never sent.

### Not defended

**1. `PRIVMSG` and `NOTICE` text is relayed verbatim, and that is deliberate.**
It is the largest remaining path for a control byte to reach another client's
terminal, and it is *not* closed here. Filtering it is not a patch: `0x01` is how
CTCP works, so a deny-list would have to become an allow-list, and that changes
what every message on the node may contain — a decision about IRC rather than
about this class. It is also a documented behaviour (CTCP relayed intact).
Treat message text from another user as untrusted.

**2. Peer-supplied strings on a federation link.** The `fed_*` log lines, and
the roster fields a peer's `SBURSTN`/`SBURSTC` install, carry bytes the peer
chose. This is a **different trust boundary**: reaching it needs a completed
`FEDERATE` handshake and the shared secret, so it is not reachable by anyone who
can open a socket to this node's port. `federation/verbs.c` already has a
`HOST_UNPRINTABLE` check, which is the shape of the right answer; extending it to
the peer-side roster is unstarted work.

**3. The node's log is still untrusted input for anything that renders it.** Two
reasons that survive the list above: a `printf("%s", ...)` added tomorrow over a
client value would not be covered by any of these policies, and
`test_log_injection.c` is what catches that — it fails the first time anything
exercises the command that reaches it, but only if the battery is extended to
that command. And the file paths and process names in the startup and
store-loading lines come from argv and the filesystem, not from a client.

**The trade you are accepting when a field is stripped rather than refused.** A
sender and a recipient can disagree about what was said, and the only record of
the difference is the log line — which is why every strip is announced with a
count. An `AWAY` message made **entirely** of refused bytes takes the *clear*
edge (`305`, not marked away): storing it would mark the user away with an empty
message, and an empty trailing parameter is the parameterless `AWAY` that means
"no longer away", so the user would be away while every member was told they were
not.

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
