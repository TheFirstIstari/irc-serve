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
| `PRIVMSG`/`NOTICE` `<text>` | every other client the message is delivered to | **stripped**, and counted — see "Message text" below |

Stripping removes the bytes rather than escaping them, because nothing in this
node escapes and a reader would have to know which surface to un-escape.

**For the STORED fields above, bytes at or above `0x80` are outside the set
permanently**, so their filter never touches UTF-8 — a filter that reached them
would corrupt non-ASCII text silently. That is true of the fields whose *only*
consumer is a terminal rendering them. It is **not** true of relayed message
text, which has a second and very old consumer, and which is the subject of the
next section.

**Message text.** Relayed `PRIVMSG`/`NOTICE` text is the one field on this list
that is not a stored field, and the rule is different in a way worth being
explicit about: **strip what can control a terminal, keep what is IRC message
semantics.**

| Removed | Kept |
|---|---|
| `0x1B` ESC — the byte a CSI, an OSC title-set, a DECSC and a clipboard write are made of | `0x01` — the **CTCP delimiter**; removing either delimiter does not sanitise an `ACTION`, it corrupts it into text starting with the word |
| `0x07` BEL — rings the terminal's bell | `0x02` bold, `0x0F` plain, `0x03` colour, `0x11` mono, `0x16` reverse, `0x1D` italic, `0x1F` underline — the **mIRC codes** |
| `0x7F` DEL — invisible in a log, an ordinary glyph in most fonts | |
| C1 `0x80`–`0x9F` — the 8-bit equivalent of the same escapes, which on an 8-bit terminal *is* CSI | |

The keep list is **a switch naming eight bytes, not a range test**, and that is
deliberate: `u >= 0x02 && u <= 0x1F` looks like the keep list and is not — it
swallows BEL and ESC, and returns 0 for the delimiter. Anyone extending this has
to edit the switch, where the list is visible as a list.

**C1 is the subtle half, because the same bytes are both a control and a
letter.** In UTF-8 a C1 control is `0xC2` + `0x80`–`0x9F`, and those trailing
bytes are also the continuation bytes of ordinary text — `0xD0 0x90` is the
Cyrillic letter A, `0xCE 0x91` the Greek capital alpha. So the filter carries
one piece of state, *how many continuation bytes the sequence in progress still
expects*, and asks it before it looks at the byte on its own:

```
0xC2 0x9B   CSI                       both bytes removed
0xD0 0x90   Cyrillic A                both bytes kept
0xC3 0xA9   e-acute                   both bytes kept
0x9B        CSI on an 8-bit terminal  removed
```

The filter over the literal range `0x80`–`0x9F` is the obvious implementation
and it is wrong: it removes every accented, Greek and Cyrillic character on the
node. Measured, **8128 code points below U+3000 have a continuation byte in that
range.** That is not a filter, it is a character-set downgrade, and it fails
silently on exactly the messages people would notice losing.

The strip runs on the **assembled parameter**, never on a read. `0x01` ending
one `recv()` and the word after it starting the next are already one string by
the time anything runs, so there is no state to carry across a read boundary and
no sequence for a boundary to split in half. `test_msg_text.c` sends a CTCP split
across two writes — with an observable barrier between them, so the split is
guaranteed rather than probable — and requires it to arrive whole.

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

**1. A relay strip removes bytes, and the two groups it removes are not symmetric.**

`PRIVMSG`/`NOTICE` text is relayed to other clients with ESC, BEL, DEL and the
C1 controls removed — see "Message text" above for the table and for why the
keep list is a list. Two things about it are worth stating plainly rather than
leaving to be discovered.

*The strip is silent, and that is the trade.* A sender and a recipient can
disagree about what was sent, and neither can find the moment in the log — you
cannot grep for an escape that was removed. The node reports it once, as
`msg_stripped` in the summary line it already prints, rather than a log line per
message. So the count tells you **whether** traffic was rewritten and roughly
**how often**; it cannot tell you **what** or **by whom**. If you need the
second, that is an argument for a different design — a per-message refusal, or
an IRCv3 client capability that reports the difference — and not for turning this
one back into a log line per message.

*The strip is not an allow-list, and it is not a terminal emulator.* Bytes that
are not on the deny list reach the recipient as sent. In particular a
recipient's own client is the thing that decides what to do with a control byte
that arrives intact, and this node has no opinion about that. What is claimed is
narrow and specific: **this node does not deliver the bytes it names.** A client
that renders some other byte dangerously is a bug in that client.

****2. Peer-supplied strings on a federation link.** The `fed_*` log lines, and
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
- **Revocation is checked, from the peer's stapled OCSP response, and only on the
  outbound peer-link path.** A peer link is refused unless the peer staples a status
  this node can verify against `--tls-ca`, that is still inside its `nextUpdate`, and
  that says GOOD; `--tls-staple-permissive` turns that refusal into a warning and must
  be typed. What it does **not** cover, and this is the list that matters:
  - **There is no CRL.** A CRL is a distribution point, and an unreachable one has to
    be treated as revoked or the check is decorative — which means fetching, which the
    event loop may not do. A staple is bytes the peer already had, so nothing is
    fetched and nothing can be unreachable.
  - **Nothing refreshes a staple.** It is read once at startup from
    `--tls-ocsp-staple` and stapled from there. A stale staple stays stale until an
    operator replaces the file and restarts, at which point peers whose links were
    waiting on a fresh one refuse with `STALE`. That is a deliberate trade against a
    refresh in the event loop, not an oversight.
  - **A self-signed peer certificate cannot be checked at all.** There is no issuer,
    so nobody could have issued a status for it, and the link is refused with
    `NO_ISSUER`. A mesh that wants revocation checking needs a CA in `--tls-ca`.
  - **Inbound is not covered, and is not claimable.** There is no inbound
    client-certificate authentication in this program at all — the server never asks a
    client for a certificate — so revocation is moot inbound rather than implemented
    inbound. Inbound mTLS is not built.
  - **`notAfter` is still the outer bound.** A certificate that is never revoked is
    good until it expires, and every established peer link now logs its `not_after`
    and the seconds remaining, so that window is answerable from a log.
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
