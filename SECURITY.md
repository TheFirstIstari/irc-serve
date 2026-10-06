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

**Defended, and how.** All three of these are asserted rather than claimed.
`test_control_bytes.c` pins the wire lines a member receives, per field.
`test_log_injection.c` puts a control byte into every position a client can put
one and requires that **none** of them reaches this node's own stdout. And
`test_terminal_sweep.c` is the **reachability** property on the **client** path: it
derives the verb list from `commands.c`'s `k_commands[]`, generates every marker
byte in every argument position of every verb, and requires that none of them
reaches this node's stdout **or any client socket**.
`test_peer_terminal_sweep.c` is the same property on the **peer** path, on the
**same instrument** — the marker predicate, the byte masks and the walk are one
implementation in `tests/harness/sweep_scan.h`, because two copies of "what counts
as a marker byte" is a copy that can drift, and drift there is invisible from the
outside: one surface would quietly stop being swept while the sweep still printed
its coverage line. It derives its shapes from the frozen 4.3 S-verb shapes rather
than from `k_commands[]`, and it scans three surfaces: this node's stdout, the
peer link, and a client socket after peer-originated lines.

The third one exists because the first two did not hold. An earlier pass counted
347 `printf` sites and reported zero survivors; a site is only a leak if it is
**reachable with attacker bytes**, and reachability is a property of the call
graph rather than of the format string. Two sites that count rated
benign-looking were live: `MODE`'s `472`, which is behind `chan_has_flag()` and
behind the channel creator being auto-operated on its own `JOIN`, and `BATCH`'s
`NO_SIGN`, which is behind `pre_reg = 1` and so needs no registration at all.
Counting sites measures how many format strings were read.

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

**2. Peer-supplied strings on a federation link.** The `fed_*` log lines, and
the roster fields a peer's `SBURSTN`/`SBURSTC` install, carry bytes the peer
chose. This is a **different trust boundary**: reaching it needs a completed
`FEDERATE` handshake and the shared secret, so it is not reachable by anyone who
can open a socket to this node's port. `federation/verbs.c` already has a
`HOST_UNPRINTABLE` check, which is the shape of the right answer; extending it to
the peer-side roster is unstarted work.

**`src/federation/verbs.c` HAD no terminal-injection coverage at all** — no sweep,
no battery, no case — and it was this file that wrote control bytes into
`ch->modes`, which then propagate through `324`, the `SBURST` shadow and the whole
mesh. The exposure is longer-lived and wider than anything on the client path: a
peer that is trusted once keeps injecting.

**Both halves of that are now closed**, and the section that used to route the work
is gone because the work is done. `test_peer_terminal_sweep.c` sweeps the peer path
on the shared instrument (see **WHAT IS DEFENDED ON EACH PATH** above), and
`fed_obs()` is the single instrument for every `[observable]` line this file prints:
a `%s` argument goes through `conn_text_logsafe()` before it reaches stdout, and
every other conversion is this node's own number and is passed through, because
filtering a count would make the line lie.

The reason `fed_obs()` is a FUNCTION and not a strip at each site is the reason the
two sweeps share an instrument: a policy with fifty-six enforcement points is a
policy with fifty-five chances to be forgotten, and this file has shipped two
divergences from exactly that cause. It is also why the function has **no
`vfprintf()`** — an earlier version read the `%s` conversions with `va_arg()` and
handed the rest to `vfprintf()`, which mixes two consumers of one `va_list` and at
`-O2` left `vfprintf()` consuming nothing, so every `%s` after a `%d` on the same
line read the previous argument. It surfaced as a segfault, which is the luckiest
possible symptom; fourteen tests went red and nine of them were federation tests
whose guards all print that line. Every conversion is now pulled off the list by
hand over a closed set.

### THE ECHO POLICY, STATED ONCE

**A value this node echoes back to the socket that sent it is FILTERED: the bytes
are removed and the FIELD IS KEPT.** `emit_numeric_ex()` in `core/reply.c` is the
one place a numeric's parameters are rendered, and `send_pong()` goes through it
like every other numeric — `PONG` included, because RFC 2812 2.4 requires the token
to be echoed and says nothing about a client putting control bytes inside one. A
parameter that becomes empty is **still a parameter**: `needs_colon()` puts the `:`
marker on an empty final parameter, so a positional parser finds the field exactly
where the RFC says it is. Dropping the field instead would shift every field after
it, which is a protocol divergence rather than a filter.

**The decisive argument is not "there is no second reader".** That argument was
written into `commands.c` to justify the `421` case and it is **wrong as stated**: a
client that logs numerics to a file, or a bouncer relaying them to a human's
terminal, **is** the second reader, and it is downstream of the client rather than
of this node. The argument that does hold is narrower and is the one this policy
rests on: **the echo carries no information the sender does not already have.** The
sender chose every byte in it a moment earlier and had it in hand. That is a
property of the SENDER, not of the reader, which is why it does not depend on
whoever reads the echo afterwards — and it is why this is a filter and not a
refusal: refusing would turn a rendering hazard into a delivery hazard.

Everything else in this section that says "echo", "reported back to the client" or
"reaches the client that sent it" is an instance of this paragraph and is not
argued again.

**3. The node's log is still untrusted input for anything that renders it**, and so
is the wire. Two reasons survive the list above. A `printf("%s", ...)` added
tomorrow over a client value is not covered by any per-field policy, and
`test_terminal_sweep.c` is what catches that: it fails the first time anybody
exercises the command that reaches it, because it generates the
(verb × argument position × marker byte) space rather than listing it. The
second reason is the sweep's own **exception list**, which now has **ONE** entry on
each sweep, each with a per-entry justification, a byte set and the site that
produces it. A green sweep means *no marker byte reaches a scanned surface except
at those sites* — so the list is part of the boundary, not a footnote to it.

It was **thirteen** on the client sweep, and the eleven that were numerics echoing
a client value back, plus the nickname and `PONG`, are all gone now — because all
thirteen were **bugs rather than decisions**, and the honest response to "this
sweep needs an exception here" is to ask why. What is left is the eight mIRC
formatting bytes in **relayed message text**, which is a specification rather than
an exception: `relay_byte_kept()` keeps exactly those eight and drops every other
C0 byte including ESC and BEL.

THE TWO CHECKS THAT KEEP A LIST HONEST are what made it shrink, and they are the
part worth copying: an occurrence is excused only when its byte is in the entry's
set **AND** its line carries the entry's site, so an entry can never become a
blanket amnesty for a byte; and a listed entry whose site never appears anywhere in
the run **fails**, so the list cannot accumulate entries nobody exercises. When the
eleven echo entries stopped matching because the echoes stopped happening, the
check said so and the entries had to be **deleted** rather than left looking
reasonable.

### WHAT IS DEFENDED ON EACH PATH, AND WHAT IS NOT

- **A nickname may hold a bare C1 byte** — **no longer**. `valid_nick()` asks
  `conn_text_display_check()`, which **refuses** a raw `0x80`–`0x9F`, the encoded
  `0xC2 0x80`–`0xC2 0x9F` pair, a **truncated or interrupted** sequence, a lead byte
  outside UTF-8 (`0xC0`, `0xC1`, `0xF5`–`0xFF`), an **overlong** sequence
  (`0xE0 0x80 0xAF` and `0xF0 0x80 0x80 0xAF`) and a **surrogate half**
  (`0xED 0xA0 0x80`). It **accepts** every well-formed 2-, 3- and 4-byte sequence,
  including `ā` (`C4 81`), `café`, `日本` and U+1F600 — and the accepting half is
  asserted as carefully as the refusing half, because the check is written as four
  exclusions from three ranges and a check written as `u <= 0xDF || u >= 0xF5`
  instead would refuse every accented character on the network.

  It is a **refusal** and not a strip because there is no copy to sanitise: a
  nickname **is** every copy. It is the `<client>` field of every numeric its owner
  receives and the source of every line it sends.

  WHY THE C1 RANGE IS NOT A RANGE TEST, which is the mistake this rule is most
  likely to be "simplified" into: `ā` is `C4 81` and its **second byte is inside
  `0x80`–`0x9F`**. A byte-range refusal eats the Cyrillic, the Greek and every
  accented character on the node. What separates them is *how many continuation
  bytes the sequence in progress still expects*, and nothing else.

  WHY OVERLONG AND SURROGATE ARE IN SCOPE rather than pedantry: an overlong
  encoding decodes to the same code point as a shorter one, so a filter that
  **decodes** before it compares and a filter that compares **bytes** disagree about
  one value — and `C0 AF` is the case where they do. Two filters disagreeing about
  one value is the whole of that attack. The four excluded leads are checked
  against their own first-continuation bound, which is the tightest rule UTF-8 has.

  `test_valid_nick.c` asserts both directions in one block;
  `test_nick_utf8.c` asserts what a **second client** receives — the `PRIVMSG`
  prefix byte for byte, including `C4 81`, so a Latin-1 fallback fails as well as a
  dropped nickname — and that all 32 raw and all 32 encoded C1 bytes are refused on
  the wire with the field kept.
- **Numerics echo a client-supplied value** — **no longer**. See **THE ECHO
  POLICY** above; all eleven are filtered at the one place a numeric's parameters
  are rendered. `PONG`'s token is kept and filtered, which is not a contradiction
  of RFC 2812 2.4: the specification requires the token be **echoed** and says
  nothing about a client sending control bytes inside one, and a client demanding a
  byte-exact echo of such a token is a client whose liveness check is a string
  comparison against bytes it chose to put on the wire in the first place.
- **`PRIVMSG`/`NOTICE` text relays the eight mIRC formatting bytes** (`0x01` CTCP,
  `0x02` bold, `0x03` colour, `0x0F` plain, `0x11` mono, `0x16` reverse, `0x1D`
  italic, `0x1F` underline). That is the feature, not an oversight:
  `relay_byte_kept()` keeps exactly those eight and drops every other C0 byte
  including ESC and BEL, because a range test would swallow the hazard and would
  corrupt every CTCP. **Defended, deliberately.**

  **AND NOW IT IS THE SAME CODE ON BOTH SURFACES.** `fed_relay_clean()` in
  `federation/verbs.c` filters the peer-bound copy through those same two
  functions, at `fed_queue_line()` — the only place a peer-bound line is built. The
  peer sweep found the gap: 64 marker bytes were reaching a peer socket on one run,
  because the peer relay path had **no filter at all** rather than a different one.
  The fix routes it; adding a second filter at the second site would have produced
  two implementations of one rule, which is how this tree produced the `SMODES`
  divergence and the `vfprintf` one. Stripping is announced
  (`fed_relay_stripped: kept= removed=`) and **only when something came off**, so
  this node's log rate does not become the mesh's message rate.
- **The peer's mode string reaches `ch->modes`** — **no longer**.
  `chan_mode_implemented()` is the **one** predicate asked by the client's `MODE`,
  by `chan_mode_set()` itself and by the peer's `SMODES` handler. Before it, the
  client path refused a mode letter this node does not evaluate and the peer path
  applied all of them, so a peer could put a control byte into `ch->modes[]` and
  have it reach `324`, the `SBURST` shadow and the whole mesh. Two paths disagreeing
  is not fixed by describing it.
- **The peer path has no terminal-injection coverage** — **no longer**, and the
  routing note that used to sit here is gone because the thing it routed is done.
  The reachability answer was the one `SECURITY.md` already named: the peer path is
  reachable from a single spawned node, because `tests/harness/peer_fixture.c` owns
  one end of a link as a raw socket, lets the node dial it and answers `FEDERATE`
  with a real claim. What was needed beyond that was a second verb table — the
  `INBOUND[]` S-verbs, not `k_commands[]` — and a second shape generator, and both
  are now in the tree.

  **THE THREE THINGS THE PEER SWEEP TAUGHT, and every one of them was found by a red
  run rather than by reading**, which is why they are here rather than in a comment
  on the generator:

  1. **A filter's withholding can disguise a wrong field.** `conn_text_logsafe()`
     renders a value with a byte in the strip set as `-`, so a field that is
     **wrong** and a field that has been **correctly filtered** both print as
     `name=-`. A sweep row written with the channel in the wrong parameter reported
     itself clean for exactly that reason. Rows now assert that the expected field
     is **present-and-withheld** rather than absent entirely.
  2. **A needle that does not name the probe is satisfied by an earlier probe's
     answer.** `tc_expect(client, " 366 ")` searches the accumulated buffer, so
     after the first probe the wait returned on the *previous* channel's answer, the
     probe went out before the node had created this probe's channel, and the node
     reported a lookup failure for a channel that did not exist — which reads
     exactly like a product bug. Every wait names its probe now.
  3. **Nothing at all is the easiest thing for a sweep to get wrong**, because a
     node that never received the line produces no findings. Every probe waits for
     the line the node prints for that shape, and once per marker the sweep waits
     for a PONG proving the node is still serving.

  AND THE INVERTED-ASSERTION HAZARD is checked mechanically where it can be: an
  assertion whose condition asserts a value is **absent** must have a message that
  reads as an absence. It does not attempt the general case, because
  `count == 3` is correct with "expected 3" and inverted with "no replies were
  seen", and telling those apart means reading English — a check that guesses fails
  in the direction that hides a defect.

  THE PEER PATH HAS NO `PING`, and that is **a gap, not a design choice**: the
  federation verb map has no entry for it, so a `PING` down a peer link is counted
  as an unknown verb and never answered. A peer cannot be liveness-probed through
  its own link. The sweeps work around it by probing the client socket, which asks
  the same question because one event loop serves both surfaces. **Not fixed in this
  pass** — it is more than one line, and a link that cannot be pinged is a real
  operational gap worth its own entry.

The file paths and process names in the startup and store-loading lines also come
from argv and the filesystem rather than from a client, and are outside the
sweep for that reason.

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
