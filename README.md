# irc-serve

A federated IRC server in C11. Single-threaded, **no required third-party
dependencies** — TLS is available and off by default.

[![CI](https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![C](https://img.shields.io/badge/C-C11-00599B.svg)](CMakeLists.txt)

## What it is

An IRC server designed so that running more than one is a configuration change
rather than a rewrite. The data model is multi-node from the first commit.

Three decisions carry that:

- **Nicks are scoped per server** (`nick@server`). Uniqueness is each peer's
  business, so there is no cluster-wide lock.
- **Channels are origin-owned.** A node stores only its own members; a join on a
  remote channel costs one message instead of a roster sync.
- **Clients and peers share one dispatch path.** The only difference between a
  line from a client and a line from a peer is a field on the connection.

The rule underneath them:

> A node never applies a channel state change it cannot route to that channel's
> origin. It refuses the action.

Refusing rather than queueing turns a permanent disagreement between two nodes
into a temporary one that clears on the next resync.

## Status

**A working server. 100 tests, 0 skipped, 0 code-scanning alerts, 0 required
third-party dependencies.**

There is no release. `irc-serve --help` prints the version — one definition, in
`src/core/server.h`, which CMake, the packaging and every report of it read; the
tree's newest tag is `safety-net` (`72c0192`), which is a **safety marker** rather
than a release. The newest *phase* tag is `v0.7.0-messaging`, and the newest *release*
is nothing, because there has never been one.

| | |
|---|---|
| Tests | **100 passing, 0 skipped**, 0 failing |
| Warnings | **0**, on gcc-16, upstream Clang 23 and Apple clang 21 (`-Weverything`), Release **and** Debug |
| Fortify cell | `-D_FORTIFY_SOURCE=2` (`IRC_FORTIFY=1 ./local-ci.sh`) — a **no-op on macOS**, see below |
| Sanitizers | ASan + UBSan clean locally; **ASan + LeakSanitizer + UBSan clean on Linux**, on the CI job and in `scripts/gate-linux-cell.sh` |
| Code scanning | **0 open alerts** (CodeQL) |
| Language | strict C11, **no required third-party libraries**; TLS (`-DWITH_TLS=ON`) adds the optional one |
| Size | ~45,400 lines of C (`src/` only) |

Every test that was ever a CTest skip is now a real test and
`tests/known_skips.txt` is **empty**. What that buys is a bound on **behaviour**: a
green suite means every registered test did what it says it does, on three compilers,
two configurations each, with and without TLS. It is **not** a statement about
coverage — 14 of the registered tests are unit-style, they exercise functions rather
than the wire, and no green run can distinguish "the wire path is covered" from "the
wire path is untested and nothing noticed". Reading this table as a coverage claim is
the error this paragraph used to make, and it is worth naming because a status table
is exactly where a reader goes looking for one.

**What this status does and does not mean, precisely.** The wire contract is
frozen and documented, and the tree is clean under three compilers and three
sanitizers. Whether the suite covers *all* of that contract is a question about the
tests rather than about their result, and it has no answer in this table. It does **not** mean hardened for the open
internet — see the limits below and [SECURITY.md](SECURITY.md).

**And it used to claim `v1.0.0`, which was not true.** That claim was deliberate
when it was written — it was a *maturity* milestone, not a release, and it was
bounded at the time by the paragraph above — but it was still a version number a
reader would take as a release, in a project with no 1.x history, no `v1.0.0` tag,
and TLS landing in its final weeks. The bounded sentence was worth keeping; the
number was not, so the number is gone and the sentence stays.

### Verified behaviour

Checked against a **clean `git clone`**, a Release build and a **real client
socket** — not inferred from the source:

- Registration `001`–`005`, MOTD `372`/`375`/`376`, and `421` for an unknown verb
  naming the verb it was given
- `JOIN` `PART` `TOPIC` `NAMES` `LIST` `KICK` `MODE`, `+o`/`+v` rendering as `@`/`+`,
  origin ownership, single-writer refusal `437`
- `WHO` with `352` and `315` end-of; `WHOIS` with `311` `312` `319` `317` `318`,
  plus `301` away, `330` account and `319`'s `@`/`+` channel sigils
- `401` unknown target, `442` not on that channel, `461` missing parameter, `482`
  lacking authority
- `MODE #chan +b` as a **query**: one `367` per mask then `368`, and `478` when
  the list is at `CHAN_MAX_BANS`
- `254` from `LUSERS` once any channel exists, absent while the count is zero
- CTCP (`\x01ACTION\x01`) relayed intact
- **No control byte in a client-supplied field reaches another client's terminal, or
  this node's own log.** An away message, a channel topic, a `KICK` reason, a
  `PART` reason and a ban mask arrive stripped — spaces and UTF-8 byte for byte —
  and every strip says how many bytes it dropped. Log-only values (a command word, a
  `PING` token, a `QUIT` reason, a SASL mechanism, a capability name) are **measured**
  rather than printed: kept when printable, withheld with a length and a bad-byte
  count when not. Asserted by a battery that puts a control byte into every position
  a client can put one. **Relayed `PRIVMSG`/`NOTICE` text is filtered too**, and its
  rule is the one exception worth knowing about: ESC, BEL, DEL and the C1 controls are
  removed, while `0x01` (the CTCP delimiter) and the mIRC colour and emphasis codes are
  **kept** — because stripping the delimiter would turn `ACTION` into prose, and
  stripping the mIRC codes would break colour on every client that uses it. C1 is
  removed as a control and kept as a letter: `0xC2 0x9B` goes, the `0x90` in the
  Cyrillic letter A stays, and the byte that tells them apart is how many UTF-8
  continuation bytes the sequence in progress still expects. Removing the whole
  `0x80`–`0x9F` range instead would strip 8128 code points below U+3000. The strip is
  silent and is reported once as `msg_stripped` in the node's summary line — see
  [SECURITY.md](SECURITY.md)
- Every RFC 2812 numeric, what this node does with each one and why — see
  [docs/RFC2812_CONFORMANCE.md](docs/RFC2812_CONFORMANCE.md)
- **Federation** — peer links, the `FEDERATE` handshake, the S-verb set, `SBURST`
  resync driven on link-up, `(origin, epoch, id)` dedup, hop ceiling 10, and
  backoff with a retry budget on a dropped link
- **IRCv3** — `CAP` negotiation, SASL PLAIN, real tag escaping, `multi-prefix`,
  `message-ids`, `account-tag`, `account-notify`, `extended-join`,
  `extended-isupport`, `userhost-in-names`, `setname`, `echo-message`,
  `standard-replies`, `away-notify`, `batch`, `labeled-response`, `invite-notify`,
  `tls` and `sts` (Strict Transport Security)
- **TLS** — optional, off by default, and the build has **no required third-party
  dependency** without it. With `-DWITH_TLS=ON`: implicit TLS on its own port
  (RFC 7194's 6697), `STARTTLS` on the plaintext port with the IRCv3 refusal rules,
  peer links that can require TLS, an `sts` policy a client acts on, and — on the
  outbound peer-link path — a revocation check against the peer's **stapled** OCSP
  response, which fails closed by default

### Not implemented, and why

These are **deliberate scope decisions recorded in the design**, not oversights.
Each is documented where it is excluded.

| Missing | Why |
|---|---|
| Rate limiting | none. A client may open connections as fast as the node accepts them |
| Operator (IRCop) model | none. `CHOPER` answers `482` for every request by design, so it cannot succeed |
| Services (NickServ, ChanServ) | none. Accounts exist but are **operator-created by editing a file**; `REGISTER` is refused `482` |
| Account **federation** | the account registry is per node. Two nodes with two registries **disagree** about who somebody is, and `+account` deliberately does not cross a link |
| `chathistory` | needs per-client message history, which conflicts with §2.2's disposal rule and the fail-closed posture. A design conflict, not a task |
| `oper-tag`, `account-extban` | blocked on a subsystem that does not exist — an operator model, and a ban-expression parser |
| WebSocket transport | a second transport for the `core/transport.h` interface, which now has two implementations |
| `sasl-3.2` (SCRAM/EXTERNAL) | a crypto surface for *authentication*, which is a different problem from *transport* encryption and is not solved by TLS |
| epoll | the `FD_SETSIZE` ceiling of 1024 is accepted and documented; every accept and dial site rejects above it rather than truncating |
| Certificate revocation **inbound** | moot rather than missing: this program never asks a client for a certificate, so there is no client certificate to revoke. Inbound mTLS is not built |
| Certificate revocation **by CRL** | a CRL is a distribution point, and an unreachable one must be treated as revoked or the check is decorative — which means fetching it, and the event loop may not block. OCSP stapling is the alternative: the peer already has the bytes |
| Refreshing an OCSP staple | a refresh inside the event loop is the thing stapling exists to avoid. A stale staple stays stale until an operator replaces the file and restarts, at which point a waiting peer refuses with `STALE` |
| Revocation for a **self-signed** peer certificate | there is no issuer, so nobody could have issued a status for it. The link is refused with `NO_ISSUER`, which is a true statement about the configuration: a mesh that wants revocation checking needs a CA in `--tls-ca` |

Client-only IRCv3 specs (`react`, `typing`, `channel-context`, `batch/react`) are
**N/A for a server** and recorded as such.

There is also **no official IRCv3 conformance suite** — `ircv3/ircv3-test-suite`
does not exist — so IRCv3 support here is hand-written tests against spec text.
That is a weaker guarantee than a third-party runner and is not described as more.

## Build

Requires CMake 3.20+ and a C11 compiler. **Nothing else**, unless you ask for TLS:
the default build links libc and pthread and nothing else, which is what "no
required third-party dependencies" means.

### TLS (optional)

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=ON
cmake --build build --parallel
```

This is the **only** thing in the build that adds a third-party library, and it is
off by default for three reasons that are each a real cost avoided:

- the default build stays buildable and testable on any machine, including a CI
  runner with no OpenSSL development package;
- "plaintext is byte-identical" stays a claim about the configuration this project
  actually ships, so the regression suite means what it says;
- a deployment that does not want TLS does not link a TLS stack.

The cost, stated plainly: **a node built with the default options cannot encrypt
anything.** No `tls` and no `sts` capability, and `STARTTLS` is answered `691`. The
startup line says `tls=absent`, so that state is visible rather than inferred.

### Revocation, and what failing closed costs

A peer link over TLS is checked against the peer's **stapled** OCSP response. The
policy is one boolean and it **fails closed**: missing, stale, unverifiable and
revoked are all refusals, and `--tls-staple-permissive` is the explicit weakening.
The startup line says which, on the same line as the rest of the policy:

```
[observable] tls_init: state=READY ca=configured insecure=0 verify=PEER_CHAIN_AND_NAME ocsp_staple=configured revocation=staple-strict
[observable] tls_peer_revocation: fd=6 peer=irc.b status=GOOD policy=strict action=ACCEPT this_update=… next_update=… detail="in force"
[observable] tls_peer_cert: fd=6 peer=irc.b not_after=2026-10-06T15:27:45Z not_after_in=86335s ocsp=GOOD
```

`not_after` is the second half of the finding: even a certificate that is never
revoked is good until it expires, and an operator who cannot read that from a log
cannot answer "how long is my exposure".

**The cost, stated rather than discovered later:** both sides of a mesh need
`--tls-ocsp-staple`, so **upgrading one side of a running mesh stops peer links**
until both are configured — the refusal is named (`MISSING_STAPLE`) and the
`ocsp_staple=` field says which side is unconfigured. A staple is never refreshed.
And nothing is fetched: no HTTP, no DNS, no blocking call anywhere in the event
loop, which a test asserts by reading the source rather than by trusting this
paragraph.

```sh
# implicit TLS on 6697, STARTTLS on 6667, an `sts` policy clients will act on
./build/src/irc-serve 6667 --name irc.example   --tls-cert /etc/irc/cert.pem --tls-key /etc/irc/key.pem   --tls-port 6697 --tls-sts-duration 15552000

# require TLS, and verify peer certificates against a CA
./build/src/irc-serve 6667 --name irc.example   --tls-cert cert.pem --tls-key key.pem --tls-ca /etc/irc/ca.pem   --tls-require
```

| Option | What it does |
|---|---|
| `--tls-cert PATH` `--tls-key PATH` | The server certificate and its key, PEM. **Both**, or neither. The key must not be readable by group or other. |
| `--tls-ca PATH` | The CA store used to verify **peer** certificates. A peer link that requires TLS is **refused** without one rather than verified against system roots. |
| `--tls-insecure` | Accept a peer certificate this node cannot verify. An explicit opt-in; the default is a refusal with a named reason. |
| `--tls-port PORT` | A second listener where every byte is TLS from the first. `sts` requires it. |
| `--tls-require` | Refuse plaintext client connections, at accept. |
| `--tls-sts-duration N` | The `sts` persistence policy, in seconds. Default `0` — no policy. |
| `--peer-tls NAME` | Require that the link to peer `NAME` carries TLS. Sticky for the life of the link. |
| `--tls-ocsp-staple PATH` | An OCSP response for this node's own certificate, DER or PEM, **stapled on every handshake it performs**. Read once at startup, never refreshed, never fetched. |
| `--tls-staple-permissive` | Do **not** refuse a peer link whose stapled revocation status is missing, stale or unverifiable: log the reason and continue. A revoked certificate is then accepted, which is why the default is the strict policy and this is the flag that turns it off. |

```sh
git clone https://github.com/TheFirstIstari/irc-serve.git
cd irc-serve
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

`make local-ci` reproduces the CI warning flags exactly.

### The gate: 3 compilers × Release/Debug × `WITH_TLS` ON/OFF

`make local-ci` covers **one** compiler and **one** configuration, because that is
what `ci_test` covers. The gate is the breadth `ci_test` deliberately does not
have.

```sh
make gate                      # all 12 cells + an ASan+UBSan cell
make gate GATE_ARGS=-j2        # serial ctest, for bisecting a failure
make gate GATE_ARGS=--no-asan  # 12 build cells only
make gate GATE_ARGS=--linux    # ALSO the Linux cell, via docker
./scripts/gate.sh --help
```

A cell is **3 compilers × Release/Debug × `WITH_TLS` ON/OFF = 12**, plus one
ASan+UBSan cell at `WITH_TLS=ON`. Each cell asserts all four of: **0 compiler
errors, 0 compiler warnings, 0 failed tests, 0 skipped tests**. Skips are a
separate invariant because `ctest`'s exit code cannot express "a test skipped".

Three things about it are load-bearing:

- **Every cell is configured into a fresh directory.** A reused build directory
  reports "Built target" for a file it did not recompile, so a cell that should
  have caught a compile error reports success instead.
- **`WITH_TLS` is a dimension, not a flag.** The matrix was six builds of
  `WITH_TLS=OFF` only, and a line in a TLS-only fixture compiled clean under both
  clangs and then failed under gcc-16 the moment an ON cell existed. A compiler is
  evidence about a file only if it compiled that file.
- **It refuses to run on fewer than three compilers.** A gate that silently runs
  six cells and prints a pass is worse than no gate.

#### The Linux cell, and why it exists

`--linux` adds one more cell: the suite built and run in a **glibc container** under
**ASan + LeakSanitizer + UBSan**, at both `WITH_TLS=OFF` and `ON`. It is opt-in
because it is two full sanitized builds, and it is a cell rather than a source check
because it is the same kind of evidence as the other thirteen.

It exists because **six defects in this project have been invisible to every macOS cell
and visible only on Linux**: glibc's `__wur`, a `<sys/wait.h>` one libc's headers
include and the other's do not, `memmem()` behind a feature-test macro,
`debian/rules` configuring nothing at all because debhelper autodetected the top-level
`Makefile`, a `tf_free()` that left a node registered so `tf_done()` called `nf_kill()`
on a returned stack frame, and a 64 KiB test leak. The common cause is not any one of
them: **it is that a gate which only ever runs on Darwin reports its own blindness as
green**, and LeakSanitizer does not exist on Darwin at all.

**It degrades to a visible SKIP.** `scripts/gate-linux-cell.sh` has three exit codes —
0 ran and passed, 1 ran and failed, 3 **did not run** — and the gate prints a different
word for each and does **not** count a skipped cell as one that ran. "Skipped" and
"passed" being indistinguishable is the decorative-check failure this project keeps
paying for, and a separate exit code is the cheapest way to stop it.

Run it on its own with `./scripts/gate-linux-cell.sh`, which needs Linux and docker and
refuses on anything else rather than pretending.

Compilers are discovered, not hardcoded — `/usr/bin/gcc`, `/usr/bin/clang` and
`/usr/bin/cc` are all Apple's clang on macOS and collapse to one cell, and
Homebrew's keg-only `llvm@NN` are found via `brew --prefix` because they are not
on `PATH` at all. Override with `GATE_COMPILERS="gcc-16 clang cc"`. Build trees
land in `build-gate/`, which is gitignored.

**It is not a substitute for CI, and it is not a leak check.** LeakSanitizer does
not exist on Darwin — an ASan binary run with `detect_leaks=1` there aborts with
`detect_leaks is not supported on this platform`, taking every test with it — so
the local ASan cell runs with leak detection off. The **only** dynamic leak check
for `SSL*` and `SSL_CTX*` in this project is `ci_sanitizers`' `WITH_TLS=ON` cell on
Linux.

### The fortify cell, and what it does not buy

`IRC_FORTIFY=1 ./local-ci.sh` adds `-D_FORTIFY_SOURCE=2` to a whole
build-and-test run. It is worth being precise about it, because the reason it
exists is a diagnostic it **cannot** catch.

glibc declares `read()`, `write()`, `fread()` and `pipe()` with `__wur` —
`__attribute__((warn_unused_result))` — and GCC honours that attribute only when
the result is genuinely used, so `(void)read(...)` is an error
(`-Werror=unused-result`), not a discard. A test did exactly that, every Linux
CI job went red, and every macOS cell had built it clean: macOS does not declare
`read()` with that attribute at all, and Clang exempts an explicit `(void)` cast
even when it does.

So the fortify cell was measured before it was trusted, at `-O0` and `-O2`, on
gcc-16 and Apple clang: **it changes nothing**, because the macOS SDK declares no
`__*_chk` entry points for fortify to select. This class of defect lives in the
platform's *declaration* of a function, and no `-D` flag on macOS can produce a
glibc declaration. **`ci_macos` is not a slower version of the Linux gate for
this class — it is blind to it**, and `ci_test` (hosted Linux, GCC against glibc)
is the gate.

`scripts/check-wur-discards.sh`, which runs in `ci_test`, greps for `(void)` casts
of the libc functions glibc marks `__wur` and fails on any host. It does **not**
replace that build and does not claim to — it is a tripwire for one pattern, added
because the audit that found the original was a one-time manual pass over 1162
sites and nothing stopped the next one. Note that `fwrite` is deliberately absent
from its list: glibc declares it with `__nonnull` and no `__wur`.

### Platforms

| Platform | Status |
|---|---|
| Linux — gcc, clang | Release + Debug in CI (`ci_test`, required) |
| Linux — cachyos, self-hosted | gcc + clang × Release/Debug, **push to `main` only** |
| Linux — ASan + UBSan + LSan | `WITH_TLS` OFF and ON, `ci_sanitizers` |
| macOS | Release + Debug × `WITH_TLS` OFF/ON in CI (`ci_macos`, required) |

The build is **strict C11** with POSIX opted into through feature-test macros,
rather than relaxing to `gnu11`. Relaxing would silence a Linux build break by
giving up the portability guarantee. Read the comment block in
[`CMakeLists.txt`](CMakeLists.txt) before changing it.

## Run

```sh
./build/src/irc-serve 6667
```

Connect on `127.0.0.1:6667`. Send `NICK` then `USER`, then `JOIN #anything`.

Two federated nodes on one machine:

```sh
# node A only listens -- it will accept an inbound peer
./build/src/irc-serve 6667 --name irc.a --secret shared

# node B declares A as its peer and dials it
./build/src/irc-serve 6668 --name irc.b --secret shared \
  --peer irc.a,127.0.0.1,6667
```

Both print `link_established` once the link is up, and both apply the other's
`SBURST`.

Two things to know:

- **`--secret` is required.** A node without one refuses every inbound
  `FEDERATE`. It will listen and serve clients but will not federate.
- **A peer link that carries TLS needs `--peer-tls NAME` on the node that DIALS
  it**, and it must reach the other node's `--tls-port`. An inbound TLS peer link
  arrives on the implicit-TLS port rather than being sniffed for: a port serving
  plaintext clients has no honest way to guess. Use `--tls-require` to stop
  serving plaintext at all.
- **Declare the peer on one node only.** If both nodes list each other, both dial
  and each rejects the other's inbound claim with `NAME_IN_USE`, leaving no link.

Addresses are resolved once at startup, never inside the event loop. Joining the
same channel from a client on each node puts both nicks in both rosters.

## Layout

```
src/core/         message, connection, server, poll_loop, reply, channel, commands
src/federation/   link, verbs, burst, dedup
src/              node_main, protocol_parse, ircv3_tags, sasl_framework
tests/            unit, contract, benchmark, integration, harness
docs/             SERVER_DESIGN, DEVELOPMENT, SPEC_TRACKING, STATS
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) | Architecture and the phase plan. Start here. |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Branching, what `main` enforces, runner setup, rollback |
| [`docs/SPEC_TRACKING.md`](docs/SPEC_TRACKING.md) | Per-feature status against RFC 1459 / 2812 / IRCv3 |
| [`SECURITY.md`](SECURITY.md) | Threat model, what TLS does and does not cover |
| [`docs/STATS.md`](docs/STATS.md) | Generated test counts |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Branch from `main`, keep the suite green,
and make sure your test can fail.

The conventions that matter here:

- Assert on **observable behaviour** — return values, state transitions, bytes on
  the wire. Never on struct fields.
- A test you cannot make go red by breaking the code is not a test. Check that
  your injected fault **compiled**: a build failure leaves the old binary in
  place, so the fault looks like a pass.
- If a feature is absent, return CTest's skip code naming it, and add a line to
  `tests/known_skips.txt`. Do not write a test asserting behaviour nothing
  implements. CI fails on a skip that is not listed, and on a listed skip that no
  longer skips.
- No `sleep()` in tests. Use the `select()`-driven helpers in `tests/harness`.
- No platform-specific assertions; Linux and macOS disagree about `SO_SNDBUF`.

## License

[AGPL-3.0](LICENSE). See [`NOTICE`](NOTICE) for attribution requirements.

## Credits

- [RFC 1459](https://datatracker.ietf.org/doc/html/rfc1459),
  [RFC 2812](https://datatracker.ietf.org/doc/html/rfc2812) — the protocol
- [IRCv3](https://ircv3.net/) and
  [modern.ircdocs.horse](https://modern.ircdocs.horse/) — current specification
