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

**v1.0.0 — the nine-phase plan plus an IRCv3 phase is complete. 85 tests, 0
skipped, 0 code-scanning alerts, 0 required third-party dependencies.**

| | |
|---|---|
| Tests | **85 passing, 0 skipped**, 0 failing |
| Warnings | **0**, on gcc-16, upstream Clang 23 and Apple clang 21 (`-Weverything`), Release **and** Debug |
| Sanitizers | ASan + UBSan clean locally; **LeakSanitizer clean** on the Linux CI job |
| Code scanning | **0 open alerts** (CodeQL) |
| Language | strict C11, **no required third-party libraries**; TLS (`-DWITH_TLS=ON`) adds the optional one |
| Size | ~36,700 lines of C |

All ten phases shipped. Every test that was ever a CTest skip is now a real test
and `tests/known_skips.txt` is **empty** — so a green suite means the whole
implemented surface is covered, which was true at no earlier version.

**What 1.0 means here, precisely.** The wire contract is frozen and documented,
the suite covers all of it, and the tree is clean under three compilers and three
sanitizers. It does **not** mean hardened for the open internet — see the limits
below and [SECURITY.md](SECURITY.md).

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
  peer links that can require TLS, and an `sts` policy a client acts on

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
  actually ships, so the 85-test regression suite means what it says;
- a deployment that does not want TLS does not link a TLS stack.

The cost, stated plainly: **a node built with the default options cannot encrypt
anything.** No `tls` and no `sts` capability, and `STARTTLS` is answered `691`. The
startup line says `tls=absent`, so that state is visible rather than inferred.

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

```sh
git clone https://github.com/TheFirstIstari/irc-serve.git
cd irc-serve
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

`make local-ci` reproduces the CI warning flags exactly.

### Platforms

| Platform | Status |
|---|---|
| Linux — gcc, clang | Release + Debug in CI |
| macOS | Release + Debug in CI |
| Arch Linux, CachyOS | self-hosted runner, push to `main` only |

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
